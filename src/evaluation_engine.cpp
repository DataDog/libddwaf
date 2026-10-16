// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <atomic>
#include <cstddef>
#include <iterator>
#include <memory>
#include <optional>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "attribute_collector.hpp"
#include "cache_array.hpp"
#include "clock.hpp"
#include "context_allocator.hpp"
#include "evaluation_engine.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "exclusion/input_filter.hpp"
#include "exclusion/rule_filter.hpp"
#include "expression.hpp"
#include "log.hpp"
#include "memory_resource.hpp"
#include "module.hpp"
#include "object.hpp"
#include "object_store.hpp"
#include "processor/base.hpp"
#include "rule.hpp"
#include "ruleset.hpp"
#include "serializer.hpp"
#include "target_address.hpp"
#include "utils.hpp"

namespace ddwaf {

namespace {

// This function adds the waf.context.event "virtual" address, specifically
// meant to be used to tryigger post-processors when there has been an event
// during the lifecycle of the context.
void set_context_event_address(object_store &store)
{
    static const std::string_view event_addr = "waf.context.event";
    static auto event_addr_idx = get_target_index(event_addr);

    if (store.has_target(event_addr_idx)) {
        return;
    }

    store.insert_and_apply(event_addr_idx, event_addr, owned_object::make_boolean(true));
}

void collect_attributes(const object_store &store, const std::vector<rule_result> &results,
    attribute_collector &collector)
{

    // First collect any pending attributes from previous runs
    collector.collect_pending(store);

    for (const auto &result : results) {
        for (const auto &attr : result.attributes.get()) {
            std::visit(
                [&](const auto &value) {
                    using value_type = std::decay_t<decltype(value)>;

                    if constexpr (std::is_same_v<value_type, rule_attribute::input_target>) {
                        collector.collect(store, value.index, value.key_path, attr.key);
                    } else {
                        collector.insert(attr.key, value);
                    }
                },
                attr.value_or_target);
        }
    }
}

// A copy of an evaluation cache made by make_cache_writable, with an arena of
// its own, released along with the copy once neither the engine nor any
// subcontext uses it. Allocating it from the arena of the context instead
// would retain every superseded copy until the context is destroyed, as the
// arena never frees memory, i.e. a full copy per evaluation of a context
// performed while a subcontext is alive.
//
// The engine may later grow the containers of the copy with the memory
// resource of the context, which outlives the copy; the memory they release
// goes to whichever arena is current, where it's ignored.
class cache_copy {
public:
    // A copy of the cache of the recommended ruleset takes about 40 KiB
    static constexpr std::size_t arena_initial_size = 32768;

    explicit cache_copy(const evaluation_cache &source) : arena_(arena_initial_size)
    {
        const memory::memory_resource_guard guard(&arena_);
        cache_.emplace(source);
    }

    ~cache_copy()
    {
        const memory::memory_resource_guard guard(&arena_);
        cache_.reset();
    }

    cache_copy(const cache_copy &) = delete;
    cache_copy(cache_copy &&) = delete;
    cache_copy &operator=(const cache_copy &) = delete;
    cache_copy &operator=(cache_copy &&) = delete;

    evaluation_cache &cache() { return *cache_; }

private:
    memory::monotonic_buffer_resource arena_;
    std::optional<evaluation_cache> cache_;
};

} // namespace

evaluation_cache::evaluation_cache(const ruleset &rs)
    : preprocessors(rs.preprocessors->size()), postprocessors(rs.postprocessors->size()),
      rule_filters(rs.rule_filters->size()), input_filters(rs.input_filters->size())
{
    for (std::size_t i = 0; i < rs.rule_modules.size(); ++i) {
        rs.rule_modules[i].init_cache(rule_modules[i]);
    }
}

evaluation_cache evaluation_cache::derive(const evaluation_cache &upstream)
{
    evaluation_cache cache;
    // Processors and input filters are evaluated, and their caches written,
    // every time, and so are rule filters until they match; whereas only the
    // rules referencing the targets of the subcontext are, see
    // rule_module_cache::pending.
    cache.preprocessors = cache_array<processor_cache>::derive(
        upstream.preprocessors, upstream.preprocessors.size());
    cache.postprocessors = cache_array<processor_cache>::derive(
        upstream.postprocessors, upstream.postprocessors.size());
    cache.rule_filters = cache_array<rule_filter::cache_type>::derive(
        upstream.rule_filters, upstream.rule_filters.size());
    cache.input_filters = cache_array<input_filter::cache_type>::derive(
        upstream.input_filters, upstream.input_filters.size());
    for (std::size_t i = 0; i < cache.rule_modules.size(); ++i) {
        cache.rule_modules[i] = rule_module_cache::derive(upstream.rule_modules[i]);
    }
    cache.exclusions = exclusion_policy::derive(upstream.exclusions);
    return cache;
}

std::pair<bool, owned_object> evaluation_engine::eval(timer &deadline)
{
    make_cache_writable();

    result_serializer serializer(ruleset_->obfuscator.get(), *ruleset_->actions, output_alloc_);

    // Generate result object once relevant checks have been made
    auto [result_object, output] = serializer.initialise_result_object();

    // Once evaluation finishes (on any exit path, including a timeout) flush any
    // input batches left unevaluated and reset the new-target set so that the
    // next eval can identify new targets. The targets registered since the
    // last batch was evaluated (flushed or derived) flag their rules right
    // away, so that subcontexts don't need to inherit them from the store.
    auto on_exit = defer([this]() {
        input_batches_.flush(store_);
        flag_updated_rules();
    });

    std::vector<rule_result> all_results;
    std::size_t batches_evaluated = 0;
    bool event_addr_added = false;

    // Each queued input batch is evaluated as if it were a separate eval call,
    // draining the queue one batch at a time.
    while (input_batches_.next_batch(store_)) {
        std::vector<rule_result> results;
        auto verdict = rule_verdict::none;
        try {
            // Evaluate preprocessors first in their own try-catch, if there's a
            // timeout we still need to evaluate rules unaffected by it.
            eval_preprocessors(deadline);
            // NOLINTNEXTLINE(bugprone-empty-catch)
        } catch (const ddwaf::timeout_exception &) {}

        try {
            // Only the rules referencing a target updated since their last
            // evaluation are evaluated, and only if at least one rule target
            // is new to this batch.
            const bool should_eval_rules = flag_updated_rules();
            const bool should_eval_filters = should_eval_rules || check_new_filter_targets();

            if (should_eval_filters) {
                // Filters need to be evaluated even if rules don't, otherwise it'll
                // break the current condition cache mechanism which requires knowing
                // if an address is new to this run.
                const auto &policy = eval_filters(deadline);

                if (should_eval_rules) {
                    verdict = eval_rules(policy, results, deadline);
                    if (!event_addr_added && !results.empty()) {
                        set_context_event_address(store_);
                        event_addr_added = true;
                    }
                }
            }

            eval_postprocessors(deadline);
            ++batches_evaluated;
            // NOLINTNEXTLINE(bugprone-empty-catch)
        } catch (const ddwaf::timeout_exception &) {}

        collect_attributes(store_, results, collector_);

        if (!results.empty()) {
            all_results.insert(all_results.end(), std::make_move_iterator(results.begin()),
                std::make_move_iterator(results.end()));
        }

        if (deadline.expired() || verdict == rule_verdict::block) {
            break;
        }
    }

    output.evaluated = owned_object::make_unsigned(batches_evaluated);

    // Collect pending attributes, this will check if any new attributes are
    // available (e.g. from a postprocessor) and return a map of all attributes
    // generated during this call.
    // object::assign(result.attributes, collector_.collect_pending(store));
    serializer.serialize(all_results, collector_, deadline, output);
    return {!output.attributes.empty() || !output.actions.empty() || !output.events.empty(),
        std::move(result_object)};
}

void evaluation_engine::eval_preprocessors(timer &deadline)
{
    DDWAF_DEBUG("Evaluating preprocessors");
    make_cache_writable();

    const auto &preprocessors = *ruleset_->preprocessors;
    for (std::size_t i = 0; i < preprocessors.size(); ++i) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating preprocessors");
            throw timeout_exception();
        }

        preprocessors[i]->eval(
            store_, collector_, cache_->preprocessors.get_writable(i), output_alloc_, deadline);
    }
}

void evaluation_engine::eval_postprocessors(timer &deadline)
{
    DDWAF_DEBUG("Evaluating postprocessors");
    make_cache_writable();

    const auto &postprocessors = *ruleset_->postprocessors;
    for (std::size_t i = 0; i < postprocessors.size(); ++i) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating postprocessors");
            throw timeout_exception();
        }

        postprocessors[i]->eval(
            store_, collector_, cache_->postprocessors.get_writable(i), output_alloc_, deadline);
    }
}

exclusion_policy &evaluation_engine::eval_filters(timer &deadline)
{
    make_cache_writable();
    auto &cache = *cache_;

    DDWAF_DEBUG("Evaluating rule filters");

    const auto &rule_filters = *ruleset_->rule_filters;
    for (std::size_t i = 0; i < rule_filters.size(); ++i) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating rule filters");
            throw timeout_exception();
        }

        // A rule filter which has already matched doesn't match again, as
        // checked by rule_filter::match, which can be determined without
        // copying a cache inherited from a context.
        if (expression::get_result(std::as_const(cache.rule_filters).get(i))) {
            continue;
        }

        const auto &filter = rule_filters[i];
        auto exclusion = filter.match(
            store_, cache.rule_filters.get_writable(i), *ruleset_->exclusion_matchers, deadline);
        if (exclusion.has_value()) {
            for (const auto &rule : exclusion->rules) {
                cache.exclusions.add_rule_exclusion(rule, exclusion->mode, exclusion->action);
            }
        }
    }

    DDWAF_DEBUG("Evaluating input filters");

    const auto &input_filters = *ruleset_->input_filters;
    for (std::size_t i = 0; i < input_filters.size(); ++i) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating input filters");
            throw timeout_exception();
        }

        const auto &filter = input_filters[i];
        auto exclusion = filter.match(
            store_, cache.input_filters.get_writable(i), *ruleset_->exclusion_matchers, deadline);
        if (exclusion.has_value()) {
            for (const auto &rule : exclusion->rules) {
                cache.exclusions.add_input_exclusion(rule, exclusion->objects);
            }
        }
    }

    return cache.exclusions;
}

rule_verdict evaluation_engine::eval_rules(
    const exclusion_policy &policy, std::vector<rule_result> &results, timer &deadline)
{
    make_cache_writable();
    // When called from eval, the updated targets have already been flagged
    // before evaluating filters, this is only relevant when the rules are
    // evaluated directly.
    flag_updated_rules();
    // Rules without conditions match every time they're evaluated
    for (const auto &[module, word, mask] : ruleset_->rule_targets->unconditional_rules()) {
        cache_->rule_modules[module].pending[word] |= mask;
    }

    auto verdict = rule_verdict::none;
    for (std::size_t i = 0; i < ruleset_->rule_modules.size(); ++i) {
        const auto &mod = ruleset_->rule_modules[i];
        auto &cache = cache_->rule_modules[i];

        verdict = mod.eval(results, store_, cache, policy, *ruleset_->rule_matchers, deadline);
        if (verdict == rule_module::verdict_type::block) {
            break;
        }
    }
    return verdict;
}

void evaluation_engine::make_cache_writable()
{
    if (cache_.use_count() == 1) {
        // Synchronise with the release of a shared cache by a subcontext,
        // possibly on another thread, before modifying it.
        std::atomic_thread_fence(std::memory_order_acquire);
        return;
    }

    // Subcontexts keep the current cache, while the engine continues with a
    // copy, see cache_copy.
    auto copy = std::allocate_shared<cache_copy>(std::allocator<cache_copy>{}, *cache_);
    auto &cache = copy->cache();
    cache_ = std::shared_ptr<evaluation_cache>(std::move(copy), &cache);
}

bool evaluation_engine::flag_updated_rules()
{
    bool new_rule_targets = false;
    for (auto target : store_.updated_targets()) {
        const auto rules = ruleset_->rule_targets->find(target);
        if (rules.empty()) {
            continue;
        }

        for (const auto &[module, word, mask] : rules) {
            cache_->rule_modules[module].pending[word] |= mask;
        }

        new_rule_targets = new_rule_targets || store_.is_new_target(target);
    }
    store_.clear_updated_targets();
    return new_rule_targets;
}

} // namespace ddwaf
