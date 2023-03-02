// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <optional>

#include "compat_memory_resource.hpp"
#include "log.hpp"
#include <config.hpp>
#include <ddwaf.h>
#include <event.hpp>
#include <exclusion/input_filter.hpp>
#include <exclusion/rule_filter.hpp>
#include <obfuscator.hpp>
#include <rule.hpp>
#include <ruleset.hpp>
#include <utility>
#include <utils.hpp>

namespace ddwaf {
class context {

public:
    using object_set = std::pmr::unordered_set<const ddwaf_object *>;

    explicit context(std::shared_ptr<ruleset> ruleset)
        : ruleset_(std::move(ruleset)), store_(ruleset_->manifest, ruleset_->free_fn, &pool_)
    {
        rule_filter_cache_->reserve(ruleset_->rule_filters.size());
        input_filter_cache_->reserve(ruleset_->input_filters.size());
        collection_cache_->reserve(ruleset_->collections.size());
    }

    context(const context &) = delete;
    context &operator=(const context &) = delete;
    context(context &&) = delete;
    context &operator=(context &&) = delete;
    ~context() = default;

    DDWAF_RET_CODE run(const ddwaf_object &, optional_ref<ddwaf_result> res, uint64_t);

    // These two functions below return references to internal objects,
    // however using them this way helps with testing
    const std::pmr::unordered_set<rule *> &filter_rules(ddwaf::timer &deadline);
    const std::pmr::unordered_map<rule *, object_set> &filter_inputs(
        const std::pmr::unordered_set<rule *> &rules_to_exclude, ddwaf::timer &deadline);

    std::pmr::vector<event> match(const std::pmr::unordered_set<rule *> &rules_to_exclude,
        const std::pmr::unordered_map<rule *, object_set> &objects_to_exclude, ddwaf::timer &deadline);

protected:
    [[nodiscard]] bool is_first_run() const { return collection_cache_->empty(); }

    std::shared_ptr<ruleset> ruleset_;

    using input_filter = exclusion::input_filter;
    using rule_filter = exclusion::rule_filter;
    using pmr_object_set = std::pmr::unordered_set<const ddwaf_object *>;

    class tracking_mbr : public std::pmr::memory_resource { // NOLINT
        public:
        explicit tracking_mbr(std::pmr::monotonic_buffer_resource *upstream) : upstream_{upstream}
        {}
        ~tracking_mbr() override {
            DDWAF_DEBUG(
                "Destroying memory resource. Total of allocations is %zu bytes", total_allocated_);
        }

        void *do_allocate(std::size_t bytes, std::size_t alignment) override {
            total_allocated_ += bytes;
            return upstream_->allocate(bytes, alignment);
        }

        void do_deallocate(void *p, std::size_t bytes, std::size_t alignment) override {
            return upstream_->deallocate(p, bytes, alignment);
        }

        [[nodiscard]] bool do_is_equal(
            const std::pmr::memory_resource &other) const noexcept override
        {
            return this == &other;
        }

    private:
        size_t total_allocated_{};
        std::pmr::monotonic_buffer_resource *upstream_;
    };

    template <typename T> class WinkoutWrapper {
    public:
        template <typename... Args> explicit WinkoutWrapper(Args &&...args)
        {
            static_assert(
                std::is_constructible_v<T, Args...>, "T is not constructible with given arguments");
            new (&buffer_) T{std::forward<Args>(args)...};
        }

        T& value() {
            return *reinterpret_cast<T *>(&buffer_); // NOLINT
        }

        [[nodiscard]] const T& value() const {
            return *reinterpret_cast<T *>(&buffer_); // NOLINT
        }

        T *operator->() {
            return reinterpret_cast<T *>(&buffer_); // NOLINT
        }

        const T *operator->() const {
            return reinterpret_cast<const T *>(&buffer_); // NOLINT
        }

    private:
        std::aligned_storage_t<sizeof(T), alignof(T)> buffer_;
    };

    std::pmr::monotonic_buffer_resource mono_pool_{std::pmr::new_delete_resource()};
    tracking_mbr pool_{&mono_pool_};

    // must be declared after the memory resources
    WinkoutWrapper<ddwaf::object_store> store_;

    // Cache of filters and conditions
    WinkoutWrapper<std::pmr::unordered_map<rule_filter::ptr, rule_filter::cache_type>>
        rule_filter_cache_{&pool_};
    WinkoutWrapper<std::pmr::unordered_map<input_filter::ptr, input_filter::cache_type>>
        input_filter_cache_{&pool_};

    WinkoutWrapper<std::pmr::unordered_set<rule *>> rules_to_exclude_{&pool_};
    WinkoutWrapper<std::pmr::unordered_map<rule *, pmr_object_set>> objects_to_exclude_{&pool_};

    // Cache of collections to avoid processing once a result has been obtained
    WinkoutWrapper<std::pmr::unordered_map<std::string_view, collection::cache_type>> collection_cache_{&pool_};
    WinkoutWrapper<std::pmr::unordered_set<std::string_view>> seen_actions_{&pool_};
};


} // namespace ddwaf
