// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <charconv>
#include <iostream>
#include <memory>

#include "exception.hpp"
#include "exclusion/common.hpp"
#include "expression.hpp"
#include "log.hpp"
#include "transformer/manager.hpp"
#include "utils.hpp"

namespace ddwaf {
/*expression::eval_result expression::evaluator::eval_structured_condition(*/
    /*const condition &cond, const matcher::base &matcher, condition::cache_type &cache)*/
/*{*/
    /*if (deadline.expired()) {*/
        /*throw ddwaf::timeout_exception();*/
    /*}*/

    /*bool ephemeral = false;*/
    /*std::vector<optional_ref<const ddwaf_object>> args;*/
    /*args.reserve(cond.targets.size());*/
    /*for (unsigned i = 0; i < cond.targets.size(); ++i) {*/
        /*const auto &target = cond.targets[i];*/
        /*auto [object, attr] = store.get_target(target.root);*/
        /*if (object == nullptr) {*/
            /*return {false, false};*/
        /*}*/

        /*if (attr == object_store::attribute::ephemeral) {*/
            /*ephemeral = true;*/
        /*}*/

        /*args.emplace_back(*object);*/
    /*}*/

    /*std::optional<event::match> optional_match;*/
    /*auto [res, highlight, index] = matcher.match(args);*/

    /*if (res) {*/
        /*std::string value;*/

        /*if (index < args.size()) {*/
            /*auto matched_object = args[index];*/
            /*if (matched_object.has_value()) {*/
                /*value = object_to_string(matched_object->get());*/
            /*}*/
        /*}*/

        /*if (index < cond.targets.size()) {*/
            /*const auto &target = cond.targets[index];*/
            /*cache.match = event::match{std::move(value), std::move(highlight), matcher.name(),*/
                /*matcher.to_string(), target.name, target.key_path, ephemeral};*/
        /*} else {*/
            /*// This shouldn't ever happen....*/
            /*cache.match = event::match{std::move(value), std::move(highlight), matcher.name(),*/
                /*matcher.to_string(), "", {}, ephemeral};*/
        /*}*/

        /*return {true, ephemeral};*/
    /*}*/

    /*return {false, false};*/
/*}*/

eval_result expression::eval(cache_type &cache, const object_store &store,
    const exclusion::object_set_ref &objects_excluded,
    const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
    ddwaf::timer &deadline) const
{
    if (cache.result || conditions_.empty()) {
        return {true, false};
    }

    if (cache.conditions.size() < conditions_.size()) {
        cache.conditions.assign(conditions_.size(), condition::cache_type{});
    }

    bool ephemeral_match = false;
    for (unsigned i = 0; i < conditions_.size(); ++i) {
        const auto &cond = conditions_[i];
        auto &cond_cache = cache.conditions[i];

        if (cond_cache.match.has_value() && !cond_cache.match->ephemeral) {
            continue;
        }

        auto [res, ephemeral] = cond->eval(cond_cache, store, objects_excluded,
            dynamic_matchers, limits_, deadline);
        if (!res) {
            return {false, false};
        }
        ephemeral_match = ephemeral_match || ephemeral;
    }
    cache.result = !ephemeral_match;

    return {true, ephemeral_match};
}

/*void expression_builder::add_target(std::string name, std::vector<std::string> key_path,*/
    /*std::vector<transformer_id> transformers, expression::data_source source)*/
/*{*/
    /*expression::condition::target_type target;*/
    /*target.root = get_target_index(name);*/
    /*target.key_path = std::move(key_path);*/
    /*target.name = std::move(name);*/
    /*target.transformers = std::move(transformers);*/
    /*target.source = source;*/

    /*auto &cond = conditions_.back();*/
    /*cond.targets.emplace_back(std::move(target));*/
/*}*/

} // namespace ddwaf
