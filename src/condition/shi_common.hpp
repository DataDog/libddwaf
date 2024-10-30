// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "condition/base.hpp"
#include "condition/match_iterator.hpp"
#include "condition/shi_detector.hpp"
#include "condition/structured_condition.hpp"
#include "ddwaf.h"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "log.hpp"
#include "tokenizer/shell.hpp"
#include "utils.hpp"

namespace ddwaf {

struct shi_result {
    std::string value;
    std::vector<std::string> key_path;
};

struct shell_argument_array {
    static constexpr std::size_t npos = std::string_view::npos;

    explicit shell_argument_array(const ddwaf_object &root);
    std::size_t find(std::string_view str, std::size_t start = 0);
    [[nodiscard]] bool empty() const { return resource.empty(); }

    std::vector<std::pair<std::size_t, std::size_t>> indices;
    std::string resource;
};

template <typename ResourceType>
std::optional<shi_result> shi_impl(const ResourceType &resource,
    std::vector<shell_token> &resource_tokens, const ddwaf_object &params,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer &deadline);

} // namespace ddwaf
