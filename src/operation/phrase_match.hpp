// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <ac.h>
#include <memory>
#include <operation/base.hpp>

namespace ddwaf::operation {

class phrase_match : public base {
public:
    phrase_match(std::vector<const char *> pattern, std::vector<uint32_t> lengths);
    [[nodiscard]] std::string_view name() const override { return "phrase_match"; }
    [[nodiscard]] std::optional<event::match> match(std::string_view pattern) const override;

protected:
    std::unique_ptr<ac_t, void (*)(void *)> ac{nullptr, nullptr};
};

} // namespace ddwaf::operation
