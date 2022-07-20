// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <radixlib.h>

class ip_match : public IPWRuleProcessor
{
public:
    explicit ip_match(const std::vector<std::string> &ip_list);
    ~ip_match() override;

protected:
    bool performMatch(const char* str, size_t length, MatchGatherer& gatherer) const override;
    radix_tree_t* radixTree = nullptr;
};
