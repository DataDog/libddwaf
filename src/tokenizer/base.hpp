// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "utils.hpp"
#include <fmt/format.h>
#include <ostream>
#include <re2/re2.h>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace ddwaf {

template <typename T> struct base_token {
    T type{T::unknown};
    std::string_view str;
    std::size_t index{};
};

template <typename T> class base_tokenizer {
public:
    explicit base_tokenizer(std::string_view str, std::unordered_set<T> skip_tokens = {})
        : buffer_(str), skip_tokens_(std::move(skip_tokens))
    {}

protected:
    [[nodiscard]] char peek() const
    {
        if (idx_ >= buffer_.size()) {
            [[unlikely]] return '\0';
        }
        return buffer_[idx_];
    }
    [[nodiscard]] char prev(std::size_t offset = 1) const
    {
        if (idx_ < offset) {
            [[unlikely]] return '\0';
        }
        return buffer_[idx_ - 1];
    }

    bool advance(std::size_t offset = 1) { return (idx_ += offset) < buffer_.size(); }

    [[nodiscard]] char next(std::size_t offset = 1)
    {
        if ((idx_ + offset) >= buffer_.size()) {
            [[unlikely]] return '\0';
        }
        return buffer_[idx_ + offset];
    }

    bool eof() { return idx_ >= buffer_.size(); }

    [[nodiscard]] std::size_t index() const { return idx_; }

    std::string_view substr(std::size_t start, std::size_t size = std::string_view::npos)
    {
        return buffer_.substr(start, size);
    }

    std::string_view substr() { return buffer_.substr(idx_); }

    void add_token(T type, std::size_t size = 1)
    {
        base_token<T> token;
        token.index = index();
        token.type = type;
        token.str = substr(token.index, size);
        emplace_token(token);
        advance(token.str.size() - 1);
    }

    void emplace_token(const base_token<T> &token)
    {
        if (!skip_tokens_.contains(token.type)) {
            tokens_.emplace_back(token);
        }
    }

    std::string_view buffer_;
    std::size_t idx_{0};
    std::unordered_set<T> skip_tokens_{};
    std::vector<base_token<T>> tokens_{};
};

} // namespace ddwaf
