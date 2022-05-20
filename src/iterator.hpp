// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.


#pragma once

#include <functional>
#include <set>
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <IPWRuleProcessor.h>
#include <PWManifest.h>
#include <utils.h>
#include <validator.hpp>

namespace ddwaf
{

class object_iterator
{
public:
    explicit object_iterator(const ddwaf_object *obj,
        const std::vector<std::string> &path = {},
        const object_limits &limits = object_limits());

    operator bool() { return current_ != nullptr; }
    [[nodiscard]] bool is_valid() const { return current_ != nullptr; }
    bool operator++();

    // TODO add const, nodiscard, etc
    const ddwaf_object* operator*() { return current_; }
    DDWAF_OBJ_TYPE type() { 
        return current_ != nullptr ? current_->type : DDWAF_OBJ_INVALID;
    }

    std::vector<std::string> get_current_path();

protected:
    void initialise_cursor(const ddwaf_object *obj);
    void initialise_cursor_with_path(const ddwaf_object *obj,
        const std::vector<std::string> &path);
    void set_cursor_to_next_scalar();

    static constexpr std::size_t initial_stack_size = 32;

    const object_limits limits_;
    std::size_t path_size_{0};
    std::vector<std::pair<const ddwaf_object *, std::size_t>> stack_;
    const ddwaf_object *current_{nullptr};
};

}

using ruleCallback = bool(const ddwaf_object*, DDWAF_OBJ_TYPE, bool, bool);

class ArgsIterator
{
    struct State
    {
        std::vector<std::pair<const ddwaf_object*, size_t>> stack;
        const ddwaf_object* activeItem;
        size_t itemIndex;

        State(const ddwaf_object* args, uint32_t maxDepth);
        bool isOver() const;
        void pushStack(const ddwaf_object* newActive);
        bool popStack();
        void reset(const ddwaf_object* args);
        uint64_t getDepth() const;
    };

    State state;

public:
    ArgsIterator(ddwaf_object* args, uint64_t maxMapDepth);
    void gotoNext(bool skipIncrement = false);
    void reset(const ddwaf_object* args);
    const ddwaf_object* getActiveItem() const;
    void getKeyPath(std::vector<ddwaf_object>& keyPath) const;
    bool isOver() const;

    bool matchIterOnPath(const std::vector<std::string>& path) const;

    friend PWRetriever;
    friend class Iterator;
#ifdef TESTING
    FRIEND_TEST(TestPWRetriever, TestCreateNoTarget);
    FRIEND_TEST(TestPWRetriever, TestIterateInvalidItem);
    FRIEND_TEST(TestPWRetriever, TestIterateEmptyArray);
    FRIEND_TEST(TestPWRetriever, TestInvalidArgConstructor);
#endif
};

class Iterator
{
public:
    std::vector<PWManifest::ARG_ID>::const_iterator targetCursor;
    std::vector<PWManifest::ARG_ID>::const_iterator targetEnd;

    PWRetriever& retriever;
    bool currentTargetRunOnKey;
    bool currentTargetRunOnValue;
    ArgsIterator argsIterator;

    Iterator(PWRetriever& _retriever);
    void reset(const std::vector<PWManifest::ARG_ID>& targets);

    void gotoNext();
    void updateTargetMetadata();
    bool isOver() const;
    PWManifest::ARG_ID getActiveTarget() const;
    const std::string& getDataSource() const;
    const std::string& getManifestKey() const;
    const ddwaf_object* operator*() const;
    bool shouldMatchKey() const;
    bool shouldMatchValue() const;

    bool matchIterOnPath(const std::vector<std::string>& path) const;
    bool moveIteratorForward(bool shouldIncrementFirst = true);

    bool operator++();
    bool runIterOnLambda(const std::function<ruleCallback>& lambda);
};
