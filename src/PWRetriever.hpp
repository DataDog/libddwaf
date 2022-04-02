// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef PWArgsWrapper_h
#define PWArgsWrapper_h

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

struct RuleMatchTarget;

class PWRetriever
{
public:
    class PWArgsWrapper
    {

    public:
        PWArgsWrapper() = default;
        void addParameter(const ddwaf_object input);
        const ddwaf_object* getParameter(const std::string& paramName) const;
        bool isValid() const;

    protected:
        std::unordered_map<std::string, const ddwaf_object*> parameters;
    };

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

        bool matchIterOnPath(const std::set<std::string>& path, bool isAllowList, size_t& blockDepth) const;

        friend PWRetriever;

#ifdef TESTING
        FRIEND_TEST(TestPWRetriever, TestCreateNoTarget);
        FRIEND_TEST(TestPWRetriever, TestIterateInvalidItem);
        FRIEND_TEST(TestPWRetriever, TestIterateEmptyArray);
        FRIEND_TEST(TestPWRetriever, TestInvalidArgConstructor);
#endif
    };

    struct Iterator
    {
        struct State
        {
            std::vector<PWManifest::ARG_ID>::const_iterator targetCursor;
            std::vector<PWManifest::ARG_ID>::const_iterator targetEnd;

            bool isOver() const;
        };

        PWRetriever& retriever;
        State state;
        bool currentTargetRunOnKey;
        bool currentTargetRunOnValue;
        ArgsIterator argsIterator;

        Iterator(PWRetriever& _retriever);
        void reset(const std::vector<PWManifest::ARG_ID>& targets);

        void gotoNext(bool skipIncrement = false);
        void updateTargetMetadata();
        bool isOver() const;
        PWManifest::ARG_ID getActiveTarget() const;
        const std::string& getDataSource() const;
        const std::string& getManifestKey() const;
        const ddwaf_object* operator*() const;
        bool shouldMatchKey() const;
        bool shouldMatchValue() const;

        bool matchIterOnPath(const std::set<std::string>& path, bool isAllowList, size_t& blockDepth) const;
    };

private:
    const PWManifest& manifest;
    PWArgsWrapper wrapper;
    uint32_t max_map_depth;
    Iterator internalIterator;

    std::unordered_set<PWManifest::ARG_ID> newestBatch;
    bool runOnNewOnly = false;

    bool _matchIterOnPath(const Iterator& _iter, const std::vector<ddwaf_object>& path, bool isAllowList, size_t& blockDepth) const;

    using ruleCallback = bool(const ddwaf_object*, DDWAF_OBJ_TYPE, bool, bool);

public:
    PWRetriever(const PWManifest& _manifest,
        const ddwaf::object_limits &limits = ddwaf::object_limits());
    void addParameter(const ddwaf_object input);
    bool hasNewArgs() const;
    bool isKeyInLastBatch(PWManifest::ARG_ID key) const;

    Iterator& getIterator(const std::vector<PWManifest::ARG_ID>& targets);
    const ddwaf_object* getParameter(const PWManifest::ARG_ID paramID);

    bool moveIteratorForward(Iterator& iter, bool shouldIncrementFirst = true);

    bool runIterOnLambda(const PWRetriever::Iterator& iterator, const std::function<ruleCallback>& lambda);

    void resetMatchSession(bool runOnNew);

    bool isValid() const;

#ifdef TESTING
    friend bool tryInitializeRetriver(ddwaf_object input, uint32_t map, uint32_t array);
    FRIEND_TEST(TestAdditive, SelectiveRerun);
    FRIEND_TEST(TestPWManifest, TestUnknownArgID);
#endif
};

#endif /* PWArgsWrapper_h */
