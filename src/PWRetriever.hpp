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

struct RuleMatchTarget;

class PWRetriever
{
public:
    class PWArgsWrapper
    {
        std::unordered_map<std::string, const ddwaf_object*> parameters;
        const uint64_t maxArrayLength;

        bool _validate_object(const ddwaf_object& input, uint32_t depth = 0) const;

    public:
        const uint64_t maxMapDepth;

        PWArgsWrapper(uint64_t _maxMapDepth, uint64_t _maxArrayLength);
        bool addParameter(const ddwaf_object input);
        const ddwaf_object* getParameter(const std::string& paramName) const;
        bool isValid() const;

#ifdef TESTING
        FRIEND_TEST(TestPWArgsWrapper, TestMalformedUnsignedInt);
        FRIEND_TEST(TestPWArgsWrapper, TestMalformedSignedInt);
        FRIEND_TEST(TestPWArgsWrapper, TestMalformedString);
        FRIEND_TEST(TestPWArgsWrapper, TestMalformedMap);
        FRIEND_TEST(TestPWArgsWrapper, TestRecursiveMap);
        FRIEND_TEST(TestPWArgsWrapper, TestMalformedArray);
        FRIEND_TEST(TestPWArgsWrapper, TestRecursiveArray);
        FRIEND_TEST(TestPWArgsWrapper, TestInvalidType);
#endif
    };

    class ArgsIterator
    {
        struct State
        {
            std::vector<std::pair<const ddwaf_object*, size_t>> stack;
            const ddwaf_object* activeItem;
            size_t itemIndex;

            State(const ddwaf_object* args, uint64_t maxDepth);
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
            const uint64_t maxDepth;

            State(uint64_t _maxDepth);
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

    struct MatchHistory
    {
        using submatchType = std::vector<std::pair<uint8_t, std::string>>;

        struct Match
        {
            // Full matches (MATCHED_VARS)
            bool hasFullMatch = false;
            const char* fullMatch;
            size_t fullMatchLength;

            // Submatches if asked. More complex but less common so trying to untie this overhead from the more comment matchSession
            bool hasSubMatch = false;
            submatchType subMatch;

            std::string dataSource;
            std::string manifestKey;
            std::vector<ddwaf_object> keyPath;

            void reset();
        };

        size_t currentFilter;
        Match currentMatch;

        std::vector<std::pair<size_t, Match>> matchSession;

        MatchHistory();

        void setActiveFilter(size_t newFilter);

        void saveFullMatch(const char* value, size_t length);
        void saveSubmatches(submatchType&& submatches);
        void commitMatch(std::string&& dataSource, std::string&& manifestKey, std::vector<ddwaf_object>&& keyPath);

        void reset();
    };

private:
    const PWManifest& manifest;
    PWArgsWrapper wrapper;
    MatchHistory history;

    Iterator internalIterator;

    std::unordered_set<PWManifest::ARG_ID> newestBatch;
    bool runOnNewOnly = false;

    bool _matchIterOnPath(const Iterator& _iter, const std::vector<ddwaf_object>& path, bool isAllowList, size_t& blockDepth) const;

    using ruleCallback = bool(const ddwaf_object*, DDWAF_OBJ_TYPE, bool, bool);

public:
    PWRetriever(const PWManifest& _manifest, uint64_t _maxMapDepth, uint64_t _maxArrayLength);
    bool addParameter(const ddwaf_object input);
    bool hasNewArgs() const;
    bool isKeyInLastBatch(PWManifest::ARG_ID key) const;

    Iterator& getIterator(const std::vector<PWManifest::ARG_ID>& targets);
    const ddwaf_object* getParameter(const PWManifest::ARG_ID paramID);
    const MatchHistory& getMatchHistory() const;

    bool moveIteratorForward(Iterator& iter, bool shouldIncrementFirst = true);

    bool runIterOnLambda(const PWRetriever::Iterator& iterator, const bool saveOnMatch, const std::function<ruleCallback>& lambda);

    void registerMatch(const char* value, uint64_t length);
    void commitMatch(MatchGatherer& gather);

    void setActiveFilter(size_t newFilter);
    void resetMatchSession(bool runOnNew);

    bool isValid() const;

#ifdef TESTING
    friend bool tryInitializeRetriver(ddwaf_object input, uint32_t map, uint32_t array);
    FRIEND_TEST(TestAdditive, SelectiveRerun);
    FRIEND_TEST(TestPWManifest, TestUnknownArgID);
#endif
};

#endif /* PWArgsWrapper_h */
