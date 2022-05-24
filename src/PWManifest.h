// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef PWArgManifest_h
#define PWArgManifest_h

#include <memory>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include <re2/re2.h>
#include <utils.h>

#include <PWTransformer.h>
#include <ddwaf.h>

class PWManifest
{
public:
    typedef uint32_t ARG_ID;

    struct ArgDetails
    {
        PW_TRANSFORM_ID inline_transformer { PWT_VALUES_ONLY };
        std::string inheritFrom; // Name of the ARG_ID to report the BA we matched
        std::vector<std::string> keyPaths;
        bool isAllowList { true };

        ArgDetails() = default;
        ArgDetails(const std::string& addr, PW_TRANSFORM_ID transformer) : inline_transformer(transformer),
                                                                           inheritFrom(addr) {}

        ArgDetails(const std::string& addr, const std::string& path, PW_TRANSFORM_ID transformer) : inline_transformer(transformer), inheritFrom(addr), keyPaths({ path }) {}

        ArgDetails(ArgDetails&&)      = default;
        ArgDetails(const ArgDetails&) = delete;
        ArgDetails& operator=(ArgDetails&&) = default;
        ArgDetails& operator=(const ArgDetails&) = delete;

        ~ArgDetails() = default;
    };

private:
    struct hash_pair
    {
        template <class T1, class T2>
        size_t operator()(const std::pair<T1, T2>& p) const
        {
            auto hash1 = std::hash<T1> {}(p.first);
            auto hash2 = std::hash<T2> {}(p.second);
            return hash1 ^ hash2;
        }
    };

    std::unordered_map<std::pair<std::string, PW_TRANSFORM_ID>, ARG_ID, hash_pair> argIDTable;
    std::unordered_map<ARG_ID, ArgDetails> argManifest;
    // Unique set of inheritFrom (root) addresses
    std::unordered_set<std::string_view> root_address_set;
    // Root address memory to be returned to the API caller
    std::vector<const char*> root_addresses;

    ARG_ID counter { 0 };

public:
    PWManifest() = default;

    PWManifest(PWManifest&&)      = default;
    PWManifest(const PWManifest&) = delete;

    PWManifest& operator=(PWManifest&&) = default;
    PWManifest& operator=(const PWManifest&) = delete;

    void reserve(std::size_t count);
    ARG_ID insert(std::string_view name, ArgDetails&& arg);
    bool empty() { return argIDTable.empty(); }

    const std::vector<const char*>& get_root_addresses() const { return root_addresses; };

    bool hasTarget(const std::string& string,
                   PW_TRANSFORM_ID transformer = PWT_VALUES_ONLY) const;
    ARG_ID getTargetArgID(const std::string& target,
                          PW_TRANSFORM_ID transformer = PWT_VALUES_ONLY) const;
    const ArgDetails& getDetailsForTarget(const PWManifest::ARG_ID& argID) const;
    const std::string& getTargetName(const PWManifest::ARG_ID& argID) const;

    void findImpactedArgs(const std::unordered_set<std::string>& newFields, std::unordered_set<ARG_ID>& argsImpacted) const;
};

#endif /* PWArgManifest_h */
