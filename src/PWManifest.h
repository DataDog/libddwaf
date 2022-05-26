// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef PWArgManifest_h
#define PWArgManifest_h

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <utils.h>
#include <vector>

#include <ddwaf.h>

namespace ddwaf
{
class manifest
{
public:
    using target_type = uint32_t;
    using target_info = std::pair<target_type, std::vector<std::string>>;
    using target_set = std::unordered_set<target_type>;

    manifest() = default;
    manifest(manifest&&)      = default;
    manifest(const manifest&) = delete;
    manifest& operator=(manifest&&) = default;
    manifest& operator=(const manifest&) = delete;

    target_type insert(const std::string &name, const std::string &root,
            const std::string &key_path = {});

    bool empty() { return targets_.empty(); }

    const std::vector<const char*>& get_root_addresses() const {
        return root_addresses_;
    }

    bool contains(const std::string& name) const;
    target_type get_target(const std::string& name) const;
    std::string get_target_name(target_type target) const;
    const target_info get_target_info(target_type target) const;

    void find_derived_targets(const target_set& root_targets,
            target_set& derived_targets) const;

protected:

    std::unordered_map<std::string, target_type> targets_{};
    std::unordered_map<target_type, std::string> names_{};
    std::unordered_map<target_type, std::unordered_set<target_type>> derived_{};
    std::unordered_map<target_type, target_info> info_{};

    // Unique set of root addresses
    std::unordered_set<std::string> root_address_set_{};
    // Root address memory to be returned to the API caller
    std::vector<const char*> root_addresses_;

    target_type target_counter_{1};
};

}

class PWManifest
{
public:
    typedef uint32_t ARG_ID;

    struct ArgDetails
    {
        std::string inheritFrom; // Name of the ARG_ID to report the BA we matched
        std::vector<std::string> keyPaths;

        ArgDetails() = default;
        ArgDetails(const std::string& addr): inheritFrom(addr) {}

        ArgDetails(const std::string& addr, const std::string& path) : inheritFrom(addr), keyPaths({ path }) {}

        ArgDetails(ArgDetails&&)      = default;
        ArgDetails(const ArgDetails&) = delete;
        ArgDetails& operator=(ArgDetails&&) = default;
        ArgDetails& operator=(const ArgDetails&) = delete;

        ~ArgDetails() = default;
    };

private:
    std::unordered_map<std::string, ARG_ID> argIDTable;
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

    ARG_ID insert(std::string_view name, ArgDetails&& arg);
    bool empty() { return argIDTable.empty(); }

    const std::vector<const char*>& get_root_addresses() const { return root_addresses; };

    bool hasTarget(const std::string& string) const;
    ARG_ID getTargetArgID(const std::string& target) const;
    const ArgDetails& getDetailsForTarget(const PWManifest::ARG_ID& argID) const;
    const std::string& getTargetName(const PWManifest::ARG_ID& argID) const;

    void findImpactedArgs(const std::unordered_set<std::string>& newFields, std::unordered_set<ARG_ID>& argsImpacted) const;
};

#endif /* PWArgManifest_h */
