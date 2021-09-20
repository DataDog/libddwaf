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
#include <vector>

#include <re2/re2.h>
#include <utils.h>

#include <PWTransformer.h>
#include <ddwaf.h>

class PWRetriever;

class PWManifest
{
public:
	typedef uint32_t ARG_ID;

	struct ArgDetails
	{
        bool runOnKey{false};
        bool runOnValue{true};
		std::string inheritFrom; // Name of the ARG_ID to report the BA we matched
        std::vector<std::string> keyPaths;
        bool isAllowList{true};

        ArgDetails(const std::string &addr);
        ArgDetails(ArgDetails&&) = default;
        ArgDetails(const ArgDetails&) = delete;
        ArgDetails& operator=(ArgDetails&&) = default;
        ArgDetails& operator=(const ArgDetails&) = delete;

        ~ArgDetails() = default;
	};

private:
	std::unordered_map<std::string, ARG_ID> argIDTable;
	std::unordered_map<ARG_ID, ArgDetails> argManifest;
    std::vector<const char *> root_addresses;
    ARG_ID counter{0};
public:
    PWManifest() = default;

    PWManifest(PWManifest &&) = default;
    PWManifest(const PWManifest &) = delete;

    PWManifest& operator=(PWManifest&&) = default;
    PWManifest& operator=(const PWManifest&) = delete;

    void reserve(std::size_t count);
    void insert(std::string_view name, ArgDetails &&arg);
    bool empty() { return argIDTable.empty(); }

    std::vector<const char *>& get_root_addresses() { return root_addresses; };

	bool hasTarget(const std::string& string) const;
	ARG_ID getTargetArgID(const std::string& target) const;
	const ArgDetails& getDetailsForTarget(const PWManifest::ARG_ID& argID) const;
	const std::string& getTargetName(const PWManifest::ARG_ID& argID) const;

	void findImpactedArgs(const std::unordered_set<std::string>& newFields, std::unordered_set<ARG_ID>& argsImpacted) const;
};

#endif /* PWArgManifest_h */
