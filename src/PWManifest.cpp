// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <PWManifest.h>
#include <utils.h>

void PWManifest::reserve(std::size_t count)
{
    argIDTable.reserve(count);
    argManifest.reserve(count);
}

PWManifest::ARG_ID PWManifest::insert(std::string_view name, PWManifest::ArgDetails&& arg)
{
    auto [it, result] = argManifest.emplace(counter, std::move(arg));
    (void) result; // unused
    argIDTable.emplace(name, counter);

    if(root_address_set.find(it->second.inheritFrom) == root_address_set.end()) {
        root_address_set.emplace(it->second.inheritFrom);
        root_addresses.push_back(it->second.inheritFrom.c_str());
    }

    return counter++;
}

bool PWManifest::hasTarget(const std::string& string) const
{
    return argIDTable.find(string) != argIDTable.cend();
}

PWManifest::ARG_ID PWManifest::getTargetArgID(const std::string& target) const
{
    return argIDTable.find(target)->second;
}

const PWManifest::ArgDetails& PWManifest::getDetailsForTarget(const PWManifest::ARG_ID& argID) const
{
    // We can't really return a dummy object when the key doesn't exist so the caller need to call `hasTarget` first.
    return argManifest.find(argID)->second;
}

const std::string& PWManifest::getTargetName(const PWManifest::ARG_ID& target) const
{
    static const std::string& dummyTargetName("<invalid>");

    for (const auto& argIDDefinition : argIDTable)
    {
        if (argIDDefinition.second == target)
        {
            return argIDDefinition.first;
        }
    }

    return dummyTargetName;
}

void PWManifest::findImpactedArgs(const std::unordered_set<std::string>& newFields, std::unordered_set<PWManifest::ARG_ID>& argsImpacted) const
{
    argsImpacted.reserve(argManifest.size());

    for (const auto& param : argManifest)
    {
        if (newFields.find(param.second.inheritFrom) != newFields.cend())
        {
            argsImpacted.insert(param.first);
        }
    }
}
