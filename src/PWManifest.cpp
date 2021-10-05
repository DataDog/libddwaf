// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <PWManifest.h>
#include <utils.h>

PWManifest::ArgDetails::ArgDetails(const std::string& addr)
{
    size_t start = 0, end;

    end = addr.find(':', start);

    if (end == std::string::npos)
    {
        inheritFrom = addr;
        return;
    }

    inheritFrom = addr.substr(0, end);

    if (end + 1 < addr.size())
    {
        keyPaths.insert(addr.substr(end + 1, addr.size()));
    }
}

void PWManifest::reserve(std::size_t count)
{
    argIDTable.reserve(count);
    argManifest.reserve(count);
}

void PWManifest::insert(std::string_view name, PWManifest::ArgDetails&& arg)
{
    argManifest.emplace(counter, std::move(arg));
    argIDTable.emplace(name, counter);

    auto& details = argManifest.find(counter)->second;
    if (details.keyPaths.empty())
    {
        root_addresses.push_back(details.inheritFrom.c_str());
    }

    ++counter;
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

PWManifest::ArgDetails& PWManifest::getDetailsForTarget(const std::string& target)
{
    // We can't really return a dummy object when the key doesn't exist so the caller need to call `hasTarget` first.
    auto id = argIDTable.find(target)->second;
    return argManifest.find(id)->second;
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
