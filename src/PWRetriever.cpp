// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <vector>

#include <PWRetriever.hpp>
#include <PWTransformer.h>
#include <PowerWAF.hpp>
#include <log.hpp>
#include <rule.hpp>

PWRetriever::PWRetriever(const PWManifest& _manifest, const ddwaf::object_limits &limits):
    manifest(_manifest),
    max_depth(limits.max_container_depth),
    internalIterator(*this) {}

void PWRetriever::addParameter(const ddwaf_object input)
{
    newestBatch.clear();

    if (input.nbEntries == 0) {
        return;
    }

    std::size_t entries = static_cast<std::size_t>(input.nbEntries);
    const ddwaf_object* array = input.array;
    parameters.reserve(parameters.size() + entries);

    std::unordered_set<std::string> keyNames;
    keyNames.reserve(entries);

    for (std::size_t i = 0; i < entries; ++i)
    {
        auto length = static_cast<std::size_t>(array[i].parameterNameLength);
        std::string key(array[i].parameterName, length);

        parameters[key] = &array[i];
        keyNames.emplace(std::move(key));
    }

    manifest.findImpactedArgs(keyNames, newestBatch);
}

bool PWRetriever::hasNewArgs() const
{
    return !newestBatch.empty();
}

bool PWRetriever::isKeyInLastBatch(PWManifest::ARG_ID key) const
{
    return newestBatch.find(key) != newestBatch.cend();
}

Iterator& PWRetriever::getIterator(const std::vector<PWManifest::ARG_ID>& targets)
{
    internalIterator.reset(targets);
    return internalIterator;
}

const ddwaf_object* PWRetriever::getParameter(const PWManifest::ARG_ID paramID)
{
    const auto& details = manifest.getDetailsForTarget(paramID);

    //TODO: cache string rendering
    auto param = parameters.find(details.inheritFrom);
    if (param == parameters.end())
    {
        return nullptr;
    }

    return param->second;
}

void PWRetriever::resetMatchSession(bool _runOnNew)
{
    runOnNewOnly = _runOnNew;
}

bool PWRetriever::isValid() const
{
    return !parameters.empty();
}
