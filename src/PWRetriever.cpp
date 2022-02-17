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

bool PWRetriever::PWArgsWrapper::_validate_object(const ddwaf_object& input, uint32_t depth) const
{
    if (depth > maxMapDepth)
    {
        DDWAF_DEBUG("Validation error: Structure depth exceed the allowed limit!");
        return false;
    }

    switch (input.type)
    {
        case DDWAF_OBJ_SIGNED:
        case DDWAF_OBJ_UNSIGNED:
        {
            if (input.nbEntries != 0)
            {
                DDWAF_DEBUG("Validation error: Trying to encode an integer but nbEntries isn't 0");
                return false;
            }
            break;
        }

        case DDWAF_OBJ_STRING:
        {
            if (input.stringValue == nullptr)
            {
                DDWAF_DEBUG("Validation error: Trying to encode a string but payload is null");
                return false;
            }
            break;
        }

        case DDWAF_OBJ_ARRAY:
        case DDWAF_OBJ_MAP:
        {
            if (input.nbEntries != 0 && input.array == nullptr)
            {
                DDWAF_DEBUG("Validation error: Array claim not to be empty but actually is");
                return false;
            }

            else if (input.nbEntries > maxArrayLength)
            {
                DDWAF_DEBUG("Validation error: Array is unacceptably long");
                return false;
            }

            const bool isMap = input.type == DDWAF_OBJ_MAP;

            const ddwaf_object* array = input.array;
            for (uint64_t i = 0; i < input.nbEntries; ++i)
            {
                //Arrays aren't allowed to have parameter names but maps must have them
                // Therefore, unless hasParamName == isMap, something is wrong
                bool hasParamName = array[i].parameterName != nullptr;
                if (hasParamName != isMap)
                {
                    DDWAF_DEBUG("Validation error: key name are mandatory in maps (%u - %s)", isMap, (hasParamName ? array[i].parameterName : "(null)"));
                    return false;
                }

                if (isMap)
                {
                    DDWAF_TRACE("Performing recursive validation of key %s", array[i].parameterName);
                }
                else
                {
                    DDWAF_TRACE("Performing recursive validation of item #%" PRIu64, i);
                }

                if (!_validate_object(array[i], depth + 1))
                {
                    DDWAF_DEBUG("Validation error: the recursive validation failed");
                    return false;
                }
            }
            break;
        }

        default:
            DDWAF_DEBUG("Validation error: Unrecognized type %u", input.type);
            return false;
    }

    return true;
}

PWRetriever::PWArgsWrapper::PWArgsWrapper(uint64_t _maxMapDepth, uint64_t _maxArrayLength) : maxArrayLength(_maxArrayLength), maxMapDepth(_maxMapDepth) {}

bool PWRetriever::PWArgsWrapper::addParameter(const ddwaf_object input)
{
    DDWAF_TRACE("Sanitizing WAF parameters");

    //Do the limits make sense?
    if (maxMapDepth == 0 || maxArrayLength == 0)
    {
        DDWAF_DEBUG("Illegal WAF call: the sanitization constants don't make sense!");
        return false;
    }

    //Is the input even remotely valid
    if (input.type != DDWAF_OBJ_MAP)
    {
        DDWAF_DEBUG("Illegal WAF call: parameter structure isn't a map!");
        return false;
    }

    //Note: map can be empty
    if (input.nbEntries != 0 && input.array == nullptr)
    {
        DDWAF_DEBUG("Illegal WAF call: parameter structure claim not to be empty but actually is");
        return false;
    }

    // Sanitize the parameters, and if they're all good, insert them in the array
    const ddwaf_object* mainArray = input.array;
    for (size_t i = 0; i < input.nbEntries; ++i)
    {
        const char* parameterName = mainArray[i].parameterName;

        if (parameterName == nullptr)
        {
            DDWAF_DEBUG("Parameter #%zu doesn't have a name!", i);
            return false;
        }

        DDWAF_TRACE("Sanitizing parameter %s", parameterName);

        if (!_validate_object(mainArray[i]))
        {
            DDWAF_DEBUG("Sanitizing parameter %s failed!", parameterName);
            return false;
        }
    }

    // Ok, let's insert them
    parameters.reserve(parameters.size() + (size_t) input.nbEntries);
    for (size_t i = 0; i < input.nbEntries; ++i)
    {
        parameters[std::string(mainArray[i].parameterName, (size_t) mainArray[i].parameterNameLength)] = &mainArray[i];
    }

    DDWAF_TRACE("Parameter sanitization was successfull");
    return true;
}

const ddwaf_object* PWRetriever::PWArgsWrapper::getParameter(const std::string& paramName) const
{
    //TODO: cache string rendering
    auto param = parameters.find(paramName);
    if (param == parameters.end())
    {
        return nullptr;
    }

    return param->second;
}

bool PWRetriever::PWArgsWrapper::isValid() const
{
    return !parameters.empty();
}

PWRetriever::ArgsIterator::State::State(const ddwaf_object* args, uint64_t maxDepth) : activeItem(args), itemIndex(0)
{
    stack.reserve((size_t) maxDepth);
}

bool PWRetriever::ArgsIterator::State::isOver() const
{
    return activeItem == NULL && stack.empty();
}

void PWRetriever::ArgsIterator::State::pushStack(const ddwaf_object* newActive)
{
    if (activeItem != NULL)
    {
        stack.emplace_back(std::make_pair(activeItem, itemIndex));
    }

    activeItem = newActive;
    itemIndex  = 0;
}

bool PWRetriever::ArgsIterator::State::popStack()
{
    if (stack.empty())
    {
        return false;
    }

    auto item = stack.back();

    activeItem = item.first;
    itemIndex  = item.second + 1;

    stack.pop_back();
    return true;
}

void PWRetriever::ArgsIterator::State::reset(const ddwaf_object* args)
{
    activeItem = args;
    itemIndex  = 0;
    stack.clear();
}

uint64_t PWRetriever::ArgsIterator::State::getDepth() const
{
    // The depth of the active parameter is the length of the stack, plus one if the active item is a container
    const uint64_t depth = activeItem != nullptr && (activeItem->type & PWI_CONTAINER_TYPES) != 0;
    return depth + stack.size();
}

PWRetriever::ArgsIterator::ArgsIterator(ddwaf_object* args, uint64_t maxMapDepth) : state(args, maxMapDepth)
{
    if (state.activeItem != nullptr && state.activeItem->type == DDWAF_OBJ_INVALID)
    {
        state.activeItem = nullptr;
    }
}

void PWRetriever::ArgsIterator::gotoNext(bool skipIncrement)
{
    // We need to detect the first item not to loop infinitely on "hasRelevantKey"
    for (bool isFirstItem = true; !state.isOver(); isFirstItem = false)
    {
        // If there is an active item we were consuming, see if there is more data
        // Otherwise, keep following this logic
        if (state.activeItem != nullptr)
        {
            if (state.activeItem->type & PWI_CONTAINER_TYPES)
            {
                bool wasCurrentItemMidProcessing = false;

                // Startup code flow, we want to find an object to consume but not skip the first one
                if (skipIncrement && state.itemIndex < state.activeItem->nbEntries)
                {
                    skipIncrement = false;
                }

                // If the child was a container, this mean we waited on an intermediary item to run on its key.
                // We can now proceed by skipping the `hasRelevantKey` condition
                else if (isFirstItem && state.itemIndex < state.activeItem->nbEntries && state.activeItem->array[state.itemIndex].type & PWI_CONTAINER_TYPES)
                {
                    wasCurrentItemMidProcessing = true;
                }

                // Do we have an additional item to consume?
                else if (++state.itemIndex >= state.activeItem->nbEntries)
                {
                    state.activeItem = nullptr;
                    continue;
                }

                bool itemAccepted = false;
                while (true)
                {
                    const ddwaf_object& newItem = state.activeItem->array[state.itemIndex];

                    // If yes, is it a valid item?
                    if (newItem.type == DDWAF_OBJ_INVALID)
                    {
                        // If it's not, let's loop back with the top level loop
                        break;
                    }

                    // Is there a key to run on, we may want to pause
                    bool hasRelevantKey = newItem.parameterName != NULL && !wasCurrentItemMidProcessing;

                    // Otherwise, if it's a container, we skip the item...
                    if (!hasRelevantKey && newItem.type & PWI_CONTAINER_TYPES)
                    {
                        // Empty container, ignore it
                        if (newItem.nbEntries == 0)
                        {
                            // If it's not, let's loop back with the top level loop
                            break;
                        }

                        // Push the stack
                        state.pushStack(&state.activeItem->array[state.itemIndex]);

                        // Make sure that if we ignored an intermediary key, we consider the next one we may meet
                        wasCurrentItemMidProcessing = false;

                        // We want to re-run the logic and handle encapsulated containers
                        continue;
                    }
                    else
                    {
                        // We're good!
                        itemAccepted = true;
                        break;
                    }
                }

                if (itemAccepted)
                {
                    return;
                }
            }
            else
            {
                state.activeItem = nullptr;
                break;
            }
        }

        // Was there a stack with item to consume?
        else if (state.popStack())
        {
            // Poping the stack updated the active item, let's run the first part of the logic again
            skipIncrement = true;
            isFirstItem   = false;
            continue;
        }
    }
}

void PWRetriever::ArgsIterator::reset(const ddwaf_object* args)
{
    if (args != nullptr && args->type != DDWAF_OBJ_INVALID)
    {
        state.reset(args);

        // If we're a container, we need to find the first valid item
        if (state.activeItem->type & PWI_CONTAINER_TYPES)
        {
            gotoNext(true);
        }
    }
    else
    {
        state.reset(nullptr);
    }
}

const ddwaf_object* PWRetriever::ArgsIterator::getActiveItem() const
{
    if (state.activeItem == nullptr)
        return NULL;

    if (state.activeItem->type & PWI_CONTAINER_TYPES)
        return &state.activeItem->array[state.itemIndex];

    return state.activeItem;
}

void PWRetriever::ArgsIterator::getKeyPath(std::vector<ddwaf_object>& keyPath) const
{
    keyPath.reserve(state.stack.size() + 2);

    if (!state.stack.empty())
    {
        for (auto iter = state.stack.cbegin() + 1; iter != state.stack.cend(); ++iter)
        {
            ddwaf_object arg;
            if (iter->first->parameterNameLength != 0)
            {
                ddwaf_object_stringl_nc(&arg, iter->first->parameterName, iter->first->parameterNameLength);
            }
            else
            {
                // Store the index
                ddwaf_object_unsigned_force(&arg, (iter - 1)->second);
            }

            keyPath.emplace_back(arg);
        }

        if (state.activeItem != NULL)
        {
            ddwaf_object arg;
            if (state.activeItem->parameterNameLength)
            {
                ddwaf_object_stringl_nc(&arg, state.activeItem->parameterName, state.activeItem->parameterNameLength);
            }
            else
            {
                // Store the index
                ddwaf_object_unsigned_force(&arg, state.stack.back().second);
            }

            keyPath.emplace_back(arg);
        }
    }

    if (state.activeItem != NULL && state.activeItem->type & PWI_CONTAINER_TYPES)
    {
        ddwaf_object arg;
        if (state.activeItem->type == DDWAF_OBJ_MAP && state.itemIndex < state.activeItem->nbEntries)
        {
            const ddwaf_object& lastItem = state.activeItem->array[state.itemIndex];

            ddwaf_object_stringl_nc(&arg, lastItem.parameterName, lastItem.parameterNameLength);
        }
        else
        {
            ddwaf_object_unsigned_force(&arg, state.itemIndex);
        }

        keyPath.emplace_back(arg);
    }
}

bool PWRetriever::ArgsIterator::isOver() const
{
    return state.isOver();
}

bool PWRetriever::ArgsIterator::matchIterOnPath(const std::set<std::string>& path, bool isAllowList, size_t& blockDepth) const
{
    size_t stackPos          = 1;
    const auto& currentStack = state.stack;

    for (auto iter = path.cbegin(); iter != path.cend(); ++iter, ++blockDepth, ++stackPos)
    {
        const std::string& key = *iter;

        const ddwaf_object* argValue;

        // Go throught the stack ensuring we match the list
        if (stackPos < currentStack.size())
        {
            argValue = currentStack[stackPos].first;
        }
        // Okay, the full stack match the keys, now check the active item
        else if (stackPos == currentStack.size())
        {
            argValue = state.activeItem;
        }
        // If the active item is a container, we have one more level
        else if (stackPos == currentStack.size() + 1 && state.activeItem->type & PWI_CONTAINER_TYPES)
        {
            argValue = &state.activeItem->array[state.itemIndex];
        }

        // Our path doesn't go this far, this is a problem in the case of an allowlist, not if that's a blocklist
        else
        {
            return isAllowList;
        }

        //If the tree we're matching stop matching the list
        if (argValue->parameterName != nullptr && std::string_view(argValue->parameterName) != key)
        {
            return false;
        }
    }

    return true;
}

PWRetriever::Iterator::State::State(uint64_t _maxDepth) : maxDepth(_maxDepth) {}

bool PWRetriever::Iterator::State::isOver() const
{
    return targetCursor == targetEnd;
}

PWRetriever::Iterator::Iterator(PWRetriever& _retriever) : retriever(_retriever), state(retriever.wrapper.maxMapDepth), argsIterator(nullptr, state.maxDepth) {}

void PWRetriever::Iterator::reset(const std::vector<PWManifest::ARG_ID>& targets)
{
    state.targetCursor = targets.cbegin();
    state.targetEnd    = targets.cend();

    // If we need to run only on new targets, we find the first new target
    if (retriever.runOnNewOnly)
    {
        while (state.targetCursor != state.targetEnd && !retriever.isKeyInLastBatch(*state.targetCursor))
        {
            state.targetCursor += 1;
        }
    }

    if (state.targetCursor == state.targetEnd)
        return;

    argsIterator.reset(retriever.getParameter(*state.targetCursor));
    if (!argsIterator.isOver())
    {
        // If we have a valid item, then we query which high tidbits we're interested in
        updateTargetMetadata();
    }
    else
    {
        // If we don't we let the gotoNext logic handle that for us
        gotoNext();
    }
}

void PWRetriever::Iterator::gotoNext(bool skipIncrement)
{
    argsIterator.gotoNext(skipIncrement);
    if (!argsIterator.isOver())
        return;

    // Are we done?
    if (state.isOver())
        return;

    // If we fully consummed the last item, let's move to the next one
    while (++state.targetCursor != state.targetEnd)
    {
        // If the new target isn't in the set of new targets and this isn't the first run, skip the target
        //	We already cached the result so there is no point in running on it again
        //	(there is an edge case when there are multiple filters on a rule but this is handled higher up)
        if (retriever.runOnNewOnly && !retriever.isKeyInLastBatch(*state.targetCursor))
        {
            continue;
        }

        // Pick the new top level object for the target
        argsIterator.reset(retriever.getParameter(*state.targetCursor));

        // If the object is valid, we good. Otherwise, loop again
        if (!argsIterator.isOver())
        {
            // Update the details
            updateTargetMetadata();
            return;
        }
    }
}

void PWRetriever::Iterator::updateTargetMetadata()
{
    const auto& fullDetails = retriever.manifest.getDetailsForTarget(*state.targetCursor);
    currentTargetRunOnKey   = fullDetails.runOnKey;
    currentTargetRunOnValue = fullDetails.runOnValue;
}

bool PWRetriever::Iterator::isOver() const
{
    return argsIterator.isOver() && state.isOver();
}

PWManifest::ARG_ID PWRetriever::Iterator::getActiveTarget() const
{
    return *state.targetCursor;
}

const std::string& PWRetriever::Iterator::getDataSource() const
{
    return retriever.manifest.getDetailsForTarget(*state.targetCursor).inheritFrom;
}

const std::string& PWRetriever::Iterator::getManifestKey() const
{
    return retriever.manifest.getTargetName(*state.targetCursor);
}

const ddwaf_object* PWRetriever::Iterator::operator*() const
{
    return argsIterator.getActiveItem();
}

bool PWRetriever::Iterator::shouldMatchKey() const
{
    if (!currentTargetRunOnKey)
        return false;

    if (argsIterator.isOver())
        return false;

    //We shouldn't match the key of the top level item
    return argsIterator.state.getDepth() != 0;
}

bool PWRetriever::Iterator::shouldMatchValue() const
{
    if (!currentTargetRunOnValue)
        return false;

    return (argsIterator.getActiveItem()->type & PWI_CONTAINER_TYPES) == 0;
}

bool PWRetriever::Iterator::matchIterOnPath(const std::set<std::string>& path, bool isAllowList, size_t& blockDepth) const
{
    return argsIterator.matchIterOnPath(path, isAllowList, blockDepth);
}

PWRetriever::PWRetriever(const PWManifest& _manifest, uint64_t _maxMapDepth, uint64_t _maxArrayLength) : manifest(_manifest), wrapper(_maxMapDepth, _maxArrayLength), internalIterator(*this) {}

bool PWRetriever::addParameter(const ddwaf_object input)
{
    newestBatch.clear();
    if (!wrapper.addParameter(input))
        return false;

    if (input.nbEntries)
    {
        // Populate newestBatch
        std::unordered_set<std::string> keyNames;
        keyNames.reserve((size_t) input.nbEntries);
        for (size_t i = 0; i < input.nbEntries; ++i)
        {
            keyNames.insert(std::string(input.array[i].parameterName, (size_t) input.array[i].parameterNameLength));
        }

        manifest.findImpactedArgs(keyNames, newestBatch);
    }
    return true;
}

bool PWRetriever::hasNewArgs() const
{
    return !newestBatch.empty();
}

bool PWRetriever::isKeyInLastBatch(PWManifest::ARG_ID key) const
{
    return newestBatch.find(key) != newestBatch.cend();
}

PWRetriever::Iterator& PWRetriever::getIterator(const std::vector<PWManifest::ARG_ID>& targets)
{
    internalIterator.reset(targets);
    return internalIterator;
}

const ddwaf_object* PWRetriever::getParameter(const PWManifest::ARG_ID paramID)
{
    const auto& details = manifest.getDetailsForTarget(paramID);
    return wrapper.getParameter(details.inheritFrom);
}

const PWRetriever::MatchHistory& PWRetriever::getMatchHistory() const
{
    return history;
}

bool PWRetriever::moveIteratorForward(Iterator& iter, bool shouldIncrementFirst)
{
    if (shouldIncrementFirst)
        iter.gotoNext();

    while (!iter.isOver())
    {
        const auto& arg = manifest.getDetailsForTarget(iter.getActiveTarget());
        if (arg.keyPaths.empty())
            return true;

        const bool isAllowList = arg.isAllowList;
        bool matchPath         = true;
        size_t maxDepth        = 0;
        size_t blockDepth      = 0;
        // The key is accepted, if:
        //  - in the case of a blocklist, it was rejected consistently
        //  - in the case of an allowlist, it accepted at least once
        if ((matchPath = iter.matchIterOnPath(arg.keyPaths, isAllowList, blockDepth)))
        {
            if (arg.isAllowList)
                return true;

            // The blocklist matched :(
            maxDepth = blockDepth - 1;
        }

        // Either we matched the full list and never matched (good for blocklist, bad for allowlist)
        //		or we matched the blacklist

        // Never matched the blocklist
        if (!matchPath && !isAllowList)
            return true;

        // If we matched the blocklist, we need to first pop the stack until we get out of the restricted region
        bool popped = false;

        if (!isAllowList)
        {
            while (iter.argsIterator.state.getDepth() > maxDepth && iter.argsIterator.state.popStack())
                popped = true;
        }

        iter.gotoNext(popped);
    }

    return false;
}

bool PWRetriever::runIterOnLambda(const PWRetriever::Iterator& iterator, const bool saveOnMatch, const std::function<ruleCallback>& lambda)
{
    const ddwaf_object* input = *iterator;
    //Do we have data?
#ifndef TESTING
    //This should be impossible with messing with the Iterator context and we can't call this function directly as it'll break the coverage
    // I'd still like the keep the test in just to be on the safe side
    if (input == nullptr)
        return false;
#endif

    //We match the key of the ddwaf_object if it exists
    if (iterator.shouldMatchKey() && lambda(input, DDWAF_OBJ_STRING, true, true))
    {
        if (saveOnMatch)
            registerMatch(input->parameterName, input->parameterNameLength);

        return true;
    }

    if (iterator.shouldMatchValue() && lambda(input, input->type, false, true))
    {
        if (saveOnMatch && input->type == DDWAF_OBJ_STRING)
            registerMatch(input->stringValue, input->nbEntries);

        return true;
    }

    return false;
}

PWRetriever::MatchHistory::MatchHistory()
{
    matchSession.reserve(8);
}

void PWRetriever::registerMatch(const char* value, uint64_t length)
{
    history.saveFullMatch(value, (size_t) length);
}

void PWRetriever::commitMatch(MatchGatherer& gather)
{
    history.saveSubmatches(std::move(gather.submatches));
    history.commitMatch(std::move(gather.dataSource), std::move(gather.manifestKey), std::move(gather.keyPath));
    gather.clear();
}

void PWRetriever::setActiveFilter(size_t newFilter)
{
    history.setActiveFilter(newFilter);
}

void PWRetriever::resetMatchSession(bool _runOnNew)
{
    history.reset();
    runOnNewOnly = _runOnNew;
}

bool PWRetriever::isValid() const
{
    return wrapper.isValid();
}

void PWRetriever::MatchHistory::Match::reset()
{
    hasFullMatch = false;
    hasSubMatch  = false;
    subMatch.clear();
}

void PWRetriever::MatchHistory::saveFullMatch(const char* value, size_t length)
{
    if (value != NULL)
    {
        currentMatch.hasFullMatch    = true;
        currentMatch.fullMatch       = value;
        currentMatch.fullMatchLength = length;
    }
}

void PWRetriever::MatchHistory::saveSubmatches(submatchType&& submatches)
{
    if (!submatches.empty())
    {
        currentMatch.hasSubMatch = true;
        currentMatch.subMatch    = std::move(submatches);
    }
}

void PWRetriever::MatchHistory::commitMatch(std::string&& dataSource, std::string&& manifestKey, std::vector<ddwaf_object>&& keyPath)
{
    if (currentMatch.hasSubMatch || currentMatch.hasFullMatch)
    {
        currentMatch.dataSource  = std::move(dataSource);
        currentMatch.manifestKey = std::move(manifestKey);
        currentMatch.keyPath     = std::move(keyPath);
        matchSession.emplace_back(std::make_pair(currentFilter, std::move(currentMatch)));
    }
}

void PWRetriever::MatchHistory::setActiveFilter(size_t newFilter)
{
    currentFilter = newFilter;
    currentMatch.reset();
}

void PWRetriever::MatchHistory::reset()
{
    matchSession.clear();
    currentMatch.reset();
}
