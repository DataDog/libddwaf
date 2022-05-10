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


ArgsIterator::State::State(const ddwaf_object* args, uint32_t maxDepth) : activeItem(args), itemIndex(0)
{
    stack.reserve(static_cast<size_t>(maxDepth));
}

bool ArgsIterator::State::isOver() const
{
    return activeItem == NULL && stack.empty();
}

void ArgsIterator::State::pushStack(const ddwaf_object* newActive)
{
    if (activeItem != NULL)
    {
        stack.emplace_back(std::make_pair(activeItem, itemIndex));
    }

    activeItem = newActive;
    itemIndex  = 0;
}

bool ArgsIterator::State::popStack()
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

void ArgsIterator::State::reset(const ddwaf_object* args)
{
    activeItem = args;
    itemIndex  = 0;
    stack.clear();
}

uint64_t ArgsIterator::State::getDepth() const
{
    // The depth of the active parameter is the length of the stack, plus one if the active item is a container
    const uint64_t depth = activeItem != nullptr && (activeItem->type & PWI_CONTAINER_TYPES) != 0;
    return depth + stack.size();
}

ArgsIterator::ArgsIterator(ddwaf_object* args, uint64_t maxMapDepth) : state(args, maxMapDepth)
{
    if (state.activeItem != nullptr && state.activeItem->type == DDWAF_OBJ_INVALID)
    {
        state.activeItem = nullptr;
    }
}

void ArgsIterator::gotoNext(bool skipIncrement)
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

void ArgsIterator::reset(const ddwaf_object* args)
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

const ddwaf_object* ArgsIterator::getActiveItem() const
{
    if (state.activeItem == nullptr)
        return NULL;

    if (state.activeItem->type & PWI_CONTAINER_TYPES)
        return &state.activeItem->array[state.itemIndex];

    return state.activeItem;
}

void ArgsIterator::getKeyPath(std::vector<ddwaf_object>& keyPath) const
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

bool ArgsIterator::isOver() const
{
    return state.isOver();
}

bool ArgsIterator::matchIterOnPath(const std::set<std::string>& path) const
{
    size_t stackPos          = 1;
    const auto& currentStack = state.stack;

    for (auto iter = path.cbegin(); iter != path.cend(); ++iter, ++stackPos)
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
        } else {
            return true;
        }

        //If the tree we're matching stop matching the list
        if (argValue->parameterName != nullptr && std::string_view(argValue->parameterName) != key)
        {
            return false;
        }
    }

    return true;
}

Iterator::Iterator(PWRetriever& _retriever) : 
    retriever(_retriever), argsIterator(nullptr, retriever.max_depth) {}

void Iterator::reset(const std::vector<PWManifest::ARG_ID>& targets)
{
    targetCursor = targets.cbegin();
    targetEnd    = targets.cend();

    // If we need to run only on new targets, we find the first new target
    if (retriever.runOnNewOnly)
    {
        while (targetCursor != targetEnd && !retriever.isKeyInLastBatch(*targetCursor))
        {
            targetCursor += 1;
        }
    }

    if (targetCursor == targetEnd) {
        return;
    }

    argsIterator.reset(retriever.getParameter(*targetCursor));
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

void Iterator::gotoNext()
{
    argsIterator.gotoNext();
    if (!argsIterator.isOver())
        return;

    // Are we done?
    if (isOver())
        return;

    // If we fully consummed the last item, let's move to the next one
    while (++targetCursor != targetEnd)
    {
        // If the new target isn't in the set of new targets and this isn't the first run, skip the target
        //	We already cached the result so there is no point in running on it again
        //	(there is an edge case when there are multiple filters on a rule but this is handled higher up)
        if (retriever.runOnNewOnly && !retriever.isKeyInLastBatch(*targetCursor))
        {
            continue;
        }

        // Pick the new top level object for the target
        argsIterator.reset(retriever.getParameter(*targetCursor));

        // If the object is valid, we good. Otherwise, loop again
        if (!argsIterator.isOver())
        {
            // Update the details
            updateTargetMetadata();
            return;
        }
    }
}

void Iterator::updateTargetMetadata()
{
    const auto& fullDetails = retriever.manifest.getDetailsForTarget(*targetCursor);
    currentTargetRunOnKey   = fullDetails.inline_transformer & PWT_KEYS_ONLY;
    currentTargetRunOnValue = fullDetails.inline_transformer & PWT_VALUES_ONLY;
}

bool Iterator::isOver() const
{
    return argsIterator.isOver() && (targetCursor == targetEnd);
}

PWManifest::ARG_ID Iterator::getActiveTarget() const
{
    return *targetCursor;
}

const std::string& Iterator::getDataSource() const
{
    return retriever.manifest.getDetailsForTarget(*targetCursor).inheritFrom;
}

const std::string& Iterator::getManifestKey() const
{
    return retriever.manifest.getTargetName(*targetCursor);
}

const ddwaf_object* Iterator::operator*() const
{
    return argsIterator.getActiveItem();
}

bool Iterator::shouldMatchKey() const
{
    if (!currentTargetRunOnKey)
        return false;

    if (argsIterator.isOver())
        return false;

    //We shouldn't match the key of the top level item
    return argsIterator.state.getDepth() != 0;
}

bool Iterator::shouldMatchValue() const
{
    if (!currentTargetRunOnValue)
        return false;

    return (argsIterator.getActiveItem()->type & PWI_CONTAINER_TYPES) == 0;
}

bool Iterator::matchIterOnPath(const std::set<std::string>& path) const
{
    return argsIterator.matchIterOnPath(path);
}

bool Iterator::moveIteratorForward(bool shouldIncrementFirst)
{
    if (shouldIncrementFirst)
        gotoNext();

    while (!isOver())
    {
        const auto& arg = retriever.manifest.getDetailsForTarget(getActiveTarget());
        if (arg.keyPaths.empty()) {
            return true;
        }

        if (matchIterOnPath(arg.keyPaths)) {
            return true;
        }

        gotoNext();
    }

    return false;
}

bool Iterator::runIterOnLambda(const std::function<ruleCallback>& lambda)
{
    const ddwaf_object* input = argsIterator.getActiveItem();
    //Do we have data?
    //This should be impossible with messing with the Iterator context and we can't call this function directly as it'll break the coverage
    // I'd still like the keep the test in just to be on the safe side
    if (input == nullptr) {
        return false;
    }

    //We match the key of the ddwaf_object if it exists
    if (shouldMatchKey() && lambda(input, DDWAF_OBJ_STRING, true, true))
    {
        return true;
    }

    if (shouldMatchValue() && lambda(input, input->type, false, true))
    {
        return true;
    }

    return false;
}


