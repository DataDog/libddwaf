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

namespace ddwaf
{

namespace
{
bool is_container(const ddwaf_object *obj)
{
    return obj != nullptr  && (obj->type & PWI_CONTAINER_TYPES) != 0;
}

bool is_scalar(const ddwaf_object *obj)
{
    return obj != nullptr && (obj->type & PWI_DATA_TYPES) != 0;
}

bool is_null(const ddwaf_object *obj)
{
    return obj == nullptr || obj->type == DDWAF_OBJ_INVALID;
}

std::pair<unsigned, bool> to_unsigned(std::string_view str)
{
    try {
        std::size_t pos;
        auto converted = std::stol(str.data(), &pos);
        if (pos == str.size() && converted >= 0) {
            return {converted, true};
        }
    } catch (...) { }

    return {0, false};
}

}

object_iterator::object_iterator(const ddwaf_object *obj,
    const std::vector<std::string> &path,
    const object_limits &limits): limits_(limits), path_size_(path.size())
{
    stack_.reserve(initial_stack_size);

    if (path.empty()) {
        initialise_cursor(obj);
    } else {
        initialise_cursor_with_path(obj, path);
    }
}

void object_iterator::initialise_cursor(const ddwaf_object *obj)
{
    if (is_null(obj)) { return; }
    if (is_scalar(obj)) { current_ = obj; return; }

    // Uninitialised object...? We should throw an exception at some point
    if (!is_container(obj)) { return; }

    // Add container to stack and find next scalar
    if ((limits_.max_container_depth - 1) > 0) {
        stack_.push_back({obj, 0});
        set_cursor_to_next_scalar();
    }
}

void object_iterator::initialise_cursor_with_path(const ddwaf_object *obj,
    const std::vector<std::string> &path)
{
    // An object with a path should always start with a container
    if (!is_container(obj)) { return; }

    if ((limits_.max_container_depth - 1) <= 0) { return; }

    // TODO: path shouldn't be longer than max_depth, although this can
    // be enforced during initialisation / parsing.

    // Add container to stack and find next scalar within the given path
    stack_.push_back({obj, 0});
    
    std::size_t size = std::min(path.size(),
            static_cast<std::size_t>(limits_.max_container_depth));
    for (std::size_t i = 0; i < size; i++) {
        std::string_view key = path[i];
        auto &[parent, index] = stack_.back();

        ddwaf_object *child = nullptr;
        if (parent->type == DDWAF_OBJ_MAP) {
            for (std::size_t j = 0; j < parent->nbEntries; j++) {
                auto possible_child = &parent->array[j];
                std::string_view child_key(possible_child->parameterName,
                    possible_child->parameterNameLength);

                if (child_key == key) {
                    child = possible_child;
                    index = j + 1;
                    break;
                }
            }
        } else if (parent->type == DDWAF_OBJ_ARRAY) {
            // TODO somehow cache this to avoid doing it over and over
            auto [key_idx, res] = to_unsigned(key);

            // The key is not an integer or larger than the number of entries
            // we fail.
            if (!res || key_idx >= parent->nbEntries) { break; }

            child = &parent->array[key_idx];
            index = key_idx + 1;
        }

        // We matched a key in the path but the item is null, so we
        // break as there won't be anything else to look for. The
        // iterator is effectively invalid.
        if (!is_null(child)) {
            // If we find a scalar and it's the last element,
            // we found a valid element within the path.
            if (is_scalar(child) && (i + 1) == path.size()) {
                current_ = child;
            } else if (is_container(child)) {
                stack_.push_back({child, 0});

                if ((i + 1) < path.size()) { continue; }
                // If it's the last element in the path, we get the next
                // scalar and exit
                set_cursor_to_next_scalar();
            }
        }

        // If we reach this point
        break;
    }
}

void object_iterator::set_cursor_to_next_scalar()
{
    current_ = nullptr;

    // The stack is the same size as the path, which means the current was
    // within the path, so we can't continue;
    if (path_size_ > 0 && stack_.size() == path_size_) { return; }

    while (!stack_.empty() && current_ == nullptr) {
        auto &[parent, index] = stack_.back();

        if (index >= parent->nbEntries || index >= limits_.max_container_size) {
            // We are at the end of the container, but if the container is the
            // last element in the path, we can't remove it.
            if (path_size_ > 0 && stack_.size() == (path_size_ + 1)) {
                break;
            }
            // Pop can invalidate the parent references so after this point
            // they should not be used.
            stack_.pop_back();
            continue;
        }

        if (is_container(&parent->array[index])) {
            if (stack_.size() < limits_.max_container_depth) {
                // Push can invalidate the current references to the parent
                // so we increment the index before a potential reallocation
                // and prevent any further use of the references.
                stack_.push_back({&parent->array[index++], 0});
                continue;
            }
        } else if (is_scalar(&parent->array[index])) {
            current_ = &parent->array[index];
        }

        ++index;
    }
}

bool object_iterator::operator++()
{
    if (current_ != nullptr) {
        set_cursor_to_next_scalar();
    }
    return current_ != nullptr;
}

// TODO: return string_view as this will be immediately copied after
std::vector<std::string> object_iterator::get_current_path()
{
    if (stack_.empty() || current_ == nullptr) {
        return {};
    }

    std::vector<std::string> keys;
    keys.reserve(stack_.size());

    auto [parent, parent_index] = stack_.front();
    for (unsigned i = 1; i < stack_.size(); i++) {
        auto [child, child_index] = stack_[i];
        if (parent->type == DDWAF_OBJ_MAP && child->parameterName != nullptr) {
            keys.emplace_back(child->parameterName, child->parameterNameLength);
        } else if (parent->type == DDWAF_OBJ_ARRAY) {
            keys.emplace_back(std::to_string(parent_index - 1));
        }

        parent = child;
        parent_index = child_index;
    }

    if (parent->type == DDWAF_OBJ_MAP && current_->parameterName != nullptr) {
        keys.emplace_back(current_->parameterName, current_->parameterNameLength);
    } else if (parent->type == DDWAF_OBJ_ARRAY) {
        keys.emplace_back(std::to_string(parent_index - 1));
    }

    return keys;
}

}


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

bool ArgsIterator::matchIterOnPath(const std::vector<std::string>& path) const
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

bool Iterator::matchIterOnPath(const std::vector<std::string>& path) const
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


