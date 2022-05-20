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
std::vector<std::string> object_iterator::get_current_path() const
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
