// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <cstdint>
#include <random>

#include "condition/cmdi_detector.hpp"

using namespace ddwaf;
using namespace std::literals;

extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

extern "C" int LLVMFuzzerInitialize(const int * /*argc*/, char *** /*argv*/)
{
    ddwaf::memory::set_local_memory_resource(std::pmr::new_delete_resource());
    return 0;
}

template <typename... Args> std::vector<condition_parameter> gen_param_def(Args... addresses)
{
    return {{{{std::string{addresses}, get_target_index(addresses)}}}...};
}

// NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
std::pair<std::vector<std::string_view>, std::string_view> deserialize(
    const uint8_t *data, size_t size)
{
    if (size < sizeof(std::size_t)) {
        return {};
    }

    const auto resource_size = *reinterpret_cast<const std::size_t *>(data);

    data += sizeof(std::size_t);
    size -= sizeof(std::size_t);

    if (size < sizeof(std::size_t)) {
        return {};
    }

    std::vector<std::string_view> resource;
    resource.reserve(resource_size);

    for (std::size_t i = 0; i < resource_size; ++i) {
        const auto arg_size = *reinterpret_cast<const std::size_t *>(data);
        data += sizeof(std::size_t);
        size -= sizeof(std::size_t);

        if (size < arg_size) {
            return {};
        }

        std::string_view arg{reinterpret_cast<const char *>(data), arg_size};
        data += arg_size;
        size -= arg_size;

        resource.emplace_back(arg);
    }

    if (size < sizeof(std::size_t)) {
        return {};
    }

    const auto param_size = *reinterpret_cast<const std::size_t *>(data);
    data += sizeof(std::size_t);
    size -= sizeof(std::size_t);

    if (size < param_size) {
        return {};
    }

    std::string_view param{reinterpret_cast<const char *>(data), param_size};

    return {std::move(resource), param};
}

struct serializer {
    uint8_t *data;
    std::size_t total_size{0};

    explicit serializer(uint8_t *Data) : data(Data) {}

    void serialize(std::size_t size)
    {
        memcpy(data, reinterpret_cast<uint8_t *>(&size), sizeof(std::size_t));
        data += sizeof(std::size_t);
        total_size += sizeof(std::size_t);
    }

    void serialize(std::string_view str)
    {
        std::size_t size = str.size();
        serialize(size);

        memcpy(data, str.data(), size);
        data += size;
        total_size += size;
    }

    template <typename T>
    std::size_t serialize(const std::vector<T> &resource, std::string_view param)
        requires std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view>
    {
        serialize(resource.size());
        for (const auto &arg : resource) { serialize(arg); }
        serialize(param);

        return total_size;
    }
};

// NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)

extern "C" size_t LLVMFuzzerCustomMutator(
    // NOLINTNEXTLINE
    uint8_t *Data, size_t Size, [[maybe_unused]] size_t MaxSize, [[maybe_unused]] unsigned int Seed)
{
    static thread_local std::mt19937 rng(Seed);

    // One size_t for array size, another one for the parameter length
    MaxSize -= sizeof(std::size_t) * 2;

    // Resource and parameter size limits
    auto max_resource_size = 3 * MaxSize / 4;
    auto max_resource_string_size = 2 * MaxSize / 4;
    auto max_param_size = MaxSize / 4;

    auto [old_resource, param] = deserialize(Data, Size);

    // Compose the resource into a string
    std::string resource_str;
    for (const auto &arg : old_resource) {
        if (!resource_str.empty()) {
            resource_str.append(" ");
        }
        resource_str.append(arg);
    }

    // Ensure that the resource doesn't take more than half the remaining buffer
    // since the final mutated resource will have to be split into arrays elements
    // adding further overheads
    std::size_t resource_size = std::min(resource_str.size(), max_resource_string_size);
    resource_str.resize(max_resource_string_size);

    // Mutate
    auto new_size = LLVMFuzzerMutate(
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        reinterpret_cast<uint8_t *>(resource_str.data()), resource_size, resource_str.size());
    resource_str.resize(new_size);

    // Break down the resource into array elements
    std::size_t start = 0;
    std::size_t total_size = 0;
    std::vector<std::string> new_resource;
    for (std::size_t i = 0; i < resource_str.size(); ++i) {
        if (ddwaf::isspace(resource_str[i]) && start != i && static_cast<bool>(rng() % 2)) {
            new_resource.emplace_back(resource_str.substr(start, i - start));
            total_size += sizeof(std::size_t) + new_resource.back().size();
            start = i + 1;
        } else if ((i + 1) == resource_str.size()) {
            new_resource.emplace_back(resource_str.substr(start));
            total_size += sizeof(std::size_t) + new_resource.back().size();
        }

        if (total_size >= max_resource_size) {
            break;
        }
    }
    MaxSize -= total_size;

    std::size_t possible_param_size = std::min({MaxSize, max_param_size, resource_str.size()});
    auto param_idx = rng() % resource_str.size();
    auto param_size =
        1 + (rng() % std::min(possible_param_size, (resource_str.size() - param_idx)));

    auto param_buffer = resource_str.substr(param_idx, param_size);
    return serializer{Data}.serialize(new_resource, param_buffer);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size)
{
    cmdi_detector cond{{gen_param_def("server.sys.exec.cmd", "server.request.query")}};

    auto [resource, param] = deserialize(bytes, size);

    auto root = owned_object::make_map(0, ddwaf::memory::get_default_resource());
    root.emplace("server.request.query",
        owned_object::make_string(param, ddwaf::memory::get_default_resource()));

    auto array = root.emplace(
        "server.sys.exec.cmd", owned_object::make_array(0, ddwaf::memory::get_default_resource()));
    for (auto arg : resource) {
        array.emplace_back(owned_object::make_string(arg, ddwaf::memory::get_default_resource()));
    }

    object_store store;
    store.insert(std::move(root));

    ddwaf::timer deadline{2s};
    condition_cache cache;
    (void)cond.eval(cache, store, {}, {}, deadline);

    return 0;
}
