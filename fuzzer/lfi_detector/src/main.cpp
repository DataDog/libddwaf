// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>

#include "condition/lfi_detector.hpp"

using namespace ddwaf;
using namespace std::literals;

extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

extern "C" int LLVMFuzzerInitialize(const int * /*argc*/, char *** /*argv*/)
{
    ddwaf::memory::set_local_memory_resource(std::pmr::new_delete_resource());
    return 0;
}

template <typename... Args> std::vector<parameter_definition> gen_param_def(Args... addresses)
{
    return {{{{std::string{addresses}, get_target_index(addresses)}}}...};
}

// NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
std::pair<std::string_view, std::string_view> deserialize(const uint8_t *data, size_t size)
{
    if (size < sizeof(std::size_t)) {
        return {};
    }

    const auto resource_size = *reinterpret_cast<const std::size_t *>(data);
    data += sizeof(std::size_t);
    size -= sizeof(std::size_t);

    if (size < resource_size) {
        return {};
    }

    std::string_view resource{reinterpret_cast<const char *>(data), resource_size};
    data += resource_size;
    size -= resource_size;

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

    return {resource, param};
}

uint8_t *serialize_string(uint8_t *Data, const std::vector<char> &str)
{
    std::size_t size = str.size();
    memcpy(Data, reinterpret_cast<uint8_t *>(&size), sizeof(std::size_t));
    Data += sizeof(std::size_t);
    memcpy(Data, str.data(), size);
    Data += size;
    return Data;
}

void serialize(uint8_t *Data, const std::vector<char> &resource, const std::vector<char> &param)
{
    Data = serialize_string(Data, resource);
    serialize_string(Data, param);
}
// NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)

// NOLINTNEXTLINE
extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t *Data, size_t Size, [[maybe_unused]] size_t MaxSize, [[maybe_unused]] unsigned int Seed)
{
    auto [resource, param] = deserialize(Data, Size);

    MaxSize -= sizeof(std::size_t) * 2;

    std::vector<char> resource_buffer{resource.begin(), resource.end()};
    resource_buffer.resize(resource_buffer.size() + MaxSize / 2);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto new_size = LLVMFuzzerMutate(reinterpret_cast<uint8_t *>(resource_buffer.data()),
        resource.size(), resource_buffer.size());
    resource_buffer.resize(new_size);

    std::vector<char> param_buffer{resource.begin(), resource.end()};
    param_buffer.resize(resource_buffer.size() + MaxSize / 2);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    new_size = LLVMFuzzerMutate(
        reinterpret_cast<uint8_t *>(param_buffer.data()), resource.size(), resource_buffer.size());
    param_buffer.resize(new_size);

    serialize(Data, resource_buffer, param_buffer);

    return Size;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    auto [resource, param] = deserialize(bytes, size);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(
        &root, "server.io.fs.file", ddwaf_object_stringl(&tmp, resource.data(), resource.size()));
    ddwaf_object_map_add(
        &root, "server.request.query", ddwaf_object_stringl(&tmp, param.data(), param.size()));

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    (void)cond.eval(cache, store, {}, {}, deadline);

    return 0;
}
