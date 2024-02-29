// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>

#include "condition/ssrf_detector.hpp"

using namespace ddwaf;
using namespace std::literals;

extern "C" size_t
LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

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
std::pair<std::string, std::string> deserialize(const uint8_t *data, size_t size)
{
    if (size < sizeof(std::size_t)) { return {}; }

    const auto resource_size = *reinterpret_cast<const std::size_t*>(data);
    data += sizeof(std::size_t);
    size -= sizeof(std::size_t);

    if (size < resource_size) { return {}; }

    std::string resource{reinterpret_cast<const char *>(data), resource_size};
    data += resource_size;
    size -= resource_size;

    if (size < sizeof(std::size_t)) { return {}; }

    const auto param_size = *reinterpret_cast<const std::size_t*>(data);
    data += sizeof(std::size_t);
    size -= sizeof(std::size_t);

    if (size < param_size) { return {}; }

    std::string param{reinterpret_cast<const char *>(data), param_size};

    return {resource, param};
}

uint8_t *serialize_string(uint8_t *Data, const std::string &str)
{
    std::size_t size = str.size();
    memcpy(Data, reinterpret_cast<uint8_t*>(&size), sizeof(std::size_t));
    Data += sizeof(std::size_t);
    memcpy(Data, str.c_str(), size);
    Data += size;
    return Data;
}

void serialize(uint8_t *Data, const std::string &resource, const std::string &param)
{
    Data = serialize_string(Data, resource);
    serialize_string(Data, param);
}
// NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)

// NOLINTNEXTLINE
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
    [[maybe_unused]] size_t MaxSize, [[maybe_unused]] unsigned int Seed) 
{
    auto [resource, param] = deserialize(Data, Size);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto new_size = LLVMFuzzerMutate(reinterpret_cast<uint8_t *>(resource.data()),
            resource.size(), resource.size());
    resource.resize(new_size);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    new_size = LLVMFuzzerMutate(reinterpret_cast<uint8_t *>(param.data()),
            param.size(), param.size());
    param.resize(new_size);

    serialize(Data, resource, param);

    return Size;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size)
{
    ssrf_detector cond{{gen_param_def("server.io.net.url", "server.request.query")}};

    auto [resource, param] = deserialize(bytes, size);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.io.net.url",
            ddwaf_object_string(&tmp, resource.c_str()));
    ddwaf_object_map_add(&root, "server.request.query", 
            ddwaf_object_string(&tmp, param.c_str()));

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    (void)cond.eval(cache, store, {}, {}, deadline);

    return 0;
}
