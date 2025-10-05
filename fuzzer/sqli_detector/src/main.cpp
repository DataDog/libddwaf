// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>
#include <random>

#include "condition/sqli_detector.hpp"
#include "tokenizer/sql_base.hpp"

using namespace ddwaf;
using namespace std::literals;

ddwaf::sql_dialect dialect = ddwaf::sql_dialect::generic;

extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

extern "C" int LLVMFuzzerInitialize(const int *argc, char ***argv)
{
    ddwaf::memory::set_local_memory_resource(std::pmr::new_delete_resource());

    for (int i = 0; i < *argc; i++) {
        std::string_view arg = (*argv)[i];
        if (arg.starts_with("--dialect=")) {
            dialect = ddwaf::sql_dialect_from_type(arg.substr(sizeof("--dialect=") - 1));
            break;
        }
    }
    return 0;
}

template <typename... Args> std::vector<condition_parameter> gen_param_def(Args... addresses)
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

uint8_t *serialize_string(uint8_t *Data, std::string_view str)
{
    std::size_t size = str.size();
    memcpy(Data, reinterpret_cast<uint8_t *>(&size), sizeof(std::size_t));
    Data += sizeof(std::size_t);
    memcpy(Data, str.data(), size);
    Data += size;
    return Data;
}

std::size_t serialize(uint8_t *Data, std::string_view resource, std::string_view param)
{
    Data = serialize_string(Data, resource);
    serialize_string(Data, param);
    return sizeof(std::size_t) * 2 + resource.size() + param.size();
}
// NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)

// NOLINTNEXTLINE
extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t *Data, size_t Size, [[maybe_unused]] size_t MaxSize, [[maybe_unused]] unsigned int Seed)
{
    static thread_local std::random_device dev;
    static thread_local std::mt19937 rng(dev());

    auto [resource, param] = deserialize(Data, Size);
    MaxSize -= sizeof(std::size_t) * 2;

    std::string resource_buffer{resource.begin(), resource.end()};
    resource_buffer.resize(std::max(resource_buffer.size(), MaxSize / 2));

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto new_size = LLVMFuzzerMutate(reinterpret_cast<uint8_t *>(resource_buffer.data()),
        resource.size(), resource_buffer.size());
    resource_buffer.resize(new_size);

    auto param_idx = rng() % new_size;
    auto param_size = 1 + rng() % (new_size - param_idx);

    // std::cout << "max_size: " << MaxSize << ", new_size: " << new_size << ", idx: " << param_idx
    // << ", size: " << param_size << '\n';
    auto param_buffer = resource_buffer.substr(param_idx, param_size);
    return serialize(Data, resource_buffer, param_buffer);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size)
{
    sqli_detector cond{
        {gen_param_def("server.db.statement", "server.request.query", "server.db.statement")}};

    auto [resource, param] = deserialize(bytes, size);

    auto dialect_str = ddwaf::sql_dialect_to_string(dialect);

    auto root = owned_object::make_map();
    root.emplace("server.request.query", owned_object::make_string(param));
    root.emplace("server.db.system", owned_object::make_string(dialect_str));
    root.emplace("server.db.statement", owned_object::make_string(resource));

    object_store store;
    store.insert(std::move(root), evaluation_scope::context());

    ddwaf::timer deadline{2s};
    base_condition::cache_type cache;
    (void)cond.eval(cache, store, {}, {}, deadline);

    return 0;
}
