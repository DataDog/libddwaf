// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include "../src/utils.hpp"
#include "common/utils.hpp"
#include "ddwaf.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <algorithm>
#include <stdexcept>
#include <type_traits>
#include <unordered_set>

template <typename E> constexpr auto to_underlying(E e) noexcept
{
    return static_cast<std::underlying_type_t<E>>(e);
}

enum class Scalar { Unknown = 0, None = 1, Bool = 2, Int = 4, Str = 8, Float = 16 };

struct BaseContainer {
    std::size_t children{};
};

using Key = std::string;

struct Record : BaseContainer {};

struct Array : BaseContainer {};

struct Schema {
    using Node = std::variant<Scalar, Key, Record, Array>;
    using Store = std::vector<Node>;

    Schema() { store = std::make_shared<Store>(); }

    Schema(const Schema &tree, std::size_t n) : size_(tree.size_ - n), store(tree.store) {}

    [[nodiscard]] Schema advance(std::size_t n) const { return {*this, n}; }

    [[nodiscard]] Node &root() const { return store->at(size_ - 1); }

    void add(const Node &node)
    {
        store->push_back(node);
        size_ += 1;
    }

    void prune(std::ptrdiff_t n)
    {
        store->erase(store->end() - n, store->end());
        size_ -= n;
    }

    [[nodiscard]] std::size_t size(std::size_t acc = 0) const
    {
        if (size_ == 0) {
            return acc;
        }
        auto node = root();
        switch (node.index()) {
        case 0:
            return acc + 1;
        case 1:
            // key + value
            // should be tail recursive thanks to acc
            return advance(1).size(1 + acc);
        case 2:
            return acc + 1 + std::get<Record>(node).children;
        case 3:
            return acc + 1 + std::get<Array>(node).children;
        }
        return acc;
    }

    std::size_t fill_from(ddwaf_object const *obj);

    std::size_t serialize(rapidjson::Writer<rapidjson::StringBuffer> &writer) const;

    bool operator==(const Schema &other) const;

    std::size_t size_{};
    std::shared_ptr<Store> store;
};

template <> struct std::hash<Schema> {

    std::size_t operator()(Schema const &tree) const noexcept
    {
        if (tree.size_ == 0) {
            return 0;
        }
        auto node = tree.root();
        switch (node.index()) {
        case 0:
            return std::hash<Scalar>{}(std::get<Scalar>(node));
        case 1: {
            std::size_t h = std::hash<Key>{}(std::get<Key>(node));
            return h ^ (std::hash<Schema>{}(tree.advance(1)) << 1);
        }
        case 2: {
            std::size_t h = 42424242;
            std::size_t read = 1;
            while (read <= std::get<Record>(node).children) {
                Schema st = tree.advance(read);
                read += st.size();
                h ^= (std::hash<Schema>{}(st) << 1);
            }
            return h;
        }
        case 3: {
            std::size_t h = 89898989;
            std::size_t read = 1;
            while (read <= std::get<Array>(node).children) {
                Schema st = tree.advance(read);
                read += st.size();
                h ^= (std::hash<Schema>{}(st) << 1);
            }
            return h;
        }
        }
        return 0;
    }
};

bool Schema::operator==(const Schema &other) const
{
    if (size_ == 0 or other.size_ == 0) {
        return false;
    }
    auto na = root();
    auto nb = other.root();
    if (na.index() != nb.index()) {
        return false;
    }
    switch (na.index()) {
    case 0:
        return std::get<Scalar>(na) == std::get<Scalar>(nb);
    case 1:
        if (std::get<Key>(na) != std::get<Key>(nb)) {
            return false;
        }
        return advance(1) == other.advance(1);
    case 2: {
        std::unordered_set<Schema> ma;
        std::unordered_set<Schema> mb;
        std::size_t read = 1;
        while (read <= std::get<Record>(na).children) {
            Schema st = advance(read);
            read += st.size();
            ma.insert(st);
        }
        read = 1;
        while (read <= std::get<Record>(nb).children) {
            Schema st = advance(read);
            read += st.size();
            mb.insert(st);
        }
        return ma == mb;
    }
    case 3: {
        std::unordered_set<Schema> ma;
        std::unordered_set<Schema> mb;
        std::size_t read = 1;
        while (read <= std::get<Array>(na).children) {
            Schema st = advance(read);
            read += st.size();
            ma.insert(st);
        }
        read = 1;
        while (read <= std::get<Array>(nb).children) {
            Schema st = advance(read);
            read += st.size();
            mb.insert(st);
        }
        return ma == mb;
    }
    }
    return false;
}

std::size_t Schema::serialize(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    auto &node = root();
    std::size_t read = 1;
    switch (node.index()) {
    case 0:
        writer.StartArray();
        writer.Uint(to_underlying(std::get<Scalar>(node)));
        writer.EndArray();
        break;
    case 1:
        writer.Key(std::get<Key>(node));
        break;
    case 2:
        writer.StartArray();
        writer.StartObject();
        while (read <= std::get<Record>(node).children) {
            // key
            read += advance(read).serialize(writer);
            // value
            read += advance(read).serialize(writer);
        }
        writer.EndObject();
        writer.EndArray();
        break;
    case 3:
        writer.StartArray();
        writer.StartArray();
        while (read <= std::get<Array>(node).children) { read += advance(read).serialize(writer); }
        writer.EndArray();
        writer.EndArray();
        break;
    }
    return read;
}

std::size_t Schema::fill_from(const ddwaf_object *obj)
{
    std::size_t added = 0;

    switch (obj->type) {
    case DDWAF_OBJ_BOOL:
        add(Scalar::Bool);
        return 1;
    case DDWAF_OBJ_STRING:
        add(Scalar::Str);
        return 1;
    case DDWAF_OBJ_SIGNED:
    case DDWAF_OBJ_UNSIGNED:
        add(Scalar::Int);
        return 1;
    case DDWAF_OBJ_MAP:
        for (std::size_t i = 0; i < obj->nbEntries; i++) {
            added += 1 + fill_from(&obj->array[i]);
            add(Key(obj->array[i].parameterName, obj->array[i].parameterNameLength));
        }
        add(Record{added});
        return 1 + added;
    case DDWAF_OBJ_ARRAY: {
        std::unordered_set<Schema> children;
        for (std::size_t i = 0; i < obj->nbEntries; i++) {
            auto n = fill_from(&obj->array[i]);
            auto r = children.insert(*this);
            if (r.second) {
                added += n;
            } else {
                prune(n);
            }
        }
        add(Array{added});
        return 1 + added;
    }
    default:
        add(Scalar::Unknown);
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    ddwaf_set_log_cb(log_cb, DDWAF_LOG_OFF);
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [file ...]\n";
        return EXIT_FAILURE;
    }

    for (int i = 1; i < argc; ++i) {
        std::cerr << "> " << argv[i] << "\n";
        std::string raw_payload = read_file(argv[i]);
        auto payload = YAML::Load(raw_payload).as<ddwaf_object>();

        Schema s;

        std::size_t added = s.fill_from(&payload);

        std::cerr << "number of nodes: " << s.size() << " added: " << added << '\n';

        rapidjson::StringBuffer buf;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buf);

        s.serialize(writer);

        std::cout << buf.GetString() << '\n';

        ddwaf_object_free(&payload);
    }

    return EXIT_SUCCESS;
}
