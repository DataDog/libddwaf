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

struct Tree {
    using Node = std::variant<Scalar, Key, Record, Array>;
    using Store = std::vector<Node>;

    Tree() { store = std::make_shared<Store>(); }

    Tree(const Tree &tree, std::size_t n) : size_(tree.size_ - n), store(tree.store) {}

    [[nodiscard]] Tree advance(std::size_t n) const { return {*this, n}; }

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

    bool operator==(const Tree &other) const;

    std::size_t size_{};
    std::shared_ptr<Store> store;
};

template <> struct std::hash<Tree> {

    std::size_t operator()(Tree const &tree) const noexcept
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
            return h ^ (std::hash<Tree>{}(tree.advance(1)) << 1);
        }
        case 2: {
            std::size_t h = 42424242;
            std::size_t read = 1;
            while (read <= std::get<Record>(node).children) {
                Tree st = tree.advance(read);
                read += st.size();
                h ^= (std::hash<Tree>{}(st) << 1);
            }
            return h;
        }
        case 3: {
            std::size_t h = 89898989;
            std::size_t read = 1;
            while (read <= std::get<Array>(node).children) {
                Tree st = tree.advance(read);
                read += st.size();
                h ^= (std::hash<Tree>{}(st) << 1);
            }
            return h;
        }
        }
        return 0;
    }
};

bool Tree::operator==(const Tree &other) const
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
        std::unordered_set<Tree> ma;
        std::unordered_set<Tree> mb;
        std::size_t read = 1;
        while (read <= std::get<Record>(na).children) {
            Tree st = advance(read);
            read += st.size();
            ma.insert(st);
        }
        read = 1;
        while (read <= std::get<Record>(nb).children) {
            Tree st = advance(read);
            read += st.size();
            mb.insert(st);
        }
        return ma == mb;
    }
    case 3: {
        std::unordered_set<Tree> ma;
        std::unordered_set<Tree> mb;
        std::size_t read = 1;
        while (read <= std::get<Array>(na).children) {
            Tree st = advance(read);
            read += st.size();
            ma.insert(st);
        }
        read = 1;
        while (read <= std::get<Array>(nb).children) {
            Tree st = advance(read);
            read += st.size();
            mb.insert(st);
        }
        return ma == mb;
    }
    }
    return false;
}

std::size_t serialize_schema(Tree &tree, rapidjson::Writer<rapidjson::StringBuffer> &writer)
{
    auto &node = tree.root();
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
    case 2: {
        writer.StartArray();
        writer.StartObject();
        while (read <= std::get<Record>(node).children) {
            auto st = tree.advance(read);
            read += serialize_schema(st, writer);
            st = tree.advance(read);
            read += serialize_schema(st, writer);
        }
        writer.EndObject();
        writer.EndArray();
        break;
    }
    case 3: {
        writer.StartArray();
        writer.StartArray();
        while (read <= std::get<Array>(node).children) {
            auto st = tree.advance(read);
            read += serialize_schema(st, writer);
        }
        writer.EndArray();
        writer.EndArray();
        break;
    }
    }
    return read;
}

std::size_t compute_schema(const ddwaf_object *node, Tree &tree)
{
    std::size_t added = 0;

    switch (node->type) {
    case DDWAF_OBJ_BOOL:
        tree.add(Scalar::Bool);
        added += 1;
        break;
    case DDWAF_OBJ_STRING:
        tree.add(Scalar::Str);
        added += 1;
        break;
    case DDWAF_OBJ_SIGNED:
    case DDWAF_OBJ_UNSIGNED:
        tree.add(Scalar::Int);
        added += 1;
        break;
    case DDWAF_OBJ_MAP: {
        for (std::size_t i = 0; i < node->nbEntries; i++) {
            added += 1 + compute_schema(&node->array[i], tree);
            tree.add(Key(node->array[i].parameterName, node->array[i].parameterNameLength));
        }
        tree.add(Record{added});
        added += 1;
        break;
    }
    case DDWAF_OBJ_ARRAY: {
        std::unordered_set<Tree> children;
        for (std::size_t i = 0; i < node->nbEntries; i++) {
            auto n = compute_schema(&node->array[i], tree);
            auto r = children.insert(tree);
            if (r.second) {
                added += n;
            } else {
                tree.prune(n);
            }
        }
        tree.add(Array{added});
        added += 1;
        break;
    }
    default:
        tree.add(Scalar::Unknown);
        added += 1;
        break;
    }
    return added;
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

        Tree tree;

        std::size_t added = compute_schema(&payload, tree);

        std::cerr << "number of nodes: " << tree.size() << " added: " << added << '\n';

        rapidjson::StringBuffer s;
        rapidjson::Writer<rapidjson::StringBuffer> writer(s);

        serialize_schema(tree, writer);

        std::cout << s.GetString() << '\n';

        ddwaf_object_free(&payload);
    }

    return EXIT_SUCCESS;
}
