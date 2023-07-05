// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include "common/utils.hpp"
#include "../src/utils.hpp"
#include "ddwaf.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <stdexcept>
#include <type_traits>
#include <unordered_set>


template <typename E>
constexpr auto to_underlying(E e) noexcept
{
    return static_cast<std::underlying_type_t<E>>(e);
}


enum class Scalar { Unknown = 0, None = 1, Bool = 2, Int = 4, Str = 8, Float = 16 };

struct BaseContainer {
  std::size_t children{};
};

using Key = std::string;

struct Record: BaseContainer {};

struct Array: BaseContainer {};

using Node = std::variant<Scalar, Key, Record, Array>;

using Tree = std::vector<Node>;

template<>
struct std::hash<Tree>
{
    std::size_t operator()(Tree const& tree) const noexcept {
        return 0;
    }
};

template<>
struct std::equal_to<Tree>
{
    bool operator()(Tree const& lhs, Tree const &rhs) const noexcept {
        if (lhs.size() != rhs.size()) {
            return false;
        }
        for (std::size_t i = 0; i < lhs.size(); i++) {
            if (lhs[i].index() != rhs[i].index()) {
                return false;
            }
            switch (lhs[i].index()) {
            case 0:
                return std::get<Scalar>(lhs[i]) == std::get<Scalar>(rhs[i]);
            case 1:
                return std::get<Key>(lhs[i]) == std::get<Key>(rhs[i]);
            case 2:
                return std::get<Record>(lhs[i]).children == std::get<Record>(rhs[i]).children;
            case 3:
                return std::get<Array>(lhs[i]).children == std::get<Array>(rhs[i]).children;
            default:
            return false;
            }
        }
        return true;
    }
};

std::size_t serialize_schema(Tree &tree, std::size_t idx, rapidjson::Writer<rapidjson::StringBuffer> &writer) {
    auto &node = tree[idx];
    std::size_t read = 1;
    writer.StartArray();
    switch (node.index()) {
    case 0:
            writer.Uint(to_underlying(std::get<Scalar>(node)));
    break;
    case 1:
    throw std::logic_error("unexpected key");
    case 2: {
            writer.StartObject();
            while (read <= std::get<Record>(node).children) {
                writer.Key(std::get<Key>(tree[idx - read]));
                read += 1;
                read += serialize_schema(tree, idx - read, writer);
            }
            writer.EndObject();
        break;
    }
    case 3: {
            writer.StartArray();
            while (read <= std::get<Array>(node).children) {
                read += serialize_schema(tree, idx - read, writer);
            }
            writer.EndArray();
            break;
    }
    }
    writer.EndArray();
    return read;
}

std::size_t compute_schema(const ddwaf_object *node, Tree &tree)
{
    std::size_t added = 0;

    switch (node->type) {
        case DDWAF_OBJ_BOOL:
            tree.push_back(Scalar::Bool);
            added += 1;
        break;
        case DDWAF_OBJ_STRING:
            tree.push_back(Scalar::Str);
            added += 1;
        break;
        case DDWAF_OBJ_SIGNED:
        case DDWAF_OBJ_UNSIGNED:
            tree.push_back(Scalar::Int);
            added += 1;
        break;
        case DDWAF_OBJ_MAP: {
            std::size_t subadded = 0;
            for (std::size_t i = 0; i < node->nbEntries; i++) {
                subadded += 1 + compute_schema(&node->array[i], tree);
                tree.push_back(Key(node->array[i].parameterName, node->array[i].parameterNameLength));
            }
            tree.push_back(Record{subadded});
            added += 1 + subadded;
            break;
        }
        case DDWAF_OBJ_ARRAY: {
            std::unordered_set<Tree> children;
            for (std::size_t i = 0; i < node->nbEntries; i++) {
                Tree subtree;
                compute_schema(&node->array[i], subtree);
                children.insert(subtree);
            }
            std::for_each(children.cbegin(), children.cend(), [&](const Tree &subtree) {
                tree.insert(tree.end(), subtree.begin(), subtree.end());
                added += subtree.size();
            });
            tree.push_back(Array{added});
            added += 1;
            break;
        }
        default:
            tree.push_back(Scalar::Unknown);
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

    for (int i=1; i < argc; ++i) {
        std::cerr << "> " << argv[i] << "\n";
        std::string raw_payload = read_file(argv[i]);
        auto payload = YAML::Load(raw_payload).as<ddwaf_object>();

        Tree tree;

        std::size_t added = compute_schema(&payload, tree);

        std::cerr << "number of nodes: " << tree.size() << " added: " << added << '\n';

        rapidjson::StringBuffer s;
        rapidjson::Writer<rapidjson::StringBuffer> writer(s);

        try {
            serialize_schema(tree, tree.size() - 1, writer);
        } catch (std::exception& e)
        {
            std::cerr << "exception caught: " << e.what() << '\n';
        }

        std::cout << s.GetString() << '\n';

        ddwaf_object_free(&payload);
    }

    return EXIT_SUCCESS;
}
