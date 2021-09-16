// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "log.hpp"
#include "test.h"

const static char path_sep =
#ifdef _WIN32
    '\\';
#else
    '/';
#endif

int main(int argc, char* argv[])
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

size_t getFileSize(const char* filename)
{
    struct stat st;
    size_t output = 0;

    if (stat(filename, &st) == 0 && st.st_size > 0)
        output = (uint64_t) st.st_size;

    return output;
}

ddwaf_object readFile(const char* filename)
{
    auto fullFileName = string { "yaml" } + path_sep + filename;

    auto fileSize = getFileSize(fullFileName.c_str());
    if (fileSize == 0)
    {
        DDWAF_ERROR("No such file or size 0 (wrong dir?): %s", fullFileName.c_str());
        return DDWAF_OBJECT_INVALID;
    }

    char* buffer = (char*) malloc(fileSize + 1);
    if (buffer == nullptr)
        return DDWAF_OBJECT_INVALID;

    FILE* file = fopen(fullFileName.c_str(), "rb");
    if (file == nullptr)
    {
        DDWAF_ERROR("Failed opening for reading: %s", fullFileName.c_str());
        free(buffer);
        return DDWAF_OBJECT_INVALID;
    }

    if (fread((void*) buffer, fileSize, 1, file) != 1)
    {
        free(buffer);
        fclose(file);
        return DDWAF_OBJECT_INVALID;
    }

    fclose(file);
    buffer[fileSize] = 0;

    auto config = readRule(buffer);
    free(buffer);
    return config;
}

ddwaf_object readRule(const char* rule)
{
    YAML::Node doc = YAML::Load(rule);
    return doc.as<ddwaf_object>();
}

namespace YAML
{

class parsing_error : public std::exception
{
public:
    parsing_error(const std::string& what) : what_(what) {}
    const char* what() { return what_.c_str(); }

protected:
    const std::string what_;
};

ddwaf_object node_to_arg(const Node& node)
{
    switch (node.Type())
    {
        case NodeType::Sequence:
        {
            ddwaf_object arg = DDWAF_OBJECT_ARRAY;
            for (auto it = node.begin(); it != node.end(); ++it)
            {
                ddwaf_object child = node_to_arg(*it);
                ddwaf_object_array_add(&arg, &child);
            }
            return arg;
        }
        case NodeType::Map:
        {
            ddwaf_object arg = DDWAF_OBJECT_MAP;
            for (auto it = node.begin(); it != node.end(); ++it)
            {
                std::string key    = it->first.as<std::string>();
                ddwaf_object child = node_to_arg(it->second);
                ddwaf_object_map_addl(&arg, key.c_str(), key.size(), &child);
            }
            return arg;
        }
        case NodeType::Scalar:
        {
            const std::string& value = node.Scalar();
            ddwaf_object arg;
            ddwaf_object_stringl(&arg, value.c_str(), value.size());
            return arg;
        }
        case NodeType::Null:
            // Perhaps this should return an invalid pwarg
            break;
        case NodeType::Undefined:
            break;
    }

    throw parsing_error("Invalid YAML node type");
}

// template helpers
as_if<ddwaf_object, void>::as_if(const Node& node_) : node(node_) {}
ddwaf_object as_if<ddwaf_object, void>::operator()() const
{
    return node_to_arg(node);
}
}
