// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "configuration/common/parser_exception.hpp"
#include "configuration/common/raw_configuration.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestParameter, ToBool)
{
    {
        owned_object root{true};

        bool value = static_cast<bool>(raw_configuration(root));
        EXPECT_TRUE(value);
    }

    {
        owned_object root{false};

        bool value = static_cast<bool>(raw_configuration(root));
        EXPECT_FALSE(value);
    }

    {
        owned_object root{"true"};

        bool value = static_cast<bool>(raw_configuration(root));
        EXPECT_TRUE(value);
    }

    {
        owned_object root{"TrUe"};

        bool value = static_cast<bool>(raw_configuration(root));
        EXPECT_TRUE(value);
    }

    {
        owned_object root{"false"};

        bool value = static_cast<bool>(raw_configuration(root));
        EXPECT_FALSE(value);
    }

    {
        owned_object root{"FaLsE"};

        bool value = static_cast<bool>(raw_configuration(root));
        EXPECT_FALSE(value);
    }

    {
        auto root = owned_object::make_map();
        EXPECT_THROW((void)static_cast<bool>(raw_configuration(root)), bad_cast);
    }
}

TEST(TestParameter, ToUint64)
{
    {
        owned_object root{2123};

        uint64_t value = static_cast<uint64_t>(raw_configuration(root));
        EXPECT_EQ(value, 2123);
    }

    {
        owned_object root{2123};

        uint64_t value = static_cast<uint64_t>(raw_configuration(root));
        EXPECT_EQ(value, 2123);
    }

    {
        owned_object root{21.0};

        uint64_t value = static_cast<uint64_t>(raw_configuration(root));
        EXPECT_EQ(value, 21);
    }

    {
        owned_object root{static_cast<double>(std::numeric_limits<uint64_t>::max() - 1024)};

        uint64_t value = static_cast<uint64_t>(raw_configuration(root));
        EXPECT_EQ(value, 18446744073709549568U);
    }

    {
        owned_object root{"2123"};

        uint64_t value = static_cast<uint64_t>(raw_configuration(root));
        EXPECT_EQ(value, 2123);
    }

    {
        auto root = owned_object::make_map();

        EXPECT_THROW((void)static_cast<uint64_t>(raw_configuration(root)), bad_cast);
    }

    {
        owned_object root{-2123};

        EXPECT_THROW((void)static_cast<uint64_t>(raw_configuration(root)), bad_cast);
    }

    {
        owned_object root{-21.0};

        EXPECT_THROW((void)static_cast<uint64_t>(raw_configuration(root)), bad_cast);
    }

    {
        owned_object root{std::numeric_limits<double>::max()};

        EXPECT_THROW((void)static_cast<uint64_t>(raw_configuration(root)), bad_cast);
    }
}

TEST(TestParameter, ToInt64)
{
    {
        owned_object root{-2123};

        int64_t value = static_cast<int64_t>(raw_configuration(root));
        EXPECT_EQ(value, -2123);
    }

    {
        owned_object root{2123};

        int64_t value = static_cast<int64_t>(raw_configuration(root));
        EXPECT_EQ(value, 2123);
    }

    {
        owned_object root{-21.0};

        int64_t value = static_cast<int64_t>(raw_configuration(root));
        EXPECT_EQ(value, -21);
    }

    {
        owned_object root{static_cast<double>(std::numeric_limits<int64_t>::max() - 512)};

        int64_t value = static_cast<int64_t>(raw_configuration(root));
        EXPECT_EQ(value, 9223372036854774784);
    }

    {
        owned_object root{"-2123"};

        int64_t value = static_cast<int64_t>(raw_configuration(root));
        EXPECT_EQ(value, -2123);
    }

    {
        auto root = owned_object::make_map();

        EXPECT_THROW((void)static_cast<int64_t>(raw_configuration(root)), bad_cast);
    }

    {
        owned_object root{std::numeric_limits<uint64_t>::max()};

        EXPECT_THROW((void)static_cast<int64_t>(raw_configuration(root)), bad_cast);
    }

    {
        owned_object root{std::numeric_limits<double>::max()};

        EXPECT_THROW((void)static_cast<int64_t>(raw_configuration(root)), bad_cast);
    }
}

TEST(TestParameter, ToFloat)
{
    {
        owned_object root{21.23};

        double value = static_cast<double>(raw_configuration(root));
        EXPECT_EQ(value, 21.23);
    }

    {
        owned_object root{"21.23"};

        double value = static_cast<double>(raw_configuration(root));
        EXPECT_EQ(value, 21.23);
    }

    {
        auto root = owned_object::make_map();

        EXPECT_THROW((void)static_cast<double>(raw_configuration(root)), bad_cast);
    }
}

TEST(TestParameter, ToString)
{
    {
        owned_object root{"hello world, this is a string"};

        auto value = static_cast<std::string>(raw_configuration(root));
        EXPECT_STREQ(value.c_str(), "hello world, this is a string");
    }

    {
        auto root = owned_object::make_array();

        EXPECT_THROW((void)static_cast<std::string>(raw_configuration(root)), bad_cast);
    }
}

TEST(TestParameter, ToStringView)
{
    {
        owned_object root{"hello world, this is a string"};

        auto value = static_cast<std::string_view>(raw_configuration(root));
        EXPECT_STRV(value, "hello world, this is a string");
    }

    {
        auto root = owned_object::make_array();

        EXPECT_THROW((void)static_cast<std::string_view>(raw_configuration(root)), bad_cast);
    }
}

TEST(TestParameter, ToVector)
{
    {
        auto root = owned_object::make_array();
        for (unsigned i = 0; i < 20; i++) { root.emplace_back(std::to_string(i)); }

        auto vec_param = static_cast<raw_configuration::vector>(raw_configuration(root));
        EXPECT_EQ(vec_param.size(), 20);

        unsigned i = 0;
        for (auto &param : vec_param) {
            auto obtained = static_cast<std::string>(param);
            auto expected = std::to_string(i++);
            EXPECT_TRUE(obtained == expected);
        }
    }

    {
        auto root = owned_object::make_map();

        raw_configuration param{root};
        EXPECT_THROW(param.operator raw_configuration::vector(), bad_cast);
    }
}

TEST(TestParameter, ToMap)
{
    {
        auto root = owned_object::make_map();

        for (unsigned i = 0; i < 20; i++) {
            root.emplace(std::to_string(i), std::to_string(i + 100));
        }

        auto map_param = static_cast<raw_configuration::map>(raw_configuration(root));
        EXPECT_EQ(map_param.size(), 20);

        for (unsigned i = 0; i < 20; i++) {
            auto key = std::to_string(i);
            raw_configuration &param = map_param[key];
            EXPECT_TRUE(static_cast<std::string>(param) == std::to_string(100 + i));
        }
    }

    {
        auto root = owned_object::make_array();

        raw_configuration param{root};
        EXPECT_THROW(param.operator raw_configuration::map(), bad_cast);
    }
}

TEST(TestParameter, ToStringVector)
{
    {
        auto root = owned_object::make_array();
        for (unsigned i = 0; i < 20; i++) { root.emplace_back(std::to_string(i)); }

        auto vec_param = static_cast<std::vector<std::string>>(raw_configuration(root));
        EXPECT_EQ(vec_param.size(), 20);

        unsigned i = 0;
        for (auto &param : vec_param) { EXPECT_STR(param, std::to_string(i++)); }
    }

    {
        auto root = owned_object::make_array();
        root.emplace_back(owned_object::make_map());

        raw_configuration param{root};
        EXPECT_THROW(param.operator std::vector<std::string>(), bad_cast);
    }
    {
        auto root = owned_object::make_map();
        raw_configuration param{root};
        EXPECT_THROW(param.operator std::vector<std::string>(), bad_cast);
    }
}

TEST(TestParameter, ToStringViewVector)
{
    {
        auto root = owned_object::make_array();
        for (unsigned i = 0; i < 20; i++) { root.emplace_back(std::to_string(i)); }

        auto vec_param = static_cast<std::vector<std::string_view>>(raw_configuration(root));
        EXPECT_EQ(vec_param.size(), 20);

        unsigned i = 0;
        for (auto &param : vec_param) {
            EXPECT_STR(static_cast<std::string>(param), std::to_string(i++));
        }
    }

    {
        auto root = owned_object::make_array();
        root.emplace_back(50);

        raw_configuration param{root};
        EXPECT_THROW(param.operator std::vector<std::string_view>(), malformed_object);
    }
    {
        auto root = owned_object::make_map();

        raw_configuration param{root};
        EXPECT_THROW(param.operator std::vector<std::string_view>(), bad_cast);
    }
}

TEST(TestParameter, ToStringViewSet)
{
    {
        auto root = owned_object::make_array();
        for (unsigned i = 0; i < 20; i++) { root.emplace_back(std::to_string(i)); }

        auto set_param = static_cast<raw_configuration::string_set>(raw_configuration(root));
        EXPECT_EQ(set_param.size(), 20);

        for (unsigned i = 0; i < 20; i++) {
            EXPECT_NE(set_param.find(std::to_string(i)), set_param.end());
        }
    }

    {
        auto root = owned_object::make_array();
        root.emplace_back(50);

        raw_configuration param{root};
        EXPECT_THROW(param.operator raw_configuration::string_set(), malformed_object);
    }
    {
        auto root = owned_object::make_map();

        raw_configuration param{root};
        EXPECT_THROW(param.operator raw_configuration::string_set(), bad_cast);
    }
}

TEST(TestParameter, ToKeyPathVectorEmpty)
{
    auto root = owned_object::make_array();
    auto vec =
        static_cast<std::vector<std::variant<std::string, int64_t>>>(raw_configuration(root));
    EXPECT_TRUE(vec.empty());
}

TEST(TestParameter, ToSemanticVersion)
{
    {
        owned_object root{"1.2.3"};

        auto value = static_cast<semantic_version>(raw_configuration(root));
        EXPECT_EQ(value.number(), 1002003);
    }

    {
        owned_object root{3};

        raw_configuration param{root};
        EXPECT_THROW(param.operator semantic_version(), bad_cast);
    }

    {
        auto root = owned_object::make_string_nocopy(nullptr, 0);

        raw_configuration param{root};
        EXPECT_THROW(param.operator semantic_version(), std::invalid_argument);
    }
}

} // namespace
