// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "parameter.hpp"
#include "test.hpp"

using namespace ddwaf;

namespace {

TEST(TestParameter, ToBool)
{
    {
        ddwaf_object root;
        ddwaf_object_bool(&root, true);

        bool value = static_cast<bool>(parameter(root));
        EXPECT_TRUE(value);
    }

    {
        ddwaf_object root;
        ddwaf_object_bool(&root, false);

        bool value = static_cast<bool>(parameter(root));
        EXPECT_FALSE(value);
    }

    {
        ddwaf_object root;
        ddwaf_object_string(&root, "true");

        bool value = static_cast<bool>(parameter(root));
        EXPECT_TRUE(value);

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root;
        ddwaf_object_string(&root, "TrUe");

        bool value = static_cast<bool>(parameter(root));
        EXPECT_TRUE(value);

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root;
        ddwaf_object_string(&root, "false");

        bool value = static_cast<bool>(parameter(root));
        EXPECT_FALSE(value);

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root;
        ddwaf_object_string(&root, "FaLsE");

        bool value = static_cast<bool>(parameter(root));
        EXPECT_FALSE(value);

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root;
        ddwaf_object_map(&root);

        EXPECT_THROW((void)static_cast<bool>(ddwaf::parameter(root)), ddwaf::bad_cast);
    }
}

TEST(TestParameter, ToUint64)
{
    {
        ddwaf_object root;
        ddwaf_object_unsigned(&root, 2123);

        uint64_t value = static_cast<uint64_t>(parameter(root));
        EXPECT_EQ(value, 2123);
    }

    {
        ddwaf_object root;
        ddwaf_object_signed(&root, 2123);

        uint64_t value = static_cast<uint64_t>(parameter(root));
        EXPECT_EQ(value, 2123);
    }

    {
        ddwaf_object root;
        ddwaf_object_float(&root, 21.0);

        uint64_t value = static_cast<uint64_t>(parameter(root));
        EXPECT_EQ(value, 21);
    }

    {
        ddwaf_object root;
        ddwaf_object_float(&root, static_cast<double>(std::numeric_limits<uint64_t>::max() - 1024));

        uint64_t value = static_cast<uint64_t>(parameter(root));
        EXPECT_EQ(value, 18446744073709549568U);
    }

    {
        ddwaf_object root;
        ddwaf_object_string_from_unsigned(&root, 2123);

        uint64_t value = static_cast<uint64_t>(parameter(root));
        EXPECT_EQ(value, 2123);

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root;
        ddwaf_object_string(&root, "2123");

        uint64_t value = static_cast<uint64_t>(parameter(root));
        EXPECT_EQ(value, 2123);

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root;
        ddwaf_object_map(&root);

        EXPECT_THROW((void)static_cast<uint64_t>(ddwaf::parameter(root)), ddwaf::bad_cast);
    }

    {
        ddwaf_object root;
        ddwaf_object_signed(&root, -2123);

        EXPECT_THROW((void)static_cast<uint64_t>(ddwaf::parameter(root)), ddwaf::bad_cast);
    }

    {
        ddwaf_object root;
        ddwaf_object_float(&root, -21.0);

        EXPECT_THROW((void)static_cast<uint64_t>(ddwaf::parameter(root)), ddwaf::bad_cast);
    }

    {
        ddwaf_object root;
        ddwaf_object_float(&root, std::numeric_limits<double>::max());

        EXPECT_THROW((void)static_cast<uint64_t>(ddwaf::parameter(root)), ddwaf::bad_cast);
    }
}

TEST(TestParameter, ToInt64)
{
    {
        ddwaf_object root;
        ddwaf_object_signed(&root, -2123);

        int64_t value = static_cast<int64_t>(parameter(root));
        EXPECT_EQ(value, -2123);
    }

    {
        ddwaf_object root;
        ddwaf_object_unsigned(&root, 2123);

        int64_t value = static_cast<int64_t>(parameter(root));
        EXPECT_EQ(value, 2123);
    }

    {
        ddwaf_object root;
        ddwaf_object_float(&root, -21.0);

        int64_t value = static_cast<int64_t>(parameter(root));
        EXPECT_EQ(value, -21);
    }

    {
        ddwaf_object root;
        ddwaf_object_float(&root, static_cast<double>(std::numeric_limits<int64_t>::max() - 512));

        int64_t value = static_cast<int64_t>(parameter(root));
        EXPECT_EQ(value, 9223372036854774784);
    }

    {
        ddwaf_object root;
        ddwaf_object_string_from_signed(&root, -2123);

        int64_t value = static_cast<int64_t>(parameter(root));
        EXPECT_EQ(value, -2123);

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root;
        ddwaf_object_string(&root, "-2123");

        int64_t value = static_cast<int64_t>(parameter(root));
        EXPECT_EQ(value, -2123);

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root;
        ddwaf_object_map(&root);

        EXPECT_THROW((void)static_cast<int64_t>(ddwaf::parameter(root)), ddwaf::bad_cast);
    }

    {
        ddwaf_object root;
        ddwaf_object_unsigned(&root, std::numeric_limits<uint64_t>::max());

        EXPECT_THROW((void)static_cast<int64_t>(ddwaf::parameter(root)), ddwaf::bad_cast);
    }

    {
        ddwaf_object root;
        ddwaf_object_float(&root, std::numeric_limits<double>::max());

        EXPECT_THROW((void)static_cast<int64_t>(ddwaf::parameter(root)), ddwaf::bad_cast);
    }
}

TEST(TestParameter, ToFloat)
{
    {
        ddwaf_object root;
        ddwaf_object_float(&root, 21.23);

        double value = static_cast<double>(parameter(root));
        EXPECT_EQ(value, 21.23);
    }

    {
        ddwaf_object root;
        ddwaf_object_string(&root, "21.23");

        double value = static_cast<double>(parameter(root));
        EXPECT_EQ(value, 21.23);

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root;
        ddwaf_object_map(&root);

        EXPECT_THROW((void)static_cast<double>(ddwaf::parameter(root)), ddwaf::bad_cast);
    }
}

TEST(TestParameter, ToString)
{
    {
        ddwaf_object root;
        ddwaf_object_string(&root, "hello world, this is a string");

        auto value = static_cast<std::string>(ddwaf::parameter(root));
        EXPECT_STREQ(value.c_str(), "hello world, this is a string");

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root;
        ddwaf_object_array(&root);

        EXPECT_THROW((void)static_cast<std::string>(ddwaf::parameter(root)), ddwaf::bad_cast);
    }
}

TEST(TestParameter, ToStringView)
{
    {
        ddwaf_object root;
        ddwaf_object_string(&root, "hello world, this is a string");

        auto value = static_cast<std::string_view>(ddwaf::parameter(root));
        EXPECT_STREQ(value.data(), "hello world, this is a string");

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root;
        ddwaf_object_array(&root);

        EXPECT_THROW((void)static_cast<std::string_view>(ddwaf::parameter(root)), ddwaf::bad_cast);
    }
}

TEST(TestParameter, ToVector)
{
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_array(&root);

        for (unsigned i = 0; i < 20; i++) {
            ddwaf_object_array_add(&root, ddwaf_object_string(&tmp, std::to_string(i).c_str()));
        }

        auto vec_param = static_cast<parameter::vector>(ddwaf::parameter(root));
        EXPECT_EQ(vec_param.size(), 20);

        unsigned i = 0;
        for (auto &param : vec_param) {
            EXPECT_STREQ(param.stringValue, std::to_string(i++).c_str());
        }

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root;
        ddwaf_object_map(&root);

        ddwaf::parameter param = root;
        EXPECT_THROW(param.operator ddwaf::parameter::vector(), ddwaf::bad_cast);
    }
}

TEST(TestParameter, ToMap)
{
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);

        for (unsigned i = 0; i < 20; i++) {
            ddwaf_object_map_add(&root, std::to_string(i).c_str(),
                ddwaf_object_string(&tmp, std::to_string(i + 100).c_str()));
        }

        auto map_param = static_cast<parameter::map>(ddwaf::parameter(root));
        EXPECT_EQ(map_param.size(), 20);

        for (unsigned i = 0; i < 20; i++) {
            ddwaf::parameter &param = map_param[std::to_string(i)];
            EXPECT_STREQ(param.stringValue, std::to_string(100 + i).c_str());
        }

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root;
        ddwaf_object_array(&root);

        ddwaf::parameter param = root;
        EXPECT_THROW(param.operator ddwaf::parameter::map(), ddwaf::bad_cast);
    }
}

TEST(TestParameter, ToStringVector)
{
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_array(&root);

        for (unsigned i = 0; i < 20; i++) {
            ddwaf_object_array_add(&root, ddwaf_object_string(&tmp, std::to_string(i).c_str()));
        }

        auto vec_param = static_cast<std::vector<std::string>>(ddwaf::parameter(root));
        EXPECT_EQ(vec_param.size(), 20);

        unsigned i = 0;
        for (auto &param : vec_param) { EXPECT_STREQ(param.c_str(), std::to_string(i++).c_str()); }

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_array(&root);

        ddwaf_object_array_add(&root, ddwaf_object_map(&tmp));

        ddwaf::parameter param = root;
        EXPECT_THROW(param.operator std::vector<std::string>(), ddwaf::bad_cast);

        ddwaf_object_free(&root);
    }
    {
        ddwaf_object root;
        ddwaf_object_map(&root);

        ddwaf::parameter param = root;
        EXPECT_THROW(param.operator std::vector<std::string>(), ddwaf::bad_cast);
    }
}

TEST(TestParameter, ToStringViewVector)
{
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_array(&root);

        for (unsigned i = 0; i < 20; i++) {
            ddwaf_object_array_add(&root, ddwaf_object_string(&tmp, std::to_string(i).c_str()));
        }

        auto vec_param = static_cast<std::vector<std::string_view>>(ddwaf::parameter(root));
        EXPECT_EQ(vec_param.size(), 20);

        unsigned i = 0;
        for (auto &param : vec_param) { EXPECT_STREQ(param.data(), std::to_string(i++).c_str()); }

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_array(&root);

        ddwaf_object_array_add(&root, ddwaf_object_unsigned(&tmp, 50));

        ddwaf::parameter param = root;
        EXPECT_THROW(param.operator std::vector<std::string_view>(), ddwaf::malformed_object);

        ddwaf_object_free(&root);
    }
    {
        ddwaf_object root;
        ddwaf_object_map(&root);

        ddwaf::parameter param = root;
        EXPECT_THROW(param.operator std::vector<std::string_view>(), ddwaf::bad_cast);
    }
}

TEST(TestParameter, ToStringViewSet)
{
    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_array(&root);

        for (unsigned i = 0; i < 20; i++) {
            ddwaf_object_array_add(&root, ddwaf_object_string(&tmp, std::to_string(i).c_str()));
        }

        auto set_param = static_cast<parameter::string_set>(ddwaf::parameter(root));
        EXPECT_EQ(set_param.size(), 20);

        for (unsigned i = 0; i < 20; i++) {
            EXPECT_NE(set_param.find(std::to_string(i)), set_param.end());
        }

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_array(&root);

        ddwaf_object_array_add(&root, ddwaf_object_unsigned(&tmp, 50));

        ddwaf::parameter param = root;
        EXPECT_THROW(param.operator ddwaf::parameter::string_set(), ddwaf::malformed_object);

        ddwaf_object_free(&root);
    }
    {
        ddwaf_object root;
        ddwaf_object_map(&root);

        ddwaf::parameter param = root;
        EXPECT_THROW(param.operator ddwaf::parameter::string_set(), ddwaf::bad_cast);
    }
}

} // namespace
