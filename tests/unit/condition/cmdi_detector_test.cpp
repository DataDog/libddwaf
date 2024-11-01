// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "condition/cmdi_detector.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

template <typename... Args> std::vector<condition_parameter> gen_param_def(Args... addresses)
{
    return {{{{std::string{addresses}, get_target_index(addresses)}}}...};
}

std::string generate_resource_string(const std::vector<std::string> &resource)
{
    std::string resource_str;
    for (const auto &arg : resource) {
        if (!resource_str.empty()) {
            resource_str.append(" \"");
            resource_str.append(arg);
            resource_str.append("\"");
        } else {
            resource_str.append(arg);
        }
    }
    return resource_str;
}

TEST(TestCmdiDetector, InvalidType)
{
    cmdi_detector cond{{gen_param_def("server.sys.exec.cmd", "server.request.query")}};

    ddwaf_object tmp;
    ddwaf_object root;

    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.sys.exec.cmd", ddwaf_object_map(&tmp));
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "whatever"));

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_FALSE(res.outcome);
}

TEST(TestCmdiDetector, EmptyResource)
{
    cmdi_detector cond{{gen_param_def("server.sys.exec.cmd", "server.request.query")}};

    ddwaf_object tmp;
    ddwaf_object root;

    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.sys.exec.cmd", ddwaf_object_array(&tmp));
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "whatever"));

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_FALSE(res.outcome);
}

TEST(TestCmdiDetector, ExecutableInjection)
{
    cmdi_detector cond{{gen_param_def("server.sys.exec.cmd", "server.request.query")}};

    std::vector<std::tuple<std::vector<std::string>, std::string, std::string>> samples{
        {{"ls", "-l", "/file/in/repository"}, "ls", "ls"},
        {{"   ls         ", "-l", "/file/in/repository"}, " ls          ", "ls"},
        {{"/usr/bin/reboot"}, "/usr/bin/reboot", "/usr/bin/reboot"},
        {{"/usr/bin/reboot", "-f"}, "/usr/bin/reboot", "/usr/bin/reboot"},
        {{" /usr/bin/reboot", "-f"}, "     /usr/bin/reboot        ", "/usr/bin/reboot"},
        {{"//usr//bin//reboot"}, "//usr//bin//reboot", "//usr//bin//reboot"},
        {{"   //usr//bin//reboot\t\n"}, "//usr//bin//reboot", "//usr//bin//reboot"},
        {{"//usr//bin//reboot", "-f"}, "//usr//bin//reboot", "//usr//bin//reboot"},
        {{R"(C:\\Temp\\script.ps1)"}, R"(C:\\Temp\\script.ps1)", R"(C:\\Temp\\script.ps1)"},
        {{R"(C:\Temp\script.ps1)"}, R"(C:\Temp\script.ps1)", R"(C:\Temp\script.ps1)"},
        {{"C:/bin/powershell.exe"}, "C:/bin/powershell.exe", "C:/bin/powershell.exe"},
    };

    for (const auto &[resource, param, expected] : samples) {
        ddwaf_object tmp;
        ddwaf_object root;
        ddwaf_object_map(&root);

        std::string resource_str = generate_resource_string(resource);
        ddwaf_object array;
        ddwaf_object_array(&array);
        for (const auto &arg : resource) {
            ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, arg.c_str()));
        }
        ddwaf_object_map_add(&root, "server.sys.exec.cmd", &array);

        ddwaf_object_map_add(
            &root, "server.request.query", ddwaf_object_string(&tmp, param.c_str()));

        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome) << param;
        EXPECT_FALSE(res.ephemeral);

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.sys.exec.cmd");
        EXPECT_STR(cache.match->args[0].resolved, resource_str.c_str());
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, expected.c_str());
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], expected.c_str());
    }
}

TEST(TestCmdiDetector, LinuxShellInjection)
{
    cmdi_detector cond{{gen_param_def("server.sys.exec.cmd", "server.request.query")}};

    std::vector<std::pair<std::vector<std::string>, std::string>> samples{
        {{"/usr/bin/sh", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/sh", "-ci", "ls -l"}, "ls -l"},
        {{"/usr/bin/sh", "-c", "-i", "ls -l"}, "ls -l"},
        {{"/usr/bin/bash", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/bash", "-ci", "ls -l"}, "ls -l"},
        {{"/usr/bin/bash", "-c", "-i", "ls -l"}, "ls -l"},
        {{"/usr/bin/ksh", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/ksh", "-ci", "ls -l"}, "ls -l"},
        {{"/usr/bin/ksh", "-c", "-i", "ls -l"}, "ls -l"},
        {{"/usr/bin/ksh", "ls -l"}, "ls -l"},
        {{"/usr/bin/rksh", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/rksh", "-ci", "ls -l"}, "ls -l"},
        {{"/usr/bin/rksh", "-c", "-i", "ls -l"}, "ls -l"},
        {{"/usr/bin/rksh", "ls -l"}, "ls -l"},
        {{"/usr/bin/fish", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/fish", "-ci", "ls -l"}, "ls -l"},
        {{"/usr/bin/fish", "-c", "-i", "ls -l"}, "ls -l"},
        {{"/usr/bin/zsh", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/zsh", "-ci", "ls -l"}, "ls -l"},
        {{"/usr/bin/zsh", "-c", "-i", "ls -l"}, "ls -l"},
        {{"/usr/bin/dash", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/dash", "-ci", "ls -l"}, "ls -l"},
        {{"/usr/bin/dash", "-c", "-i", "ls -l"}, "ls -l"},
        {{"/usr/bin/ash", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/ash", "-ci", "ls -l"}, "ls -l"},
        {{"/usr/bin/ash", "-c", "-i", "ls -l"}, "ls -l"},
    };

    for (const auto &[resource, param] : samples) {
        ddwaf_object tmp;
        ddwaf_object root;
        ddwaf_object_map(&root);

        std::string resource_str = generate_resource_string(resource);
        ddwaf_object array;
        ddwaf_object_array(&array);
        for (const auto &arg : resource) {
            ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, arg.c_str()));
        }
        ddwaf_object_map_add(&root, "server.sys.exec.cmd", &array);

        ddwaf_object_map_add(
            &root, "server.request.query", ddwaf_object_string(&tmp, param.c_str()));

        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome) << param;
        EXPECT_FALSE(res.ephemeral);

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.sys.exec.cmd");
        EXPECT_STR(cache.match->args[0].resolved, resource_str.c_str());
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, param.c_str());
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], param.c_str());
    }
}

TEST(TestCmdiDetector, WindowsShellInjection)
{
    cmdi_detector cond{{gen_param_def("server.sys.exec.cmd", "server.request.query")}};

    std::vector<std::pair<std::vector<std::string>, std::string>> samples{
        {{R"(C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe)", "-Command", "ls -l"},
            "ls -l"},
        {{R"(C:\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE)", "-Command", "ls -l"},
            "ls -l"},
        {{R"(C:/windows/system32/WindowsPowerShell/v1.0/powershell.exe)", "-Command", "ls -l"},
            "ls -l"},
        {{R"(C:/WINDOWS/SYSTEM32/WINDOWSPOWERSHELL/V1.0/POWERSHELL.EXE)", "-Command", "ls -l"},
            "ls -l"},
        {{R"(C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe)", "-Command", "ls -l"},
            "ls -l"},
        {{R"(C:\\WINDOWS\\SYSTEM32\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE)", "-Command", "ls -l"},
            "ls -l"},
        {{R"(C://windows//system32//WindowsPowerShell//v1.0//powershell.exe)", "-Command", "ls -l"},
            "ls -l"},
        {{R"(C://WINDOWS//SYSTEM32//WINDOWSPOWERSHELL//V1.0//POWERSHELL.EXE)", "-Command", "ls -l"},
            "ls -l"},
        {{R"(powershell.exe)", "-Command", "ls -l"}, "ls -l"},
        {{R"(POWERSHELL.EXE)", "-Command", "ls -l"}, "ls -l"},
        {{R"(powershell)", "-Command", "ls -l"}, "ls -l"},
        {{R"(POWERSHELL)", "-Command", "ls -l"}, "ls -l"},
    };

    for (const auto &[resource, param] : samples) {
        ddwaf_object tmp;
        ddwaf_object root;
        ddwaf_object_map(&root);

        std::string resource_str = generate_resource_string(resource);
        ddwaf_object array;
        ddwaf_object_array(&array);
        for (const auto &arg : resource) {
            ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, arg.c_str()));
        }
        ddwaf_object_map_add(&root, "server.sys.exec.cmd", &array);

        ddwaf_object_map_add(
            &root, "server.request.query", ddwaf_object_string(&tmp, param.c_str()));

        object_store store;
        store.insert(root);

        ddwaf::timer deadline{2s};
        condition_cache cache;
        auto res = cond.eval(cache, store, {}, {}, deadline);
        ASSERT_TRUE(res.outcome) << resource[0];
        EXPECT_FALSE(res.ephemeral);

        EXPECT_TRUE(cache.match);
        EXPECT_STRV(cache.match->args[0].address, "server.sys.exec.cmd");
        EXPECT_STR(cache.match->args[0].resolved, resource_str.c_str());
        EXPECT_TRUE(cache.match->args[0].key_path.empty());

        EXPECT_STRV(cache.match->args[1].address, "server.request.query");
        EXPECT_STR(cache.match->args[1].resolved, param.c_str());
        EXPECT_TRUE(cache.match->args[1].key_path.empty());

        EXPECT_STR(cache.match->highlights[0], param.c_str());
    }
}

} // namespace
