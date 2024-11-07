// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "condition/cmdi_detector.hpp"
#include "platform.hpp"

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

TEST(TestCmdiDetector, NoExecutableInjection)
{
    cmdi_detector cond{{gen_param_def("server.sys.exec.cmd", "server.request.query")}};

    std::vector<std::pair<std::vector<std::string>, std::string>> samples{
        {{"ls", "-l", "/file/in/repository"}, "/usr/bin/ls"},
        {{"/usr/bin/reboot"}, "reboot"},
        {{"/usr/bin/reboot", "-f"}, "unrelated.exe"},
        {{"/usr/bin/reboot", "-f"}, "/bin/unrelated.exe"},
        {{"/usr/bin/reboot", "-f"}, "/usr"},
        {{"/usr/bin/reboot", "-f"}, "usr"},
        {{"/usr/bin/reboot", "-f"}, "-f"},
        {{"//usr//bin//reboot"}, "usr//bin//reboot"},
        {{"//usr//bin//reboot", "-f"}, "//usr//bin//eboot"},
        {{R"(C:\\Temp\\script.ps1)"}, R"(C:\\Temp\script.ps1)"},
        {{R"(C:\Temp\script.ps1)"}, R"(C:\Temp\script.ps)"},
        {{"C:/bin/powershell.exe"}, ":/bin/powershell.exe"},
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
        ASSERT_FALSE(res.outcome) << param;
        EXPECT_FALSE(res.ephemeral);
    }
}

TEST(TestCmdiDetector, NoShellInjection)
{
    cmdi_detector cond{{gen_param_def("server.sys.exec.cmd", "server.request.query")}};

    std::vector<std::pair<std::vector<std::string>, std::string>> samples{
        {{"C:/bin/powershell.exe", "-Command", "ls -l $file ; cat /etc/passwd"}, "-l $file"},
        {{"/usr/bin/ash", "-c", "ls -l $file ; cat /etc/passwd"}, "cat"},
        {{"/usr/bin/ash", "-c", "ls -l ; $(cat $file)"}, "-l"},
        {{"/usr/bin/ash", "-c", "\n -l ; $(cat $file)"}, "\n"},
        {{"/usr/bin/psh", "-c", "ls -l ; $(cat $file)"}, "ls -l"},
        {{"/usr/bin/bash", "-Command", "\"ls -l ; $(cat $file)\""}, "ls -l"},
        {{"/usr/bin/ksh", "getconf PAGESIZE"}, "get"},
        {{"/usr/bin/rksh", "cat hello"}, "hello"},
        {{"bash", "-c",
             "file -b --mime '/tmp/ForumEntr-avec "
             "kedge20160204-37527-ctbhbi20160204-37527-tuzome.png'"},
            "file"},
        {{"bash", "file -b --mime '/tmp/ForumEntr-avec "
                  "kedge20160204-37527-ctbhbi20160204-37527-tuzome.png'"},
            "file -b --mime"},
        {{"/bin/sh", "file -b --mime '/tmp/ForumEntr-avec "
                     "kedge20160204-37527-ctbhbi20160204-37527-tuzome.png'"},
            "file -e"},
        {{"dash", "echo hello"}, "b"},
        {{"/bin/zsh", "phantomjs /vendor/assets/javascripts/highcharts/highcharts-convert.js "
                      "-infile /app/tmp/highcharts/json/input.json -outfile "
                      "/app/tmp/highcharts/png/survey_641_chart.png -width 700 2>&1"},
            "641"},
        {{"/sh", "/usr/bin/generate.sh --margin-bottom 20mm --margin-top 27mm --print-media-type "
                 "--header-html https://url/blabla-bla --footer-html https://url/blabla-bla "
                 "https://url/blabla-bla -"},
            "blabla-bla"},
        {{"/bin/fish", "ls -l -r -t"}, "-r -t"},
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
        ASSERT_FALSE(res.outcome) << resource_str;
        EXPECT_FALSE(res.ephemeral);
    }
}

TEST(TestCmdiDetector, ExecutableInjection)
{
    cmdi_detector cond{{gen_param_def("server.sys.exec.cmd", "server.request.query")}};

    std::vector<std::tuple<std::vector<std::string>, std::string, std::string>> samples{
        {{"ls", "-l", "/file/in/repository"}, "ls", "ls"},
        {{"/usr/bin/reboot"}, "/usr/bin/reboot", "/usr/bin/reboot"},
        {{"/usr/bin/reboot", "-f"}, "/usr/bin/reboot", "/usr/bin/reboot"},
        {{"//usr//bin//reboot"}, "//usr//bin//reboot", "//usr//bin//reboot"},
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

TEST(TestCmdiDetector, ExecutableWithSpacesInjection)
{
    cmdi_detector cond{{gen_param_def("server.sys.exec.cmd", "server.request.query")}};

    std::vector<std::tuple<std::vector<std::string>, std::string, std::string>> samples{
        {{"   ls         ", "-l", "/file/in/repository"}, " ls ", "ls"},
        {{"  ls\n", "-l", "/file/in/repository"}, " ls\n", "ls"},
        {{"\tls\n", "-l", "/file/in/repository"}, "ls", "ls"},
        {{"ls", "-l", "/file/in/repository"}, "\t   ls   \n", "ls"},
        {{"   //usr//bin//reboot\t\n"}, "//usr//bin//reboot", "//usr//bin//reboot"},
        {{" /usr/bin/reboot", "-f"}, "     /usr/bin/reboot        ", "/usr/bin/reboot"},
        {{" /usr/bin/reboot\v", "-f"}, "     /usr/bin/reboot        ", "/usr/bin/reboot"},
        {{"\r \r /usr/bin/reboot\v", "-f"}, "\v \n  /usr/bin/reboot        ", "/usr/bin/reboot"},
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
    system_platform_override spo{platform::linux};

    cmdi_detector cond{{gen_param_def("server.sys.exec.cmd", "server.request.query")}};

    std::vector<std::pair<std::vector<std::string>, std::string>> samples{
        {{"sh", "-c", "ls -l"}, "ls -l"},
        {{"/sh", "-c", "ls -l"}, "ls -l"},
        {{"/bin/sh", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/sh", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/sh", "-ci", "ls -l"}, "ls -l"},
        {{"/usr/bin/sh", "-ic", "ls -l"}, "ls -l"},
        {{"/usr/bin/sh", "-c", "-i", "ls -l"}, "ls -l"},

        {{"bash", "-c", "ls -l"}, "ls -l"},
        {{"/bash", "-c", "ls -l"}, "ls -l"},
        {{"/bin/bash", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/bash", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/bash", "-ci", "ls -l"}, "ls -l"},
        {{"/usr/bin/bash", "-ic", "ls -l"}, "ls -l"},
        {{"/usr/bin/bash", "-c", "-i", "ls -l"}, "ls -l"},

        {{"ksh", "-c", "ls -l"}, "ls -l"},
        {{"/ksh", "-c", "ls -l"}, "ls -l"},
        {{"/bin/ksh", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/ksh", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/ksh", "-ci", "ls -l"}, "ls -l"},
        {{"/usr/bin/ksh", "-ic", "ls -l"}, "ls -l"},
        {{"/usr/bin/ksh", "-c", "-i", "ls -l"}, "ls -l"},
        {{"/usr/bin/ksh", "ls -l"}, "ls -l"},

        {{"rksh", "-c", "ls -l"}, "ls -l"},
        {{"/rksh", "-c", "ls -l"}, "ls -l"},
        {{"/bin/rksh", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/rksh", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/rksh", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/rksh", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/rksh", "-ci", "ls -l"}, "ls -l"},
        {{"/usr/bin/rksh", "-ic", "ls -l"}, "ls -l"},
        {{"/usr/bin/rksh", "-c", "-i", "ls -l"}, "ls -l"},
        {{"/usr/bin/rksh", "ls -l"}, "ls -l"},

        {{"fish", "-c", "ls -l"}, "ls -l"},
        {{"/fish", "-c", "ls -l"}, "ls -l"},
        {{"/bin/fish", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/fish", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/fish", "-ci", "ls -l"}, "ls -l"},
        {{"/usr/bin/fish", "-ic", "ls -l"}, "ls -l"},
        {{"/usr/bin/fish", "-c", "-i", "ls -l"}, "ls -l"},

        {{"zsh", "-c", "ls -l"}, "ls -l"},
        {{"/zsh", "-c", "ls -l"}, "ls -l"},
        {{"/bin/zsh", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/zsh", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/zsh", "-ci", "ls -l"}, "ls -l"},
        {{"/usr/bin/zsh", "-ic", "ls -l"}, "ls -l"},
        {{"/usr/bin/zsh", "-c", "-i", "ls -l"}, "ls -l"},

        {{"dash", "-c", "ls -l"}, "ls -l"},
        {{"/dash", "-c", "ls -l"}, "ls -l"},
        {{"/bin/dash", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/dash", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/dash", "-ci", "ls -l"}, "ls -l"},
        {{"/usr/bin/dash", "-ic", "ls -l"}, "ls -l"},
        {{"/usr/bin/dash", "-c", "-i", "ls -l"}, "ls -l"},

        {{"ash", "-c", "ls -l"}, "ls -l"},
        {{"/ash", "-c", "ls -l"}, "ls -l"},
        {{"/bin/ash", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/ash", "-c", "ls -l"}, "ls -l"},
        {{"/usr/bin/ash", "-ci", "ls -l"}, "ls -l"},
        {{"/usr/bin/ash", "-ic", "ls -l"}, "ls -l"},
        {{"/usr/bin/ash", "-c", "-i", "ls -l"}, "ls -l"},
        {{"/usr/bin/sh", "-c", "+x", "ls -l"}, "ls -l"},

        {{"/usr/bin/bash", "-c", "+x", "ls -l"}, "ls -l"},
        {{"/usr/bin/bash", "-c", "+x", "-i", "ls -l"}, "ls -l"},
        {{"/usr/bin/ksh", "-c", "+x", "ls -l"}, "ls -l"},
        {{"/usr/bin/ksh", "+x", "ls -l"}, "ls -l"},
        {{"/usr/bin/rksh", "-c", "+x", "ls -l"}, "ls -l"},
        {{"/usr/bin/rksh", "+x", "ls -l"}, "ls -l"},
        {{"/usr/bin/fish", "-c", "+x", "ls -l"}, "ls -l"},
        {{"/usr/bin/zsh", "-c", "+x", "ls -l"}, "ls -l"},
        {{"/usr/bin/dash", "-c", "+x", "ls -l"}, "ls -l"},
        {{"/usr/bin/ash", "-c", "+x", "ls -l"}, "ls -l"},

        // Double quote removal
        {{"/usr/bin/bash", "-c", "+x", R"("ls -l")"}, "ls -l"},
        {{"/usr/bin/bash", "-c", "+x", "-i", R"("ls -l")"}, "ls -l"},
        {{"/usr/bin/ksh", "-c", "+x", R"("ls -l")"}, "ls -l"},
        {{"/usr/bin/ksh", "+x", R"("ls -l")"}, "ls -l"},
        {{"/usr/bin/rksh", "-c", "+x", R"("ls -l")"}, "ls -l"},
        {{"/usr/bin/rksh", "+x", R"("ls -l")"}, "ls -l"},
        {{"/usr/bin/fish", "-c", "+x", R"("ls -l")"}, "ls -l"},
        {{"/usr/bin/zsh", "-c", "+x", R"("ls -l")"}, "ls -l"},
        {{"/usr/bin/dash", "-c", "+x", R"("ls -l")"}, "ls -l"},
        {{"/usr/bin/ash", "-c", "+x", R"("ls -l")"}, "ls -l"},

        // Single quote removal
        {{"/usr/bin/bash", "-c", "+x", R"('ls -l')"}, "ls -l"},
        {{"/usr/bin/bash", "-c", "+x", "-i", R"('ls -l')"}, "ls -l"},
        {{"/usr/bin/ksh", "-c", "+x", R"('ls -l')"}, "ls -l"},
        {{"/usr/bin/ksh", "+x", R"('ls -l')"}, "ls -l"},
        {{"/usr/bin/rksh", "-c", "+x", R"('ls -l')"}, "ls -l"},
        {{"/usr/bin/rksh", "+x", R"('ls -l')"}, "ls -l"},
        {{"/usr/bin/fish", "-c", "+x", R"('ls -l')"}, "ls -l"},
        {{"/usr/bin/zsh", "-c", "+x", R"('ls -l')"}, "ls -l"},
        {{"/usr/bin/dash", "-c", "+x", R"('ls -l')"}, "ls -l"},
        {{"/usr/bin/ash", "-c", "+x", R"('ls -l')"}, "ls -l"},
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
        ASSERT_TRUE(res.outcome) << resource_str;
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
    system_platform_override spo{platform::windows};

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

        {{R"(powershell.exe)", "-Command", R"("ls -l")"}, "ls -l"},
        {{R"(POWERSHELL.EXE)", "-Command", R"("ls -l")"}, "ls -l"},
        {{R"(powershell)", "-Command", R"("ls -l")"}, "ls -l"},
        {{R"(POWERSHELL)", "-Command", R"("ls -l")"}, "ls -l"},

        {{R"(powershell.exe)", "-Command", R"("ls -l")"}, R"("ls -l")"},
        {{R"(POWERSHELL.EXE)", "-Command", R"("ls -l")"}, R"("ls -l")"},
        {{R"(powershell)", "-Command", R"("ls -l")"}, R"("ls -l")"},
        {{R"(POWERSHELL)", "-Command", R"("ls -l")"}, R"("ls -l")"},

        {{R"(powershell.exe)", "-Command", R"('ls -l')"}, "ls -l"},
        {{R"(POWERSHELL.EXE)", "-Command", R"('ls -l')"}, "ls -l"},
        {{R"(powershell)", "-Command", R"('ls -l')"}, "ls -l"},
        {{R"(POWERSHELL)", "-Command", R"('ls -l')"}, "ls -l"},

        {{R"(powershell.exe)", "-Command", R"('ls -l')"}, "'ls -l'"},
        {{R"(POWERSHELL.EXE)", "-Command", R"('ls -l')"}, "'ls -l'"},
        {{R"(powershell)", "-Command", R"('ls -l')"}, "'ls -l'"},
        {{R"(POWERSHELL)", "-Command", R"('ls -l')"}, "'ls -l'"},

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
        ASSERT_TRUE(res.outcome) << resource_str;
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

TEST(TestCmdiDetector, ExecutableInjectionMultipleArguments)
{
    cmdi_detector cond{{gen_param_def("server.sys.exec.cmd", "server.request.query")}};
    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);

    std::vector<std::string> resource{"/usr/bin/halt", "-h"};
    std::unordered_map<std::string, std::string> params{
        {"halt", "bin"}, {"-h", "usr"}, {"executable", "/usr/bin/halt"}};

    std::string resource_str = generate_resource_string(resource);
    ddwaf_object array;
    ddwaf_object_array(&array);
    for (const auto &arg : resource) {
        ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, arg.c_str()));
    }
    ddwaf_object_map_add(&root, "server.sys.exec.cmd", &array);

    ddwaf_object map;
    ddwaf_object_map(&map);
    for (const auto &[key, value] : params) {
        ddwaf_object_map_add(&map, key.c_str(), ddwaf_object_string(&tmp, value.c_str()));
    }
    ddwaf_object_map_add(&root, "server.request.query", &map);

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
    EXPECT_STR(cache.match->args[1].resolved, "/usr/bin/halt");
    EXPECT_STR(cache.match->args[1].key_path[0], "executable");

    EXPECT_STR(cache.match->highlights[0], "/usr/bin/halt");
}

TEST(TestCmdiDetector, EmptyExecutable)
{
    cmdi_detector cond{{gen_param_def("server.sys.exec.cmd", "server.request.query")}};
    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);

    std::vector<std::string> resource{"", "-h"};
    std::unordered_map<std::string, std::string> params{
        {"halt", "bin"}, {"-h", "usr"}, {"executable", "/usr/bin/halt"}};

    std::string resource_str = generate_resource_string(resource);
    ddwaf_object array;
    ddwaf_object_array(&array);
    for (const auto &arg : resource) {
        ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, arg.c_str()));
    }
    ddwaf_object_map_add(&root, "server.sys.exec.cmd", &array);

    ddwaf_object map;
    ddwaf_object_map(&map);
    for (const auto &[key, value] : params) {
        ddwaf_object_map_add(&map, key.c_str(), ddwaf_object_string(&tmp, value.c_str()));
    }
    ddwaf_object_map_add(&root, "server.request.query", &map);

    object_store store;
    store.insert(root);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    ASSERT_FALSE(res.outcome) << resource[0];
    EXPECT_FALSE(res.ephemeral);
}

TEST(TestCmdiDetector, ShellInjectionMultipleArguments)
{
    cmdi_detector cond{{gen_param_def("server.sys.exec.cmd", "server.request.query")}};
    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);

    std::vector<std::string> resource{"/usr/bin/sh", "-c", "ls -l $file; $(cat /etc/passwd)"};
    std::unordered_map<std::string, std::string> params{
        {"-l $file", "bin"}, {"-h", "usr"}, {"shell", "; $(cat /etc/passwd)"}};

    std::string resource_str = generate_resource_string(resource);
    ddwaf_object array;
    ddwaf_object_array(&array);
    for (const auto &arg : resource) {
        ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, arg.c_str()));
    }
    ddwaf_object_map_add(&root, "server.sys.exec.cmd", &array);

    ddwaf_object map;
    ddwaf_object_map(&map);
    for (const auto &[key, value] : params) {
        ddwaf_object_map_add(&map, key.c_str(), ddwaf_object_string(&tmp, value.c_str()));
    }
    ddwaf_object_map_add(&root, "server.request.query", &map);

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
    EXPECT_STR(cache.match->args[1].resolved, "; $(cat /etc/passwd)");
    EXPECT_STR(cache.match->args[1].key_path[0], "shell");

    EXPECT_STR(cache.match->highlights[0], "; $(cat /etc/passwd)");
}

} // namespace
