// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <atomic>
#include <cstring>
#include <string>
#include <thread>

#include "thread_exit.hpp"

#include "common/gtest_utils.hpp"
#include "ddwaf.h"

#ifndef _WIN32
#  include <pthread.h>
#endif

using namespace ddwaf;

namespace {

std::atomic<int> calls{0};
void count_call() noexcept { ++calls; }

TEST(TestThreadExit, CallbackRunsOnThreadExit)
{
    calls = 0;
    std::thread([] { EXPECT_TRUE(thread_exit::register_callback(count_call)); }).join();
    EXPECT_EQ(calls, 1);
}

TEST(TestThreadExit, CallbacksRunInReverseOrder)
{
    static std::string order;
    order.clear();
    std::thread([] {
        EXPECT_TRUE(thread_exit::register_callback([]() noexcept { order += 'a'; }));
        EXPECT_TRUE(thread_exit::register_callback([]() noexcept { order += 'b'; }));
    }).join();
    EXPECT_EQ(order, "ba");
}

TEST(TestThreadExit, TooManyCallbacks)
{
    calls = 0;
    std::thread([] {
        for (std::size_t i = 0; i < thread_exit::max_callbacks; ++i) {
            EXPECT_TRUE(thread_exit::register_callback(count_call));
        }
        EXPECT_FALSE(thread_exit::register_callback(count_call));
    }).join();
    EXPECT_EQ(calls, thread_exit::max_callbacks);
}

TEST(TestThreadExit, CallbackRegisteredFromCallback)
{
    calls = 0;
    std::thread([] {
        EXPECT_TRUE(thread_exit::register_callback([]() noexcept {
            ++calls;
            EXPECT_TRUE(thread_exit::register_callback(count_call));
        }));
    }).join();
    EXPECT_EQ(calls, 2);
}

#ifndef _WIN32
// On Windows, callbacks are run by a thread_local destructor, so this isn't
// supported there.
TEST(TestThreadExit, CallbackRegisteredFromThreadLocalDestructor)
{
    struct registers_on_destruction {
        registers_on_destruction() = default;
        ~registers_on_destruction() { EXPECT_TRUE(thread_exit::register_callback(count_call)); }
        registers_on_destruction(const registers_on_destruction &) = delete;
        registers_on_destruction(registers_on_destruction &&) = delete;
        registers_on_destruction &operator=(const registers_on_destruction &) = delete;
        registers_on_destruction &operator=(registers_on_destruction &&) = delete;
    };

    calls = 0;
    std::thread([] {
        thread_local registers_on_destruction object;
        (void)object;
    }).join();
    EXPECT_EQ(calls, 1);
}

// On glibc, thread_local destructors registered while the pthread key
// destructors of the thread run are never called; callbacks registered at
// that point must still run.
TEST(TestThreadExit, CallbackRegisteredFromKeyDestructor)
{
    pthread_key_t key;
    ASSERT_EQ(pthread_key_create(&key, [](void * /*value*/) {
        EXPECT_TRUE(thread_exit::register_callback(count_call));
    }),
        0);

    calls = 0;
    std::thread([key] { pthread_setspecific(key, &key); }).join();
    EXPECT_EQ(calls, 1);

    pthread_key_delete(key);
}
#endif

// Evaluating from the destructor of a thread_local object, constructed before
// the first evaluation of the thread, must work as usual: libddwaf's
// per-thread state (here the cache of the regex prefilter) mustn't be used
// after it's freed.
TEST(TestThreadExit, EvaluateFromThreadLocalDestructor)
{
    static std::atomic<int> code_in_destructor{-1};

    struct evaluator {
        evaluator() = default;
        ~evaluator()
        {
            if (handle == nullptr) {
                return;
            }

            auto *alloc = ddwaf_get_default_allocator();
            int code = -1;
            for (const char *value :
                {"xx union  select yy", "nothing here, but long enough to be scanned"}) {
                auto *context = ddwaf_context_init(handle, alloc);
                ddwaf_object map;
                ddwaf_object_set_map(&map, 1, alloc);
                ddwaf_object_set_string(ddwaf_object_insert_key(&map, STRL("q"), alloc), value,
                    std::strlen(value), alloc);
                ddwaf_object out;
                auto res = ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME);
                if (code == -1) {
                    code = res;
                }
                ddwaf_object_destroy(&out, alloc);
                ddwaf_context_destroy(context);
            }
            code_in_destructor = code;
            ddwaf_destroy(handle);
        }
        evaluator(const evaluator &) = delete;
        evaluator(evaluator &&) = delete;
        evaluator &operator=(const evaluator &) = delete;
        evaluator &operator=(evaluator &&) = delete;

        ddwaf_handle handle{nullptr};
    };

    std::thread([] {
        thread_local evaluator object;

        auto *alloc = ddwaf_get_default_allocator();
        auto rule = json_to_object(
            R"({"version": "2.2", "metadata": {"rules_version": "1.8.0"}, "rules": [
            {"id": "r1", "name": "r1", "tags": {"type": "t", "category": "c"},
            "conditions": [{"operator": "match_regex", "parameters": {"inputs":
            [{"address": "q"}], "regex": "union\\s+select"}}]}]})");
        object.handle = ddwaf_init(&rule, nullptr);
        ddwaf_object_destroy(&rule, alloc);
        ASSERT_NE(object.handle, nullptr);

        auto *context = ddwaf_context_init(object.handle, alloc);
        ddwaf_object map;
        ddwaf_object_set_map(&map, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&map, STRL("q"), alloc), STRL("union select 1"), alloc);
        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &map, alloc, &out, LONG_TIME), DDWAF_MATCH);
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }).join();

    EXPECT_EQ(code_in_destructor, DDWAF_MATCH);
}

} // namespace
