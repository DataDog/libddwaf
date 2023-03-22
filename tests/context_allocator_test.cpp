// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "context_allocator.hpp"
#include "ddwaf.h"
#include "test.h"
#include <thread>

using namespace ddwaf;

class TestContextAllocator : public ::testing::Test {
public:
    void SetUp() override
    {
        old_resource = memory::get_local_memory_resource();
        memory::set_local_memory_resource(&resource);
    }

    void TearDown() override { memory::set_local_memory_resource(old_resource); }

protected:
    std::pmr::memory_resource *old_resource;
    memory::null_memory_resource resource;
};

TEST_F(TestContextAllocator, NullLocalAllocator)
{
    memory::context_allocator alloc;
    EXPECT_THROW(alloc.allocate(1), std::bad_alloc);

    // If the allocator is not set, memory::* objecs won't be able to allocate
    EXPECT_THROW(memory::string("string longer than optimisation"), std::bad_alloc);
}

TEST_F(TestContextAllocator, MonotonicLocalAllocator)
{
    // If the allocator is not set, memory::* objecs won't be able to allocate
    std::pmr::monotonic_buffer_resource resource;
    memory::set_local_memory_resource(&resource);
    EXPECT_EQ(memory::get_local_memory_resource(), &resource);

    memory::context_allocator alloc;
    auto value = alloc.allocate(1);
    EXPECT_NE(value, nullptr);
    alloc.deallocate(value, 1);

    EXPECT_NO_THROW(memory::string("string longer than optimisation"));
}

TEST_F(TestContextAllocator, AllocatorGuard)
{
    // If the allocator is not set, memory::* objecs won't be able to allocate
    auto *old_resource = memory::get_local_memory_resource();

    std::pmr::monotonic_buffer_resource resource;
    {
        memory::memory_resource_guard guard{&resource};
        EXPECT_EQ(memory::get_local_memory_resource(), &resource);
        EXPECT_NO_THROW(memory::string("string longer than optimisation"));
    }

    EXPECT_EQ(memory::get_local_memory_resource(), old_resource);
}

TEST_F(TestContextAllocator, MultipleThreads)
{
    std::pmr::monotonic_buffer_resource resource;
    memory::memory_resource_guard guard{&resource};
    EXPECT_EQ(memory::get_local_memory_resource(), &resource);

    {
        memory::context_allocator alloc;
        auto value = alloc.allocate(1);
        EXPECT_NE(value, nullptr);
        alloc.deallocate(value, 1);

        EXPECT_NO_THROW(memory::string("string longer than optimisation"));
    }

    std::thread([]() {
        memory::context_allocator alloc;
        EXPECT_THROW(alloc.allocate(1), std::bad_alloc);

        // If the allocator is not set, memory::* objecs won't be able to allocate
        EXPECT_THROW(memory::string("string longer than optimisation"), std::bad_alloc);
    }).join();

    std::thread([]() {
        std::pmr::monotonic_buffer_resource resource;
        memory::memory_resource_guard guard{&resource};
        EXPECT_EQ(memory::get_local_memory_resource(), &resource);

        memory::context_allocator alloc;
        auto value = alloc.allocate(1);
        EXPECT_NE(value, nullptr);
        alloc.deallocate(value, 1);

        EXPECT_NO_THROW(memory::string("string longer than optimisation"));
    }).join();

    {
        memory::context_allocator alloc;
        auto value = alloc.allocate(1);
        EXPECT_NE(value, nullptr);
        alloc.deallocate(value, 1);

        EXPECT_NO_THROW(memory::string("string longer than optimisation"));
    }
}
