// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "input_batch_queue.hpp"
#include "object_store.hpp"

#include "common/ddwaf_object_da.hpp"
#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

TEST(TestInputBatchQueue, EnqueueAndApplySingleBatch)
{
    auto query = get_target_index("query");

    object_store store;
    input_batch_queue queue;

    EXPECT_TRUE(queue.insert_batch(store, object_builder_da::map({{"query", "hello"}})));
    EXPECT_FALSE(queue.empty());

    // Not applied until consumed
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.get_target(query).has_value());

    EXPECT_TRUE(queue.next_batch(store));
    EXPECT_TRUE(queue.empty());
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_TRUE(store.get_target(query).has_value());

    // Draining an empty queue resets the new-target set and returns false
    EXPECT_FALSE(queue.next_batch(store));
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_TRUE(store.get_target(query).has_value());
}

TEST(TestInputBatchQueue, InsertNonMapBatchReturnsFalse)
{
    object_store store;
    input_batch_queue queue;

    EXPECT_FALSE(queue.insert_batch(store, test::ddwaf_object_da::make_string("hello")));
    EXPECT_FALSE(queue.insert_batch(store, owned_object{}));
    EXPECT_TRUE(queue.empty());
}

TEST(TestInputBatchQueue, EmptyBatchIsNotSkipped)
{
    object_store store;
    input_batch_queue queue;

    // A map with no addresses is valid but enqueues nothing
    EXPECT_TRUE(queue.insert_batch(store, object_builder_da::map({})));
    EXPECT_FALSE(queue.empty());
}

TEST(TestInputBatchQueue, EnqueueAndApplyMultipleBatches)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    input_batch_queue queue;

    EXPECT_TRUE(queue.insert_batches(
        store, object_builder_da::array({object_builder_da::map({{"query", "hello"}}),
                   object_builder_da::map({{"url", "bye"}})})));

    // First batch: query is new
    EXPECT_TRUE(queue.next_batch(store));
    EXPECT_TRUE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));

    // Second batch: only url is new, the previous new-target set is reset
    EXPECT_TRUE(queue.next_batch(store));
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_TRUE(store.is_new_target(url));

    // Both targets remain available in the store
    EXPECT_TRUE(store.get_target(query).has_value());
    EXPECT_TRUE(store.get_target(url).has_value());

    EXPECT_FALSE(queue.next_batch(store));
    EXPECT_TRUE(queue.empty());
}

TEST(TestInputBatchQueue, InsertBatchesNonArrayReturnsFalse)
{
    object_store store;
    input_batch_queue queue;

    EXPECT_FALSE(queue.insert_batches(store, object_builder_da::map({{"query", "hello"}})));
    EXPECT_TRUE(queue.empty());
}

TEST(TestInputBatchQueue, InsertBatchesWithNonMapElementLeavesQueueUntouched)
{
    object_store store;
    input_batch_queue queue;

    // The middle element is not a map: the whole call fails and nothing is queued
    EXPECT_FALSE(queue.insert_batches(
        store, object_builder_da::array({object_builder_da::map({{"query", "hello"}}),
                   test::ddwaf_object_da::make_string("not a map"),
                   object_builder_da::map({{"url", "bye"}})})));
    EXPECT_TRUE(queue.empty());
}

TEST(TestInputBatchQueue, FlushAppliesRemainingBatchesAsNonNew)
{
    auto query = get_target_index("query");
    auto url = get_target_index("url");

    object_store store;
    input_batch_queue queue;

    EXPECT_TRUE(queue.insert_batch(store, object_builder_da::map({{"query", "hello"}})));
    EXPECT_TRUE(queue.insert_batch(store, object_builder_da::map({{"url", "bye"}})));

    // Consume only the first batch
    EXPECT_TRUE(queue.next_batch(store));
    EXPECT_TRUE(store.is_new_target(query));

    // Flushing applies the remaining batch as non-new and resets the new set
    queue.flush(store);
    EXPECT_TRUE(queue.empty());
    EXPECT_FALSE(store.has_new_targets());
    EXPECT_FALSE(store.is_new_target(query));
    EXPECT_FALSE(store.is_new_target(url));

    // The remaining batch's data is still available in the store
    EXPECT_TRUE(store.get_target(query).has_value());
    EXPECT_TRUE(store.get_target(url).has_value());
}

} // namespace
