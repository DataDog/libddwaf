// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2025 Datadog, Inc.

#include "attribute_collector.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {

/*TEST(TestAttributeCollector, InsertNoCopy)*/
/*{*/
/*ddwaf_object expected;*/
/*ddwaf_object_string(&expected, "value");*/

/*attribute_collector collector;*/
/*EXPECT_TRUE(collector.insert("address", expected, false));*/

/*object_store store;*/
/*collector.collect_pending(store);*/
/*auto attributes = collector.get_available_attributes_and_reset();*/

/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*EXPECT_EQ(ddwaf_object_size(&attributes), 1);*/

/*const auto *obtained = ddwaf_object_at_value(&attributes, 0);*/
/*EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);*/
/*EXPECT_EQ(obtained->stringValue, expected.stringValue);*/
/*EXPECT_STREQ(obtained->stringValue, expected.stringValue);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, InsertCopy)*/
/*{*/
/*ddwaf_object expected;*/
/*ddwaf_object_string(&expected, "value");*/

/*attribute_collector collector;*/
/*EXPECT_TRUE(collector.insert("address", expected, true));*/

/*object_store store;*/
/*collector.collect_pending(store);*/
/*auto attributes = collector.get_available_attributes_and_reset();*/

/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*EXPECT_EQ(ddwaf_object_size(&attributes), 1);*/

/*const auto *obtained = ddwaf_object_at_value(&attributes, 0);*/
/*EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);*/
/*EXPECT_NE(obtained->stringValue, expected.stringValue);*/
/*EXPECT_STREQ(obtained->stringValue, expected.stringValue);*/

/*ddwaf_object_free(&expected);*/
/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, InsertDuplicate)*/
/*{*/
/*ddwaf_object expected;*/
/*ddwaf_object_string(&expected, "value");*/

/*attribute_collector collector;*/
/*EXPECT_TRUE(collector.insert("address", expected, true));*/
/*EXPECT_FALSE(collector.insert("address", expected, true));*/

/*object_store store;*/
/*collector.collect_pending(store);*/
/*auto attributes = collector.get_available_attributes_and_reset();*/

/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*EXPECT_EQ(ddwaf_object_size(&attributes), 1);*/

/*const auto *obtained = ddwaf_object_at_value(&attributes, 0);*/
/*EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);*/
/*EXPECT_NE(obtained->stringValue, expected.stringValue);*/
/*EXPECT_STREQ(obtained->stringValue, expected.stringValue);*/

/*ddwaf_object_free(&expected);*/
/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, CollectAvailableScalar)*/
/*{*/
/*ddwaf_object tmp;*/
/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address", ddwaf_object_string(&tmp, "value"));*/

/*object_store store;*/
/*store.insert(input_map);*/

/*attribute_collector collector;*/
/*EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));*/
/*auto attributes = collector.get_available_attributes_and_reset();*/

/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*EXPECT_EQ(ddwaf_object_size(&attributes), 1);*/

/*const auto *expected = ddwaf_object_at_value(&input_map, 0);*/
/*const auto *obtained = ddwaf_object_at_value(&attributes, 0);*/
/*EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);*/
/*EXPECT_NE(obtained->stringValue, expected->stringValue);*/
/*EXPECT_STREQ(obtained->stringValue, expected->stringValue);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, CollectAvailableKeyPathScalar)*/
/*{*/
/*ddwaf_object tmp;*/
/*ddwaf_object second_map;*/
/*ddwaf_object_map(&second_map);*/
/*ddwaf_object_map_add(&second_map, "second", ddwaf_object_string(&tmp, "value"));*/

/*ddwaf_object first_map;*/
/*ddwaf_object_map(&first_map);*/
/*ddwaf_object_map_add(&first_map, "first", &second_map);*/

/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address", &first_map);*/

/*object_store store;*/
/*store.insert(input_map);*/

/*attribute_collector collector;*/
/*std::vector<std::string> key_path{"first", "second"};*/
/*EXPECT_TRUE(*/
/*collector.collect(store, get_target_index("input_address"), key_path, "output_address"));*/
/*auto attributes = collector.get_available_attributes_and_reset();*/

/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*EXPECT_EQ(ddwaf_object_size(&attributes), 1);*/

/*const auto *expected = ddwaf_object_at_value(&second_map, 0);*/
/*const auto *obtained = ddwaf_object_at_value(&attributes, 0);*/
/*EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);*/
/*EXPECT_NE(obtained->stringValue, expected->stringValue);*/
/*EXPECT_STREQ(obtained->stringValue, expected->stringValue);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, CollectAvailableKeyPathSingleValueArray)*/
/*{*/
/*ddwaf_object tmp;*/
/*ddwaf_object third_array;*/
/*ddwaf_object_array(&third_array);*/
/*ddwaf_object_array_add(&third_array, ddwaf_object_string(&tmp, "value"));*/

/*ddwaf_object second_map;*/
/*ddwaf_object_map(&second_map);*/
/*ddwaf_object_map_add(&second_map, "second", &third_array);*/

/*ddwaf_object first_map;*/
/*ddwaf_object_map(&first_map);*/
/*ddwaf_object_map_add(&first_map, "first", &second_map);*/

/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address", &first_map);*/

/*object_store store;*/
/*store.insert(input_map);*/

/*attribute_collector collector;*/
/*std::vector<std::string> key_path{"first", "second"};*/
/*EXPECT_TRUE(*/
/*collector.collect(store, get_target_index("input_address"), key_path, "output_address"));*/
/*auto attributes = collector.get_available_attributes_and_reset();*/

/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*EXPECT_EQ(ddwaf_object_size(&attributes), 1);*/

/*const auto *expected = ddwaf_object_at_value(&third_array, 0);*/
/*const auto *obtained = ddwaf_object_at_value(&attributes, 0);*/
/*EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);*/
/*EXPECT_NE(obtained->stringValue, expected->stringValue);*/
/*EXPECT_STREQ(obtained->stringValue, expected->stringValue);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, CollectAvailableKeyPathMultiValueArray)*/
/*{*/
/*ddwaf_object tmp;*/
/*ddwaf_object third_array;*/
/*ddwaf_object_array(&third_array);*/
/*ddwaf_object_array_add(&third_array, ddwaf_object_string(&tmp, "value0"));*/
/*ddwaf_object_array_add(&third_array, ddwaf_object_string(&tmp, "value1"));*/
/*ddwaf_object_array_add(&third_array, ddwaf_object_string(&tmp, "value2"));*/

/*ddwaf_object second_map;*/
/*ddwaf_object_map(&second_map);*/
/*ddwaf_object_map_add(&second_map, "second", &third_array);*/

/*ddwaf_object first_map;*/
/*ddwaf_object_map(&first_map);*/
/*ddwaf_object_map_add(&first_map, "first", &second_map);*/

/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address", &first_map);*/

/*object_store store;*/
/*store.insert(input_map);*/

/*attribute_collector collector;*/
/*std::vector<std::string> key_path{"first", "second"};*/
/*EXPECT_TRUE(*/
/*collector.collect(store, get_target_index("input_address"), key_path, "output_address"));*/
/*auto attributes = collector.get_available_attributes_and_reset();*/

/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*EXPECT_EQ(ddwaf_object_size(&attributes), 1);*/

/*const auto *expected = ddwaf_object_at_value(&third_array, 0);*/
/*const auto *obtained = ddwaf_object_at_value(&attributes, 0);*/
/*EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);*/
/*EXPECT_NE(obtained->stringValue, expected->stringValue);*/
/*EXPECT_STREQ(obtained->stringValue, expected->stringValue);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, CollectUnavailableKeyPath)*/
/*{*/
/*ddwaf_object tmp;*/
/*ddwaf_object second_map;*/
/*ddwaf_object_map(&second_map);*/
/*ddwaf_object_map_add(&second_map, "third", ddwaf_object_string(&tmp, "value"));*/

/*ddwaf_object first_map;*/
/*ddwaf_object_map(&first_map);*/
/*ddwaf_object_map_add(&first_map, "first", &second_map);*/

/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address", &first_map);*/

/*object_store store;*/
/*store.insert(input_map);*/

/*attribute_collector collector;*/
/*std::vector<std::string> key_path{"first", "second"};*/
/*EXPECT_FALSE(*/
/*collector.collect(store, get_target_index("input_address"), key_path, "output_address"));*/
/*auto attributes = collector.get_available_attributes_and_reset();*/

/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*EXPECT_EQ(ddwaf_object_size(&attributes), 0);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, CollectPendingKeyPathScalar)*/
/*{*/
/*ddwaf_object tmp;*/
/*ddwaf_object second_map;*/
/*ddwaf_object_map(&second_map);*/
/*ddwaf_object_map_add(&second_map, "second", ddwaf_object_string(&tmp, "value"));*/

/*ddwaf_object first_map;*/
/*ddwaf_object_map(&first_map);*/
/*ddwaf_object_map_add(&first_map, "first", &second_map);*/

/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address", &first_map);*/

/*object_store store;*/

/*attribute_collector collector;*/
/*std::vector<std::string> key_path{"first", "second"};*/
/*EXPECT_TRUE(*/
/*collector.collect(store, get_target_index("input_address"), key_path, "output_address"));*/
/*auto attributes = collector.get_available_attributes_and_reset();*/
/*EXPECT_EQ(ddwaf_object_size(&attributes), 0);*/
/*EXPECT_TRUE(collector.has_pending_attributes());*/

/*store.insert(input_map);*/
/*collector.collect_pending(store);*/
/*attributes = collector.get_available_attributes_and_reset();*/
/*EXPECT_EQ(ddwaf_object_size(&attributes), 1);*/
/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*const auto *expected = ddwaf_object_at_value(&second_map, 0);*/
/*const auto *obtained = ddwaf_object_at_value(&attributes, 0);*/
/*EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);*/
/*EXPECT_NE(obtained->stringValue, expected->stringValue);*/
/*EXPECT_STREQ(obtained->stringValue, expected->stringValue);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, CollectAvailableKeyPathInvalidValue)*/
/*{*/
/*ddwaf_object tmp;*/
/*ddwaf_object second_map;*/
/*ddwaf_object_map(&second_map);*/
/*ddwaf_object_map_add(&second_map, "second", ddwaf_object_map(&tmp));*/

/*ddwaf_object first_map;*/
/*ddwaf_object_map(&first_map);*/
/*ddwaf_object_map_add(&first_map, "first", &second_map);*/

/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address", &first_map);*/

/*object_store store;*/
/*store.insert(input_map);*/

/*attribute_collector collector;*/
/*std::vector<std::string> key_path{"first", "second"};*/
/*EXPECT_FALSE(*/
/*collector.collect(store, get_target_index("input_address"), key_path, "output_address"));*/
/*auto attributes = collector.get_available_attributes_and_reset();*/

/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*EXPECT_EQ(ddwaf_object_size(&attributes), 0);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, CollectDuplicateScalar)*/
/*{*/
/*ddwaf_object tmp;*/
/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address", ddwaf_object_string(&tmp, "value"));*/

/*object_store store;*/
/*store.insert(input_map);*/

/*attribute_collector collector;*/
/*EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));*/
/*EXPECT_FALSE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));*/
/*auto attributes = collector.get_available_attributes_and_reset();*/

/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*EXPECT_EQ(ddwaf_object_size(&attributes), 1);*/

/*const auto *expected = ddwaf_object_at_value(&input_map, 0);*/
/*const auto *obtained = ddwaf_object_at_value(&attributes, 0);*/
/*EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);*/
/*EXPECT_NE(obtained->stringValue, expected->stringValue);*/
/*EXPECT_STREQ(obtained->stringValue, expected->stringValue);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, CollectAvailableScalarFromSingleValueArray)*/
/*{*/
/*ddwaf_object tmp;*/
/*ddwaf_object intermediate_array;*/
/*ddwaf_object_array(&intermediate_array);*/
/*ddwaf_object_array_add(&intermediate_array, ddwaf_object_string(&tmp, "value"));*/

/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address", &intermediate_array);*/

/*object_store store;*/
/*store.insert(input_map);*/

/*attribute_collector collector;*/
/*EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));*/
/*auto attributes = collector.get_available_attributes_and_reset();*/

/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*EXPECT_EQ(ddwaf_object_size(&attributes), 1);*/

/*const auto *expected = ddwaf_object_at_value(ddwaf_object_at_value(&input_map, 0), 0);*/
/*const auto *obtained = ddwaf_object_at_value(&attributes, 0);*/
/*EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);*/
/*EXPECT_NE(obtained->stringValue, expected->stringValue);*/
/*EXPECT_STREQ(obtained->stringValue, expected->stringValue);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, CollectAvailableScalarFromMultiValueArray)*/
/*{*/
/*ddwaf_object tmp;*/
/*ddwaf_object intermediate_array;*/
/*ddwaf_object_array(&intermediate_array);*/
/*ddwaf_object_array_add(&intermediate_array, ddwaf_object_string(&tmp, "value0"));*/
/*ddwaf_object_array_add(&intermediate_array, ddwaf_object_string(&tmp, "value1"));*/
/*ddwaf_object_array_add(&intermediate_array, ddwaf_object_string(&tmp, "value2"));*/

/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address", &intermediate_array);*/

/*object_store store;*/
/*store.insert(input_map);*/

/*attribute_collector collector;*/
/*EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));*/
/*auto attributes = collector.get_available_attributes_and_reset();*/

/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*EXPECT_EQ(ddwaf_object_size(&attributes), 1);*/

/*const auto *expected = ddwaf_object_at_value(ddwaf_object_at_value(&input_map, 0), 0);*/
/*const auto *obtained = ddwaf_object_at_value(&attributes, 0);*/
/*EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);*/
/*EXPECT_NE(obtained->stringValue, expected->stringValue);*/
/*EXPECT_STREQ(obtained->stringValue, expected->stringValue);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, CollectInvalidObjectFromArray)*/
/*{*/
/*ddwaf_object tmp;*/
/*ddwaf_object intermediate_array;*/
/*ddwaf_object_array(&intermediate_array);*/
/*ddwaf_object_array_add(&intermediate_array, ddwaf_object_map(&tmp));*/

/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address", &intermediate_array);*/

/*object_store store;*/
/*store.insert(input_map);*/

/*attribute_collector collector;*/
/*EXPECT_FALSE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));*/
/*auto attributes = collector.get_available_attributes_and_reset();*/

/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*EXPECT_EQ(ddwaf_object_size(&attributes), 0);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, CollectUnavailableScalar)*/
/*{*/
/*object_store store;*/
/*attribute_collector collector;*/

/*// The attribute should be in the pending queue*/
/*EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));*/
/*EXPECT_TRUE(collector.has_pending_attributes());*/

/*collector.collect_pending(store);*/
/*EXPECT_TRUE(collector.has_pending_attributes());*/

/*auto attributes = collector.get_available_attributes_and_reset();*/
/*EXPECT_EQ(ddwaf_object_size(&attributes), 0);*/

/*// After adding the attribute, collect_pending should extract, copy and return*/
/*// the expected attribute*/
/*ddwaf_object tmp;*/
/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address", ddwaf_object_string(&tmp, "value"));*/

/*store.insert(input_map);*/
/*collector.collect_pending(store);*/
/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*attributes = collector.get_available_attributes_and_reset();*/
/*EXPECT_EQ(ddwaf_object_size(&attributes), 1);*/

/*const auto *expected = ddwaf_object_at_value(&input_map, 0);*/
/*const auto *obtained = ddwaf_object_at_value(&attributes, 0);*/
/*EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);*/
/*EXPECT_NE(obtained->stringValue, expected->stringValue);*/
/*EXPECT_STREQ(obtained->stringValue, expected->stringValue);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, CollectUnavailableScalarFromSingleValueArray)*/
/*{*/
/*object_store store;*/
/*attribute_collector collector;*/

/*// The attribute should be in the pending queue*/
/*EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));*/
/*EXPECT_TRUE(collector.has_pending_attributes());*/

/*collector.collect_pending(store);*/
/*EXPECT_TRUE(collector.has_pending_attributes());*/

/*auto attributes = collector.get_available_attributes_and_reset();*/
/*EXPECT_EQ(ddwaf_object_size(&attributes), 0);*/

/*// After adding the attribute, collect_pending should extract, copy and return*/
/*// the expected attribute*/
/*ddwaf_object tmp;*/
/*ddwaf_object intermediate_array;*/
/*ddwaf_object_array(&intermediate_array);*/
/*ddwaf_object_array_add(&intermediate_array, ddwaf_object_string(&tmp, "value"));*/

/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address", &intermediate_array);*/

/*store.insert(input_map);*/
/*collector.collect_pending(store);*/
/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*attributes = collector.get_available_attributes_and_reset();*/
/*EXPECT_EQ(ddwaf_object_size(&attributes), 1);*/

/*const auto *expected = ddwaf_object_at_value(ddwaf_object_at_value(&input_map, 0), 0);*/
/*const auto *obtained = ddwaf_object_at_value(&attributes, 0);*/
/*EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);*/
/*EXPECT_NE(obtained->stringValue, expected->stringValue);*/
/*EXPECT_STREQ(obtained->stringValue, expected->stringValue);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, CollectUnavailableScalarFromMultiValueArray)*/
/*{*/
/*object_store store;*/
/*attribute_collector collector;*/

/*// The attribute should be in the pending queue*/
/*EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));*/
/*EXPECT_TRUE(collector.has_pending_attributes());*/

/*collector.collect_pending(store);*/
/*EXPECT_TRUE(collector.has_pending_attributes());*/

/*auto attributes = collector.get_available_attributes_and_reset();*/
/*EXPECT_EQ(ddwaf_object_size(&attributes), 0);*/

/*// After adding the attribute, collect_pending should extract, copy and return*/
/*// the expected attribute*/
/*ddwaf_object tmp;*/
/*ddwaf_object intermediate_array;*/
/*ddwaf_object_array(&intermediate_array);*/
/*ddwaf_object_array_add(&intermediate_array, ddwaf_object_string(&tmp, "value0"));*/
/*ddwaf_object_array_add(&intermediate_array, ddwaf_object_string(&tmp, "value1"));*/
/*ddwaf_object_array_add(&intermediate_array, ddwaf_object_string(&tmp, "value2"));*/

/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address", &intermediate_array);*/

/*store.insert(input_map);*/
/*collector.collect_pending(store);*/
/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*attributes = collector.get_available_attributes_and_reset();*/
/*EXPECT_EQ(ddwaf_object_size(&attributes), 1);*/

/*const auto *expected = ddwaf_object_at_value(ddwaf_object_at_value(&input_map, 0), 0);*/
/*const auto *obtained = ddwaf_object_at_value(&attributes, 0);*/
/*EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);*/
/*EXPECT_NE(obtained->stringValue, expected->stringValue);*/
/*EXPECT_STREQ(obtained->stringValue, expected->stringValue);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, CollectUnavailableInvalidObject)*/
/*{*/
/*object_store store;*/
/*attribute_collector collector;*/

/*// The attribute should be in the pending queue*/
/*EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));*/
/*EXPECT_TRUE(collector.has_pending_attributes());*/

/*collector.collect_pending(store);*/
/*EXPECT_TRUE(collector.has_pending_attributes());*/

/*auto attributes = collector.get_available_attributes_and_reset();*/
/*EXPECT_EQ(ddwaf_object_size(&attributes), 0);*/

/*// After adding the attribute, collect_pending should extract, copy and return*/
/*// the expected attribute*/
/*ddwaf_object tmp;*/
/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address", ddwaf_object_array(&tmp));*/

/*store.insert(input_map);*/
/*collector.collect_pending(store);*/
/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*attributes = collector.get_available_attributes_and_reset();*/
/*EXPECT_EQ(ddwaf_object_size(&attributes), 0);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*TEST(TestAttributeCollector, CollectMultipleUnavailableScalars)*/
/*{*/
/*object_store store;*/
/*attribute_collector collector;*/

/*{*/
/*// The attribute should be in the pending queue*/
/*EXPECT_TRUE(*/
/*collector.collect(store, get_target_index("input_address_0"), {}, "output_address_0"));*/
/*EXPECT_TRUE(collector.has_pending_attributes());*/

/*// Nothing to be collected*/
/*collector.collect_pending(store);*/
/*EXPECT_TRUE(collector.has_pending_attributes());*/

/*auto attributes = collector.get_available_attributes_and_reset();*/
/*EXPECT_EQ(ddwaf_object_size(&attributes), 0);*/
/*}*/

/*{*/
/*// The attribute should be in the pending queue*/
/*EXPECT_TRUE(*/
/*collector.collect(store, get_target_index("input_address_1"), {}, "output_address_1"));*/
/*EXPECT_TRUE(collector.has_pending_attributes());*/

/*// Nothing to be collected*/
/*collector.collect_pending(store);*/
/*EXPECT_TRUE(collector.has_pending_attributes());*/

/*auto attributes = collector.get_available_attributes_and_reset();*/
/*EXPECT_EQ(ddwaf_object_size(&attributes), 0);*/
/*}*/

/*{*/
/*// After adding the attribute, collect_pending should extract, copy and return*/
/*// the expected attribute*/
/*ddwaf_object tmp;*/
/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address_0", ddwaf_object_string(&tmp, "value"));*/

/*store.insert(input_map);*/

/*EXPECT_TRUE(*/
/*collector.collect(store, get_target_index("input_address_2"), {}, "output_address_2"));*/

/*collector.collect_pending(store);*/
/*EXPECT_TRUE(collector.has_pending_attributes());*/

/*auto attributes = collector.get_available_attributes_and_reset();*/
/*EXPECT_EQ(ddwaf_object_size(&attributes), 1);*/

/*const auto *expected = ddwaf_object_at_value(&input_map, 0);*/
/*const auto *obtained = ddwaf_object_at_value(&attributes, 0);*/
/*EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);*/
/*EXPECT_NE(obtained->stringValue, expected->stringValue);*/
/*EXPECT_STREQ(obtained->stringValue, expected->stringValue);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*{*/
/*// After adding the attribute, collect_pending should extract, copy and return*/
/*// the expected attribute*/
/*ddwaf_object tmp;*/
/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address_2", ddwaf_object_string(&tmp, "value"));*/

/*store.insert(input_map);*/

/*collector.collect_pending(store);*/
/*EXPECT_TRUE(collector.has_pending_attributes());*/

/*auto attributes = collector.get_available_attributes_and_reset();*/
/*EXPECT_EQ(ddwaf_object_size(&attributes), 1);*/

/*const auto *expected = ddwaf_object_at_value(&input_map, 0);*/
/*const auto *obtained = ddwaf_object_at_value(&attributes, 0);*/
/*EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);*/
/*EXPECT_NE(obtained->stringValue, expected->stringValue);*/
/*EXPECT_STREQ(obtained->stringValue, expected->stringValue);*/

/*ddwaf_object_free(&attributes);*/
/*}*/

/*{*/
/*// After adding the attribute, collect_pending should extract, copy and return*/
/*// the expected attribute*/
/*ddwaf_object tmp;*/
/*ddwaf_object input_map;*/
/*ddwaf_object_map(&input_map);*/
/*ddwaf_object_map_add(&input_map, "input_address_1", ddwaf_object_string(&tmp, "value"));*/

/*store.insert(input_map);*/

/*collector.collect_pending(store);*/
/*EXPECT_FALSE(collector.has_pending_attributes());*/

/*auto attributes = collector.get_available_attributes_and_reset();*/
/*EXPECT_EQ(ddwaf_object_size(&attributes), 1);*/

/*const auto *expected = ddwaf_object_at_value(&input_map, 0);*/
/*const auto *obtained = ddwaf_object_at_value(&attributes, 0);*/
/*EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);*/
/*EXPECT_NE(obtained->stringValue, expected->stringValue);*/
/*EXPECT_STREQ(obtained->stringValue, expected->stringValue);*/

/*ddwaf_object_free(&attributes);*/
/*}*/
/*}*/

} // namespace
