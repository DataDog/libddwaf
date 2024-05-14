// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <list>

#include "utils.hpp"

namespace ddwaf {

/*void clone_helper(const ddwaf_object &source, ddwaf_object &destination)*/
/*{*/
/*switch (source.type) {*/
/*case DDWAF_OBJ_BOOL:*/
/*ddwaf_object_bool(&destination, source.boolean);*/
/*break;*/
/*case DDWAF_OBJ_STRING:*/
/*ddwaf_object_stringl(&destination, source.stringValue, source.nbEntries);*/
/*break;*/
/*case DDWAF_OBJ_SIGNED:*/
/*ddwaf_object_signed(&destination, source.intValue);*/
/*break;*/
/*case DDWAF_OBJ_UNSIGNED:*/
/*ddwaf_object_unsigned(&destination, source.uintValue);*/
/*break;*/
/*case DDWAF_OBJ_FLOAT:*/
/*ddwaf_object_float(&destination, source.f64);*/
/*break;*/
/*case DDWAF_OBJ_INVALID:*/
/*ddwaf_object_invalid(&destination);*/
/*break;*/
/*case DDWAF_OBJ_NULL:*/
/*ddwaf_object_null(&destination);*/
/*break;*/
/*case DDWAF_OBJ_MAP:*/
/*ddwaf_object_map(&destination);*/
/*break;*/
/*case DDWAF_OBJ_ARRAY:*/
/*ddwaf_object_array(&destination);*/
/*break;*/
/*}*/
/*}*/

/*ddwaf_object clone(ddwaf_object *input)*/
/*{*/
/*ddwaf_object tmp;*/
/*ddwaf_object_invalid(&tmp);*/

/*ddwaf_object copy;*/
/*std::list<std::pair<ddwaf_object *, ddwaf_object *>> queue;*/

/*clone_helper(*input, copy);*/
/*if (is_container(input)) {*/
/*queue.emplace_front(input, &copy);*/
/*}*/

/*while (!queue.empty()) {*/
/*auto [source, destination] = queue.front();*/
/*for (uint64_t i = 0; i < source->nbEntries; ++i) {*/
/*const auto &child = source->array[i];*/
/*clone_helper(child, tmp);*/
/*if (source->type == DDWAF_OBJ_MAP) {*/
/*ddwaf_object_map_addl(*/
/*destination, child.parameterName, child.parameterNameLength, &tmp);*/
/*} else if (source->type == DDWAF_OBJ_ARRAY) {*/
/*ddwaf_object_array_add(destination, &tmp);*/
/*}*/
/*}*/

/*for (uint64_t i = 0; i < source->nbEntries; ++i) {*/
/*if (is_container(&source->array[i])) {*/
/*queue.emplace_back(&source->array[i], &destination->array[i]);*/
/*}*/
/*}*/

/*queue.pop_front();*/
/*}*/

/*return copy;*/
/*}*/

} // namespace ddwaf
