// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstdlib>
#include <cstring>
#include <ddwaf.h>
#include <string_view>

#include <lazy_string.hpp>

namespace ddwaf {

enum class transformer_id : uint8_t {
    invalid = 0,
    lowercase,
    remove_nulls,
    compress_whitespace,
    normalize_path,
    normalize_path_win,
    url_decode,
    url_decode_iis,
    css_decode,
    js_decode,
    html_entity_decode,
    base64_decode,
    base64_decode_rfc2045,
    base64_encode,
    shell_unescape,
    url_basename,
    url_path,
    url_querystring,
    remove_comments,
    unicode_normalize,
    keys_only,
    values_only,
};

// namespace transformer {

/*template <typename Derived> class base {*/
/*public:*/
/*static bool transform(const ddwaf_object &src, ddwaf_object &dst)*/
/*{*/
/*if (src.type != DDWAF_OBJ_STRING || src.stringValue == nullptr || src.nbEntries == 0) {*/
/*return false;*/
/*}*/

/*uint64_t length = 0;*/
/*char *result = nullptr;*/
/*if constexpr (typename Derived::in_place()) {*/
/*lazy_string str({src.stringValue, src.nbEntries});*/
/*auto res = Derived::transform(str);*/
/*if (res && str.modified()) {*/
/*length = str.length();*/
/*result = str.move();*/
/*}*/
/*}*/

/*if (res) {*/
/*auto length = str.length();*/
/*ddwaf_object_stringl_nc(&dst, str.move(), length);*/
/*}*/

/*return true;*/
/*}*/

/*static bool transform(lazy_string &str)*/
/*{*/
/*if (str.length() == 0) {*/
/*return false;*/
/*}*/

/*return Derived::transform(str);*/
/*}*/
/*};*/

/*} // namespace transformer*/
} // namespace ddwaf
