// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <functional>
#include <string_view>

#include <ddwaf.h>

enum PW_TRANSFORM_ID {
    PWT_LOWERCASE = 1 << 0,
    PWT_NONULL = 1 << 1,
    PWT_COMPRESS_WHITE = 1 << 2,
    PWT_LENGTH = 1 << 3,
    PWT_NORMALIZE = 1 << 4,
    PWT_NORMALIZE_WIN = 1 << 5,
    PWT_DECODE_URL = 1 << 6,
    PWT_DECODE_URL_IIS = 1 << 7,
    PWT_DECODE_CSS = 1 << 8,
    PWT_DECODE_JS = 1 << 9,
    PWT_DECODE_HTML = 1 << 10,
    PWT_DECODE_BASE64 = 1 << 11,
    PWT_DECODE_BASE64_EXT = 1 << 12,
    PWT_ENCODE_BASE64 = 1 << 13,
    PWT_CMDLINE = 1 << 14,
    PWT_EXTRACT_BASENAME = 1 << 15,
    PWT_EXTRACT_FILENAME = 1 << 16,
    PWT_EXTRACT_QUERYSTR = 1 << 17,
    PWT_REMOVE_COMMENTS = 1 << 18,
    PWT_NUMERIZE = 1 << 19,
    PWT_KEYS_ONLY = 1 << 20,
    PWT_VALUES_ONLY = 1 << 21,
    PWT_UNICODE_NORMALIZE = 1 << 22,
    PWT_INVALID = 1 << 23
};

/*
    Constraints on transformers:
    Transformers can be chained and will undergo a fake call (readOnly=true) as an optimisation
    If the transformer's transformation could be affected by another transformer, (conditionnally
   modifying the string), the transformer should always return that it'll modify the string as it
   won't be able to confirm that during the fake call. Otherwise, we're risking a bypass.
 */

class PWTransformer {
    using transformer = bool(char *, uint64_t &, bool);
    static bool runTransform(
        ddwaf_object *parameter, const std::function<transformer> &transformer, bool readOnly);
    static bool transformLowerCase(ddwaf_object *parameter, bool readOnly);
    static bool transformNoNull(ddwaf_object *parameter, bool readOnly);
    static bool transformCompressWhiteSpace(ddwaf_object *parameter, bool readOnly);
    static bool transformLength(ddwaf_object *parameter, bool readOnly);
    static bool transformNormalize(ddwaf_object *parameter, bool readOnly);
    static bool transformNormalizeWin(ddwaf_object *parameter, bool readOnly);
    static bool transformDecodeURL(ddwaf_object *parameter, bool readOnly, bool readIIS);
    static bool transformDecodeCSS(ddwaf_object *parameter, bool readOnly);
    static bool transformDecodeJS(ddwaf_object *parameter, bool readOnly);
    static bool transformDecodeHTML(ddwaf_object *parameter, bool readOnly);
    static bool transformDecodeBase64RFC4648(ddwaf_object *parameter, bool readOnly);
    static bool transformDecodeBase64RFC2045(ddwaf_object *parameter, bool readOnly);
    static bool transformEncodeBase64(ddwaf_object *parameter, bool readOnly);
    static bool transformCmdLine(ddwaf_object *parameter, bool readOnly);
    static bool transformRemoveComments(ddwaf_object *parameter, bool readOnly);
    static bool transformNumerize(ddwaf_object *parameter, bool readOnly);
    static bool transformUnicodeNormalize(ddwaf_object *parameter, bool readOnly);

    static bool transformURLBaseName(ddwaf_object *parameter, bool readOnly);
    static bool transformURLFilename(ddwaf_object *parameter, bool readOnly);
    static bool transformURLQueryString(ddwaf_object *parameter, bool readOnly);

public:
    static PW_TRANSFORM_ID getIDForString(std::string_view str);
    static bool transform(
        PW_TRANSFORM_ID transformID, ddwaf_object *parameter, bool readOnly = false);
    static bool doesNeedTransform(
        const std::vector<PW_TRANSFORM_ID> &transformIDs, ddwaf_object *parameter);
};
