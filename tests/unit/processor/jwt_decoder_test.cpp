// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"
#include "processor/jwt_decoder.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestJwtDecoder, Basic)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "authorization",
        ddwaf_object_string(
            &tmp, "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9."
                  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUx"
                  "NjIzOTAyMn0.o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-"
                  "8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_"
                  "61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_"
                  "Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-"
                  "qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJh"
                  "h994RAPzCG0hmQ"));

    jwt_decoder gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] = gen.eval_impl({{}, {}, false, &headers}, cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_MAP);
    EXPECT_EQ(attr, object_store::attribute::none);

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

} // namespace
