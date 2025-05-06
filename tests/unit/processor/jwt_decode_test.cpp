// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"
#include "processor/jwt_decode.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestJwtDecoder, Basic)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "authorization",
        ddwaf_object_string(&tmp,
            "Bearer eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUx"
            "NjIzOTAyMn0.o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-"
            "8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_"
            "61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_"
            "Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-"
            "qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJh"
            "h994RAPzCG0hmQ"));

    jwt_decode gen{"id", {}, {}, false, true};

    std::vector<std::string> key_path{"authorization"};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] =
        gen.eval_impl({.address = {}, .key_path = key_path, .ephemeral = false, .value = &headers},
            cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_MAP);
    EXPECT_EQ(attr, object_store::attribute::none);

    EXPECT_JSON(output,
        R"({"header":{"alg":"RS384","typ":"JWT"},"payload":{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022},"signature":{"available":true}})");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestJwtDecoder, KeyPathLeadsToSingleValueArray)
{
    ddwaf_object tmp;

    ddwaf_object array;
    ddwaf_object_array(&array);

    ddwaf_object_array_add(&array,
        ddwaf_object_string(&tmp,
            "Bearer eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUx"
            "NjIzOTAyMn0.o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-"
            "8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_"
            "61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_"
            "Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-"
            "qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJh"
            "h994RAPzCG0hmQ"));

    ddwaf_object headers;
    ddwaf_object_map(&headers);

    ddwaf_object_map_add(&headers, "authorization", &array);
    jwt_decode gen{"id", {}, {}, false, true};

    std::vector<std::string> key_path{"authorization"};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] =
        gen.eval_impl({.address = {}, .key_path = key_path, .ephemeral = false, .value = &headers},
            cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_MAP);
    EXPECT_EQ(attr, object_store::attribute::none);

    EXPECT_JSON(output,
        R"({"header":{"alg":"RS384","typ":"JWT"},"payload":{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022},"signature":{"available":true}})");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestJwtDecoder, KeyPathLeadsToValidMultiValueArray)
{
    ddwaf_object tmp;

    ddwaf_object array;
    ddwaf_object_array(&array);

    ddwaf_object_array_add(&array,
        ddwaf_object_string(&tmp,
            "Bearer eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUx"
            "NjIzOTAyMn0.o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-"
            "8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_"
            "61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_"
            "Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-"
            "qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJh"
            "h994RAPzCG0hmQ"));
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "Arachni"));

    ddwaf_object headers;
    ddwaf_object_map(&headers);

    ddwaf_object_map_add(&headers, "authorization", &array);
    jwt_decode gen{"id", {}, {}, false, true};

    std::vector<std::string> key_path{"authorization"};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] =
        gen.eval_impl({.address = {}, .key_path = key_path, .ephemeral = false, .value = &headers},
            cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_MAP);
    EXPECT_EQ(attr, object_store::attribute::none);

    EXPECT_JSON(output,
        R"({"header":{"alg":"RS384","typ":"JWT"},"payload":{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022},"signature":{"available":true}})");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestJwtDecoder, KeyPathLeadsToInvalidMultiValueArray)
{
    ddwaf_object tmp;

    ddwaf_object array;
    ddwaf_object_array(&array);

    // Even though the token is there, we only take the first element of arrays as we're trying
    // to account for the serialisation not perform a JWT search.
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "Arachni"));
    ddwaf_object_array_add(&array,
        ddwaf_object_string(&tmp,
            "Bearer eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUx"
            "NjIzOTAyMn0.o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-"
            "8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_"
            "61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_"
            "Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-"
            "qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJh"
            "h994RAPzCG0hmQ"));

    ddwaf_object headers;
    ddwaf_object_map(&headers);

    ddwaf_object_map_add(&headers, "authorization", &array);
    jwt_decode gen{"id", {}, {}, false, true};

    std::vector<std::string> key_path{"authorization"};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] =
        gen.eval_impl({.address = {}, .key_path = key_path, .ephemeral = false, .value = &headers},
            cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_INVALID);

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestJwtDecoder, MissingKeypath)
{
    ddwaf_object headers;
    ddwaf_object_string(&headers,
        "Bearer eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUx"
        "NjIzOTAyMn0.o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-"
        "8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_"
        "61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_"
        "Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-"
        "qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJh"
        "h994RAPzCG0hmQ");

    jwt_decode gen{"id", {}, {}, false, true};

    std::vector<std::string> key_path{"authorization"};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] =
        gen.eval_impl({.address = {}, .key_path = key_path, .ephemeral = false, .value = &headers},
            cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_INVALID);

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestJwtDecoder, EmptyHeader)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "authorization",
        ddwaf_object_string(&tmp,
            "Bearer ."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUx"
            "NjIzOTAyMn0.o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-"
            "8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_"
            "61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_"
            "Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-"
            "qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJh"
            "h994RAPzCG0hmQ"));

    jwt_decode gen{"id", {}, {}, false, true};

    std::vector<std::string> key_path{"authorization"};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] =
        gen.eval_impl({.address = {}, .key_path = key_path, .ephemeral = false, .value = &headers},
            cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_MAP);
    EXPECT_EQ(attr, object_store::attribute::none);

    EXPECT_JSON(output,
        R"({"header":null,"payload":{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022},"signature":{"available":true}})");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestJwtDecoder, EmptyPayload)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "authorization",
        ddwaf_object_string(&tmp,
            "Bearer eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9."
            ".o1hC1xYbJolSyh0-bOY230w22zEQSk5TiBfc-OCvtpI2JtYlW-23-"
            "8B48NpATozzMHn0j3rE0xVUldxShzy0xeJ7vYAccVXu2Gs9rnTVqouc-UZu_wJHkZiKBL67j8_"
            "61L6SXswzPAQu4kVDwAefGf5hyYBUM-80vYZwWPEpLI8K4yCBsF6I9N1yQaZAJmkMp_"
            "Iw371Menae4Mp4JusvBJS-s6LrmG2QbiZaFaxVJiW8KlUkWyUCns8-"
            "qFl5OMeYlgGFsyvvSHvXCzQrsEXqyCdS4tQJd73ayYA4SPtCb9clz76N1zE5WsV4Z0BYrxeb77oA7jJh"
            "h994RAPzCG0hmQ"));

    jwt_decode gen{"id", {}, {}, false, true};

    std::vector<std::string> key_path{"authorization"};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] =
        gen.eval_impl({.address = {}, .key_path = key_path, .ephemeral = false, .value = &headers},
            cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_MAP);
    EXPECT_EQ(attr, object_store::attribute::none);

    EXPECT_JSON(output,
        R"({"header":{"alg":"RS384","typ":"JWT"},"payload":null,"signature":{"available":true}})");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestJwtDecoder, LargePayloadBeyondLimit)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "authorization",
        ddwaf_object_string(&tmp,
            "Bearer "
            "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9."
            "eyJrZXlfMCI6eyJrZXlfMSI6eyJrZXlfMiI6eyJrZXlfMyI6eyJrZXlfNCI6eyJrZXlfNSI6eyJrZXlfNiI6ey"
            "JrZXlfNyI6eyJrZXlfOCI6eyJrZXlfOSI6eyJrZXlfMTAiOnsia2V5XzExIjp7ImtleV8xMiI6eyJrZXlfMyI6"
            "eyJrZXlfNCI6eyJrZXlfNSI6eyJrZXlfNiI6eyJrZXlfNyI6eyJrZXlfOCI6eyJrZXlfOSI6WyJ2YWx1ZV8wIi"
            "widmFsdWVfMSIsInZhbHVlXzIiXX19fX19fX19fX19fX19fX19fX19Cg.VGhpcyBpcyBhIHNpZ25hdHVyZQ"));

    jwt_decode gen{"id", {}, {}, false, true};

    std::vector<std::string> key_path{"authorization"};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] =
        gen.eval_impl({.address = {}, .key_path = key_path, .ephemeral = false, .value = &headers},
            cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_MAP);
    EXPECT_EQ(attr, object_store::attribute::none);

    EXPECT_JSON(output,
        R"({"header":{"alg":"RS384","typ":"JWT"},"payload":{"key_0":{"key_1":{"key_2":{"key_3":{"key_4":{"key_5":{"key_6":{"key_7":{"key_8":{"key_9":{"key_10":{"key_11":{"key_12":{"key_3":{"key_4":{"key_5":{"key_6":{"key_7":{"key_8":{"key_9":[]}}}}}}}}}}}}}}}}}}}},"signature":{"available":true}})");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestJwtDecoder, NoSignature)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "authorization",
        ddwaf_object_string(&tmp,
            "Bearer "
            "eyJhbGciOiJub25lIn0."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUx"
            "NjIzOTAyMiwicm9sZXMiOlsiYWRtaW4iLCIxODM5MDIxZCIsICJ-fiJdfQo."));

    jwt_decode gen{"id", {}, {}, false, true};

    std::vector<std::string> key_path{"authorization"};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] =
        gen.eval_impl({.address = {}, .key_path = key_path, .ephemeral = false, .value = &headers},
            cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_MAP);
    EXPECT_EQ(attr, object_store::attribute::none);

    EXPECT_JSON(output,
        R"({"header":{"alg":"none"},"payload":{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022,"roles":["admin","1839021d", "~~"]},"signature":{"available":false}})");

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);
}

TEST(TestJwtDecoder, NoPayloadNoSignatureMissingDelim)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "authorization",
        ddwaf_object_string(&tmp, "Bearer eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9."));

    jwt_decode gen{"id", {}, {}, false, true};

    std::vector<std::string> key_path{"authorization"};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] =
        gen.eval_impl({.address = {}, .key_path = key_path, .ephemeral = false, .value = &headers},
            cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_INVALID);
    EXPECT_EQ(attr, object_store::attribute::none);
    ddwaf_object_free(&headers);
}

TEST(TestJwtDecoder, NoPayloadNoSignatureMissingAllDelim)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "authorization",
        ddwaf_object_string(&tmp, "Bearer eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9"));

    jwt_decode gen{"id", {}, {}, false, true};

    std::vector<std::string> key_path{"authorization"};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] =
        gen.eval_impl({.address = {}, .key_path = key_path, .ephemeral = false, .value = &headers},
            cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_INVALID);
    EXPECT_EQ(attr, object_store::attribute::none);
    ddwaf_object_free(&headers);
}

TEST(TestJwtDecoder, NoSignatureNoDelim)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "authorization",
        ddwaf_object_string(&tmp,
            "Bearer "
            "eyJhbGciOiJub25lIn0."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUx"
            "NjIzOTAyMiwicm9sZXMiOlsiYWRtaW4iLCIxODM5MDIxZCIsICJ-fiJdfQo"));

    jwt_decode gen{"id", {}, {}, false, true};

    std::vector<std::string> key_path{"authorization"};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto [output, attr] =
        gen.eval_impl({.address = {}, .key_path = key_path, .ephemeral = false, .value = &headers},
            cache, deadline);
    EXPECT_EQ(output.type, DDWAF_OBJ_INVALID);
    EXPECT_EQ(attr, object_store::attribute::none);
    ddwaf_object_free(&headers);
}

} // namespace
