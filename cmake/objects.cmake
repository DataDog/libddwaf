set(LIBDDWAF_SOURCE
    ${libddwaf_SOURCE_DIR}/src/clock.cpp
    ${libddwaf_SOURCE_DIR}/src/interface.cpp
    ${libddwaf_SOURCE_DIR}/src/context.cpp
    ${libddwaf_SOURCE_DIR}/src/context_allocator.cpp
    ${libddwaf_SOURCE_DIR}/src/event.cpp
    ${libddwaf_SOURCE_DIR}/src/object.cpp
    ${libddwaf_SOURCE_DIR}/src/object_store.cpp
    ${libddwaf_SOURCE_DIR}/src/module.cpp
    ${libddwaf_SOURCE_DIR}/src/expression.cpp
    ${libddwaf_SOURCE_DIR}/src/ruleset_info.cpp
    ${libddwaf_SOURCE_DIR}/src/ip_utils.cpp
    ${libddwaf_SOURCE_DIR}/src/iterator.cpp
    ${libddwaf_SOURCE_DIR}/src/log.cpp
    ${libddwaf_SOURCE_DIR}/src/obfuscator.cpp
    ${libddwaf_SOURCE_DIR}/src/uri_utils.cpp
    ${libddwaf_SOURCE_DIR}/src/platform.cpp
    ${libddwaf_SOURCE_DIR}/src/sha256.cpp
    ${libddwaf_SOURCE_DIR}/src/uuid.cpp
    ${libddwaf_SOURCE_DIR}/src/action_mapper.cpp
    ${libddwaf_SOURCE_DIR}/src/builder/action_mapper_builder.cpp
    ${libddwaf_SOURCE_DIR}/src/builder/matcher_builder.cpp
    ${libddwaf_SOURCE_DIR}/src/builder/module_builder.cpp
    ${libddwaf_SOURCE_DIR}/src/builder/processor_builder.cpp
    ${libddwaf_SOURCE_DIR}/src/builder/ruleset_builder.cpp
    ${libddwaf_SOURCE_DIR}/src/tokenizer/sql_base.cpp
    ${libddwaf_SOURCE_DIR}/src/tokenizer/pgsql.cpp
    ${libddwaf_SOURCE_DIR}/src/tokenizer/mysql.cpp
    ${libddwaf_SOURCE_DIR}/src/tokenizer/sqlite.cpp
    ${libddwaf_SOURCE_DIR}/src/tokenizer/generic_sql.cpp
    ${libddwaf_SOURCE_DIR}/src/tokenizer/shell.cpp
    ${libddwaf_SOURCE_DIR}/src/exclusion/input_filter.cpp
    ${libddwaf_SOURCE_DIR}/src/exclusion/object_filter.cpp
    ${libddwaf_SOURCE_DIR}/src/exclusion/rule_filter.cpp
    ${libddwaf_SOURCE_DIR}/src/configuration/common/expression_parser.cpp
    ${libddwaf_SOURCE_DIR}/src/configuration/common/matcher_parser.cpp
    ${libddwaf_SOURCE_DIR}/src/configuration/common/transformer_parser.cpp
    ${libddwaf_SOURCE_DIR}/src/configuration/common/raw_configuration.cpp
    ${libddwaf_SOURCE_DIR}/src/configuration/common/reference_parser.cpp
    ${libddwaf_SOURCE_DIR}/src/configuration/actions_parser.cpp
    ${libddwaf_SOURCE_DIR}/src/configuration/data_parser.cpp
    ${libddwaf_SOURCE_DIR}/src/configuration/exclusion_parser.cpp
    ${libddwaf_SOURCE_DIR}/src/configuration/processor_parser.cpp
    ${libddwaf_SOURCE_DIR}/src/configuration/rule_override_parser.cpp
    ${libddwaf_SOURCE_DIR}/src/configuration/rule_parser.cpp
    ${libddwaf_SOURCE_DIR}/src/configuration/legacy_rule_parser.cpp
    ${libddwaf_SOURCE_DIR}/src/configuration/scanner_parser.cpp
    ${libddwaf_SOURCE_DIR}/src/configuration/configuration_manager.cpp
    ${libddwaf_SOURCE_DIR}/src/processor/extract_schema.cpp
    ${libddwaf_SOURCE_DIR}/src/processor/fingerprint.cpp
    ${libddwaf_SOURCE_DIR}/src/condition/exists.cpp
    ${libddwaf_SOURCE_DIR}/src/condition/lfi_detector.cpp
    ${libddwaf_SOURCE_DIR}/src/condition/sqli_detector.cpp
    ${libddwaf_SOURCE_DIR}/src/condition/ssrf_detector.cpp
    ${libddwaf_SOURCE_DIR}/src/condition/scalar_condition.cpp
    ${libddwaf_SOURCE_DIR}/src/condition/shi_common.cpp
    ${libddwaf_SOURCE_DIR}/src/condition/shi_detector.cpp
    ${libddwaf_SOURCE_DIR}/src/condition/cmdi_detector.cpp
    ${libddwaf_SOURCE_DIR}/src/matcher/phrase_match.cpp
    ${libddwaf_SOURCE_DIR}/src/matcher/regex_match.cpp
    ${libddwaf_SOURCE_DIR}/src/matcher/is_sqli.cpp
    ${libddwaf_SOURCE_DIR}/src/matcher/is_xss.cpp
    ${libddwaf_SOURCE_DIR}/src/matcher/ip_match.cpp
    ${libddwaf_SOURCE_DIR}/src/matcher/exact_match.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/lowercase.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/compress_whitespace.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/normalize_path.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/manager.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/remove_nulls.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/remove_comments.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/shell_unescape.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/unicode_normalize.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/url_basename.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/url_decode.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/url_querystring.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/url_path.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/base64_decode.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/base64_encode.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/css_decode.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/html_entity_decode.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/js_decode.cpp
    ${libddwaf_SOURCE_DIR}/src/transformer/common/utf8.cpp
    ${libddwaf_SOURCE_DIR}/src/libcxx-compat/monotonic_buffer_resource.cpp
    ${libddwaf_SOURCE_DIR}/src/vendor/fmt/format.cc
    ${libddwaf_SOURCE_DIR}/src/vendor/radixlib/radixlib.c
    ${libddwaf_SOURCE_DIR}/src/vendor/lua-aho-corasick/ac_fast.cxx
    ${libddwaf_SOURCE_DIR}/src/vendor/lua-aho-corasick/ac_slow.cxx
    ${libddwaf_SOURCE_DIR}/src/vendor/lua-aho-corasick/ac.cxx
    ${libddwaf_SOURCE_DIR}/src/vendor/libinjection/src/xss.c
    ${libddwaf_SOURCE_DIR}/src/vendor/libinjection/src/libinjection_html5.c
    ${libddwaf_SOURCE_DIR}/src/vendor/libinjection/src/libinjection_xss.c
    ${libddwaf_SOURCE_DIR}/src/vendor/libinjection/src/libinjection_sqli.c
    ${libddwaf_SOURCE_DIR}/src/vendor/utf8proc/utf8proc.c
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/bitstate.cc
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/compile.cc
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/dfa.cc
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/nfa.cc
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/onepass.cc
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/parse.cc
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/perl_groups.cc
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/prog.cc
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/re2.cc
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/regexp.cc
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/simplify.cc
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/stringpiece.cc
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/tostring.cc
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/unicode_casefold.cc
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/unicode_groups.cc
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/util/rune.cc
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/util/strutil.cc
)

set(LIBDDWAF_PUBLIC_INCLUDES ${libddwaf_SOURCE_DIR}/include)

set(LIBDDWAF_PRIVATE_INCLUDES
    ${libddwaf_SOURCE_DIR}/src
    ${libddwaf_SOURCE_DIR}/src/vendor
    ${libddwaf_SOURCE_DIR}/src/vendor/libinjection/src/
    ${libddwaf_SOURCE_DIR}/src/vendor/radixlib/
    ${libddwaf_SOURCE_DIR}/src/vendor/lua-aho-corasick/
    ${libddwaf_SOURCE_DIR}/src/vendor/utf8proc/
    ${libddwaf_SOURCE_DIR}/src/vendor/re2/
)

function(gen_objects target_name)
    add_library(${target_name} OBJECT ${LIBDDWAF_SOURCE} )

    # we need PIC even on the static lib,as it's expected to be linked in a shared lib
    set_target_properties(${target_name} PROPERTIES
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
        POSITION_INDEPENDENT_CODE 1)

    if(NOT STDLIB_MAP_RECURSIVE)
        target_compile_definitions(${target_name} PRIVATE HAS_NONRECURSIVE_UNORDERED_MAP)
    endif()

    if (LIBDDWAF_VECTORIZED_TRANSFORMERS)
        target_compile_definitions(${target_name} PRIVATE LIBDDWAF_VECTORIZED_TRANSFORMERS)
    endif()

    target_include_directories(${target_name} PUBLIC ${LIBDDWAF_PUBLIC_INCLUDES})
    target_include_directories(${target_name} PRIVATE ${LIBDDWAF_PRIVATE_INCLUDES})

    target_compile_definitions(${target_name} PRIVATE UTF8PROC_STATIC=1)
    if (MSVC)
        target_compile_definitions(${target_name} PRIVATE NOMINMAX)
    endif()

    target_link_libraries(${target_name}
        PRIVATE ${LIBDDWAF_PRIVATE_LIBRARIES}
        INTERFACE ${LIBDDWAF_INTERFACE_LIBRARIES})
endfunction()

gen_objects(libddwaf_objects)
add_library(libddwaf_shared_objects ALIAS libddwaf_objects)

if (LIBDDWAF_ENABLE_LTO)
    target_compile_options(libddwaf_objects PRIVATE -flto)

    # If LTO is enabled, we can't use objects with -flto to generate a static
    # library, as the contents of the object is an intermediate representation.
    # This can be solved (in theory) using -ffat-lto-objects, but clang < 18
    # doesn't currently support this, so we need to generate separate objects
    # specifically for the static build.
    gen_objects(libddwaf_static_objects)
else()
    add_library(libddwaf_static_objects ALIAS libddwaf_objects)
endif()

if(NOT MSVC AND LIBDDWAF_TESTING AND LIBDDWAF_TEST_COVERAGE)
    target_compile_options(libddwaf_objects PRIVATE --coverage)
endif()


