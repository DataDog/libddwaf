// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/lfi_detector.hpp"
#include "test_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

template <typename... Args> std::vector<parameter_definition> gen_param_def(Args... addresses)
{
    return {{{{std::string{addresses}, get_target_index(addresses)}}}...};
}

TEST(TestLFIDetector, Basic)
{
    lfi_detector cond{{gen_param_def("server.io.fs.file", "server.request.query")}};

    auto input = yaml_to_object(R"({
        server.io.fs.file: documents/../../../../../../../../../etc/passwd,
        server.request.query: [
            ../../../../../../../../../etc/passwd
        ]})");
    object_store store;
    store.insert(input);

    ddwaf::timer deadline{2s};
    condition_cache cache;
    auto res = cond.eval(cache, store, {}, {}, deadline);
    EXPECT_TRUE(res.outcome);

    EXPECT_TRUE(cache.match);
    EXPECT_STRV(cache.match->args[0].address, "server.io.fs.file");
    EXPECT_STR(cache.match->args[0].resolved, "documents/../../../../../../../../../etc/passwd");
    EXPECT_STRV(cache.match->args[1].address, "server.request.query");
    EXPECT_STR(cache.match->args[1].resolved, "../../../../../../../../../etc/passwd");

    EXPECT_STR(cache.match->highlights[0], "../../../../../../../../../etc/passwd");
}

/*    var input = ['documents/../../../../../../../../../etc/passwd', { params: { documentName:
 * '../../../../../../../../../etc/passwd' } }];*/

/*input = ['imgs/../secret.yml', { params: { documentName: '../secret.yml' } }];*/

/*input = ['/etc/password', { params: { documentName: '/etc/password' } }];*/
/*    var input = ['documents/../../../../../../../../../etc/passwd', { params: { documentName:
 * 'etc/passwd' } }];*/
/*assert.deepEqual(cb.apply(null, input), null);*/

/*// Should detect only end of file*/
/*assert.deepEqual(cb('/home/my/documents/pony.txt', { params: { documentName: '/home/my/documents/'
 * } }), null);*/
/*assert.deepEqual(cb('a/etc/password', { params: { documentName: 'a/etc/password' } }), null);*/

/*assert.deepEqual(cb('documents/pony.txt', { params: { documentName: 'my/documents/pony.txt' } }),
 * null);*/
/*assert.deepEqual(cb('XXX/YYY/documents/pony.txt', { params: { documentName: 'documents/pony.txt' }
 * }), null);*/
/*assert.deepEqual(cb('documents/unicorn', { params: { documentName: 'pony.txt' } }), null);*/
/*assert.deepEqual(cb('documents/unicorn.jp', { params: { documentName: 'pony.jp' } }), null);*/
} // namespace
