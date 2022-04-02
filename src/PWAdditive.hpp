// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef PWAdditive_hpp
#define PWAdditive_hpp

#include <memory>

#include <PWProcessor.hpp>
#include <PowerWAF.hpp>
#include <ddwaf.h>
#include <optional>
#include <utils.h>
#include <validator.hpp>
#include <obfuscator.hpp>

class PWAdditive
{
public:
    PWAdditive(std::shared_ptr<PowerWAF>);
    PWAdditive(const ddwaf_handle, ddwaf_object_free_fn free_fn);

    PWAdditive(const PWAdditive&) = delete;

    ~PWAdditive();

    DDWAF_RET_CODE run(ddwaf_object, optional_ref<ddwaf_result> res, uint64_t);

#ifdef TESTING
    FRIEND_TEST(TestPWProcessor, TestCache);
    FRIEND_TEST(TestPWManifest, TestUnknownArgID);
#endif
protected:
    std::shared_ptr<PowerWAF> wafReference;
    const PowerWAF* wafHandle;

    std::vector<ddwaf_object> argCache;

    ddwaf::validator object_validator;
    const ddwaf::obfuscator &event_obfuscator;
    PWRetriever retriever;
    PWProcessor processor;
    ddwaf_object_free_fn obj_free;
};

#endif /* PWAdditive_hpp */
