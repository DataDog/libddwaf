// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <context.hpp>
#include <PWRet.hpp>
#include <exception.hpp>
#include <memory>
#include <mutex>
#include <ruleset_info.hpp>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include <log.hpp>

using namespace ddwaf;

#if DDWAF_COMPILE_LOG_LEVEL <= DDWAF_COMPILE_LOG_INFO
namespace
{
const char* log_level_to_str(DDWAF_LOG_LEVEL level)
{
    switch (level)
    {
        case DDWAF_LOG_TRACE:
            return "trace";
        case DDWAF_LOG_DEBUG:
            return "debug";
        case DDWAF_LOG_ERROR:
            return "error";
        case DDWAF_LOG_WARN:
            return "warn";
        case DDWAF_LOG_INFO:
            return "info";
        case DDWAF_LOG_OFF:
            break;
    }

    return "off";
}
}
#endif
// explicit instantiation declaration to suppress warning
extern "C"
{
    ddwaf_handle ddwaf_init(const ddwaf_object* rule,
                            const ddwaf_config* config, ddwaf_ruleset_info* info)
    {
        try
        {
            if (rule != nullptr)
            {
                ddwaf::ruleset_info ri(info);
                return waf::fromConfig(*rule, config, ri);
            }
        }
        catch (const std::exception& e)
        {
            DDWAF_ERROR("%s", e.what());
        }
        catch (...)
        {
            DDWAF_ERROR("unknown exception");
        }

        return nullptr;
    }

    void ddwaf_destroy(ddwaf_handle handle)
    {
        if (handle == nullptr)
        {
            return;
        }

        try
        {
            delete handle;
        }
        catch (const std::exception& e)
        {
            DDWAF_ERROR("%s", e.what());
        }
        catch (...)
        {
            DDWAF_ERROR("unknown exception");
        }
    }

    const char* const* ddwaf_required_addresses(const ddwaf_handle handle, uint32_t* size)
    {
        if (handle == nullptr)
        {
            *size = 0;
            return nullptr;
        }

        auto& addresses = handle->manifest.get_root_addresses();
        if (addresses.empty() || addresses.size() > std::numeric_limits<uint32_t>::max())
        {
            *size = 0;
            return nullptr;
        }

        *size = (uint32_t) addresses.size();
        return addresses.data();
    }

    ddwaf_context ddwaf_context_init(const ddwaf_handle handle)
    {
        ddwaf_context output = nullptr;

        try
        {
            if (handle != nullptr)
            {
                output = new ddwaf::context(handle->get_context());
            }
        }
        catch (const std::exception& e)
        {
            DDWAF_ERROR("%s", e.what());
        }
        catch (...)
        {
            DDWAF_ERROR("unknown exception");
        }
        return output;
    }

    DDWAF_RET_CODE ddwaf_run(ddwaf_context context, ddwaf_object* data,
                             ddwaf_result* result, uint64_t timeout)
    {
        if (result != nullptr)
        {
            *result = {false, nullptr, 0};
        }

        if (context == nullptr || data == nullptr)
        {
            DDWAF_WARN("Illegal WAF call: context or data was null");
            return DDWAF_ERR_INVALID_ARGUMENT;
        }
        try
        {
            optional_ref<ddwaf_result> res { std::nullopt };
            if (result != nullptr)
            {
                res = *result;
            }

            return context->run(*data, res, timeout);
        }
        catch (const std::exception& e)
        {
            // catch-all to avoid std::terminate
            DDWAF_ERROR("%s", e.what());
        }
        catch (...)
        {
            DDWAF_ERROR("unknown exception");
        }

        return DDWAF_ERR_INTERNAL;
    }

    void ddwaf_context_destroy(ddwaf_context context)
    {
        if (context == nullptr)
        {
            return;
        }

        try
        {
            delete context;
        }
        catch (const std::exception& e)
        {
            // catch-all to avoid std::terminate
            DDWAF_ERROR("%s", e.what());
        }
        catch (...)
        {
            DDWAF_ERROR("unknown exception");
        }
    }

    const char * ddwaf_get_version()
    {
        return LIBDDWAF_VERSION;
    }

    bool ddwaf_set_log_cb(ddwaf_log_cb cb, DDWAF_LOG_LEVEL min_level)
    {
        logger::init(cb, min_level);
        DDWAF_INFO("Sending log messages to binding, min level %s",
                   log_level_to_str(min_level));
        return true;
    }
}
