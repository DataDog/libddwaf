// CEL -- BEGIN
#include "eval/public/activation.h"
#include "eval/public/activation_bind_helper.h"
#include "eval/public/builtin_func_registrar.h"
#include "eval/public/cel_expr_builder_factory.h"
#include "eval/public/structs/cel_proto_wrapper.h"
#include "eval/public/containers/field_access.h"
#include "eval/public/containers/container_backed_list_impl.h"
#include "eval/public/containers/container_backed_map_impl.h"
#include "parser/parser.h"
// CEL -- END

#include "cel_wrapper.hpp"

using CelValue = google::api::expr::runtime::CelValue;

int main()
{
    std::string rule = R"(server.path == "/google-cel-cpp")";

    datadog::waf::expression_builder builder;
    auto expr = builder.build(rule);

    CelValue key = CelValue::CreateString(new std::string("path"));
    CelValue value = CelValue::CreateString(new std::string("/google-cel-cpp"));

    auto map_builder = new google::api::expr::runtime::CelMapBuilder();
    map_builder->Add(key, value);

    {
        auto shared_expr = expr.lock();
        std::cout << std::boolalpha
                  << shared_expr->eval("server", CelValue::CreateMap(map_builder)) << '\n';
    }

    return 0;
}
