#include <iostream>
#include <string>

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

using namespace google;

namespace parser = google::api::expr::parser;
namespace runtime = google::api::expr::runtime;

/**
 * @enum DDWAF_OBJ_TYPE
 *
 * Specifies the type of a ddwaf::object.
 **/
typedef enum
{
    DDWAF_OBJ_INVALID     = 0,
    /** Value shall be decoded as a int64_t (or int32_t on 32bits platforms). **/
    DDWAF_OBJ_SIGNED   = 1 << 0,
    /** Value shall be decoded as a uint64_t (or uint32_t on 32bits platforms). **/
    DDWAF_OBJ_UNSIGNED = 1 << 1,
    /** Value shall be decoded as a UTF-8 string of length nbEntries. **/
    DDWAF_OBJ_STRING   = 1 << 2,
    /** Value shall be decoded as an array of ddwaf_object of length nbEntries, each item having no parameterName. **/
    DDWAF_OBJ_ARRAY    = 1 << 3,
    /** Value shall be decoded as an array of ddwaf_object of length nbEntries, each item having a parameterName. **/
    DDWAF_OBJ_MAP      = 1 << 4,

    DDWAF_OBJ_BOOL     = 1 << 5,
} DDWAF_OBJ_TYPE;

/**
 * @struct ddwaf_object
 *
 * Generic object used to pass data and rules to the WAF.
 **/
struct _ddwaf_object
{
    const char* parameterName;
    uint64_t parameterNameLength;
    // uintValue should be at least as wide as the widest type on the platform.
    union
    {
        const char* stringValue;
        uint64_t uintValue;
        int64_t intValue;
        ddwaf_object* array;
        bool boolean;
    };
    uint64_t nbEntries;
    DDWAF_OBJ_TYPE type;
};

namespace datadog::waf {

runtime::CelValue object_to_celvalue(const ddwaf_object &obj) {
    switch(obj.type) {
    case DDWAF_OBJ_BOOL:
        return runtime::CelValue::CreateBool(obj.boolean);
    case DDWAF_OBJ_SIGNED:
        return runtime::CelValue::CreateDouble(obj.intValue);
    case DDWAF_OBJ_UNSIGNED:
        return runtime::CelValue::CreateDouble(obj.uintValue);
    case DDWAF_OBJ_STRING:
        return runtime::CelValue::CreateString(new std::string{obj.stringValue, obj.nbEntries});
    case DDWAF_OBJ_ARRAY: {
          std::vector<runtime::CelValue> values;
          for (unsigned i = 0; i < obj.nbEntries; i++) {
              values.push_back(object_to_celvalue(obj.array[i]));
          }

          auto list = new runtime::ContainerBackedListImpl(values);
          return runtime::CelValue::CreateList(list);
    }
    case DDWAF_OBJ_MAP: {
        auto map = new runtime::CelMapBuilder();
        for (unsigned i = 0; i < obj.nbEntries; i++) {
            const auto &child = obj.array[i];
            auto key = runtime::CelValue::CreateString(
                    new std::string{child.parameterName, child.parameterNameLength});
            auto value =  object_to_celvalue(child);
            map->Add(key, value);
        }
        return runtime::CelValue::CreateMap(map);
    }
    case DDWAF_OBJ_INVALID:
    default:
        break;
    }

    return runtime::CelValue::CreateNull();
}

expression::expression(std::unique_ptr<CelExpression> &&expr): 
    expr_(new std::unique_ptr<CelExpression>(std::move(expr))) {}

expression::~expression() { delete expr_; }


bool expression::eval(const std::map<std::string_view, ddwaf_object> &object_map)
{
    auto &expr = *expr_;
    runtime::Activation activation;
    for (const auto &[key, value] : object_map) {
        activation.InsertValue(key.data(), object_to_celvalue(value));
    }

    protobuf::Arena arena;
    auto eval_status = expr->Evaluate(activation, &arena);
    if (!eval_status.ok()) {
        std::cerr << "Error " << eval_status.status().ToString() << std::endl;
        return false; }

    runtime::CelValue result = eval_status.value();
    if (!result.IsBool()) {
        std::cerr << "Error " << result.ErrorOrDie()->ToString() << std::endl;
        return false;
    }

    return result.BoolOrDie();
}

bool expression::eval(std::string_view key, const ddwaf_object &value) {
    auto &expr = *expr_;
    runtime::Activation activation;
    activation.InsertValue(key.data(), object_to_celvalue(value));

    protobuf::Arena arena;
    auto eval_status = expr->Evaluate(activation, &arena);
    if (!eval_status.ok()) {
        std::cerr << "Error " << eval_status.status().ToString() << std::endl;
        return false; }

    runtime::CelValue result = eval_status.value();
    if (!result.IsBool()) {
        std::cerr << "Error " << result.ErrorOrDie()->ToString() << std::endl;
        return false;
    }

    return result.BoolOrDie();
}

bool expression::eval(std::string_view key, std::string_view value) {
    auto &expr = *expr_;
    runtime::Activation activation;
    auto cvalue = runtime::CelValue::CreateString(new std::string(value));
    activation.InsertValue(key.data(), cvalue);

    protobuf::Arena arena;
    auto eval_status = expr->Evaluate(activation, &arena);
    if (!eval_status.ok()) { 
        std::cerr << "Error " << eval_status.status().ToString() << std::endl;
        return false; 
    }

    runtime::CelValue result = eval_status.value();
    if (!result.IsBool()) {
        std::cerr << "Error " << result.ErrorOrDie()->ToString() << std::endl;
        return false;
    }

    return result.BoolOrDie();
}

expression_builder::expression_builder():
    builder_(new std::unique_ptr<CelExpressionBuilder>(runtime::CreateCelExpressionBuilder({}))) {}

expression_builder::~expression_builder() { delete builder_; }

std::weak_ptr<expression> expression_builder::build(const std::string &expr_str) {
    auto &builder = *builder_;
    auto parse_status = parser::Parse(expr_str);
    if (!parse_status.ok()) {
        std::cerr << "Parsing failed " << parse_status.status().ToString() << '\n';
        throw;
    }

    auto parsed_expr = parse_status.value();
    auto status = runtime::RegisterBuiltinFunctions(builder->GetRegistry(), {});

    google::api::expr::v1alpha1::SourceInfo source_info;
    auto cel_expression_status = builder->CreateExpression(&parsed_expr.expr(), &source_info);
    if (!cel_expression_status.ok()) {
        std::cerr << "Compile error " << cel_expression_status.status().message() << '\n';
        throw;
    }

    std::shared_ptr<expression> waf_expr{new expression(std::move(cel_expression_status.value()))};
    built_expressions_.emplace_back(waf_expr);

    return waf_expr;
}
}
