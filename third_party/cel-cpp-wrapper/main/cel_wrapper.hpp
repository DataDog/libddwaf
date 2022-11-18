#pragma once

#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace google::api::expr::runtime {
class CelValue;
class CelExpression;
class CelExpressionBuilder;
}

using CelExpression = google::api::expr::runtime::CelExpression;
using CelExpressionBuilder = google::api::expr::runtime::CelExpressionBuilder;

typedef struct _ddwaf_object ddwaf_object;

namespace datadog::waf {

class expression_builder;

class expression {
public:
    ~expression();// { delete expr_; }
    bool eval(std::string_view key, const ddwaf_object &value);
    bool eval(std::string_view key, std::string_view value);
protected:
    friend class expression_builder;

    explicit expression(std::unique_ptr<CelExpression> &&expr);

    // Opaque pointer pointer...
    std::unique_ptr<CelExpression> *expr_{nullptr};
};

class expression_builder {
public:
    expression_builder();
    ~expression_builder();
    std::weak_ptr<expression> build(const std::string &expr_str);
protected:
    std::vector<std::shared_ptr<expression>> built_expressions_;
    // Opaque pointer pointer...
    std::unique_ptr<CelExpressionBuilder> *builder_{nullptr};
};

}
