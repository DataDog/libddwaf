// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/sqli_detector.hpp"
#include "exception.hpp"
#include "iterator.hpp"
#include "regex_utils.hpp"
#include "sql_tokenizer.hpp"
#include "utils.hpp"

#include <iostream>
#include <type_traits>
#include <variant>

using namespace std::literals;

namespace ddwaf {

namespace internal {
namespace {

constexpr auto &npos = std::string_view::npos;
constexpr std::size_t min_token_count = 4;

// Relevant regexes
auto or_operator_regex = regex_init(R"((?i)(?:OR|XOR|\|\|))");
auto order_sequence_regex = regex_init(R"((?i)(?:ASC|DESC))");
auto limit_offset_regex = regex_init(R"((?i)(?:LIMIT|OFFSET))");

enum class sqli_error {
    none,
    invalid_sql,
};

using matched_param = std::pair<std::string, std::vector<std::string>>;
using sqli_result = std::variant<sqli_error, matched_param, std::monostate>;

bool is_identifier(sql_token_type type)
{
    return type == sql_token_type::identifier || type == sql_token_type::back_quoted_string ||
           type == sql_token_type::double_quoted_string ||
           type == sql_token_type::single_quoted_string;
}

} // namespace

bool is_query_comment(std::span<sql_token> tokens)
{
    /* We want to consider as malicious user-injected comments, even if they
     * are below our 3 tokens limit.
     *
     * Some examples of comments:
     *
     *     SELECT * FROM t WHERE id =123 # AND pwd = HASH(pwd)
     *                               \----/
     *                           injected string
     *     SELECT * FROM t WHERE id =1-- AND pwd = HASH(pwd)
     *                              \---/
     *                            injected string
     */
    for (std::size_t i = 1; i < tokens.size(); ++i) {
        if (tokens[i].type == sql_token_type::eol_comment) {
            return true;
        }
    }

    // TODO: the slash star comment that could be injected from 2 distinct
    // places:
    //
    //     SELECT * FROM t WHERE id =X AND pwd = HASH(pwd) AND country=Y
    //
    // Could be injected in:
    //
    //   SELECT * FROM t WHERE id =1 /* AND pwd = HASH(pwd) AND country=*/
    //
    // So a part of the query is escaped.

    return false;
}

bool is_where_tautology(const std::vector<sql_token> &resource_tokens,
    std::span<sql_token> param_tokens, std::size_t param_tokens_begin)
{
    /* We want to consider as malicious the injections of 3 tokens (4 tokens
     * are already considered malicious) such as:
     *
     * SELECT * FROM table WHERE id=1 OR 1 AND password = HASH(password)
     *                              \----/
     *                          injected string
     *
     * https://dev.mysql.com/doc/refman/5.7/en/expressions.html
     *
     * Look if user parameters are defining a tautology or pseudo-tautology. A
     * pseudo tautology is a tautology likely to be true, e.g. `OR id` that is
     * only false if id = 0.
     */
    if (param_tokens.size() != 3 || param_tokens_begin == 0) {
        return false;
    }

    // Ensure we are in a where clause
    // This heuristic isn't perfect, and would trigger if there is any `where`
    // before the suspected tautology.
    bool where_found = false;
    for (std::size_t i = 0; i < param_tokens_begin; ++i) {
        const auto &token = resource_tokens[i];
        if (token.type == sql_token_type::command && string_iequals(token.str, "where")) {
            where_found = true;
            break;
        }
    }

    if (!where_found) {
        return false;
    }

    /* We can have two kinds of tautologies:
     *
     * The first is the usual one where `OR 1` is added to make the condition always correct.
     * The second one is where multi-parameter injection added a whole `' OR '1' = '1'`.
     * We may not be able to detect `OR` but we still want to look for `'1' = '1' where the middle
     * token is `=`. This specific case is exploited in the tutorial of webgoat.
     */

    // We do the cheaper test first

    // Is the operator in the middle a command (OR) or an operator (=, ||...)
    auto middle_token = param_tokens[1];
    if (middle_token.type != sql_token_type::binary_operator) {
        return regex_match(*or_operator_regex, middle_token.str);
    }

    // Okay, if we have a `X = Y` pattern, let's make sure X and Y are similar
    //  * The test is done the wrong way around because checking the kind is cheaper
    //  * The equality check need to be broad enough to match =/!=
    if (param_tokens[0].type != param_tokens[2].type && middle_token.str.find('=') != npos) {
        // There is *one* edge case where this still may be a tautology: when both are compatible
        // data types ('1' = 1)
        //   * Basically, if neither is a command or identifier, it's likely a tautology
        return param_tokens[0].type != sql_token_type::command &&
               param_tokens[0].type != sql_token_type::identifier &&
               param_tokens[2].type != sql_token_type::identifier &&
               param_tokens[2].type != sql_token_type::command;
    }

    return true;
}

bool has_order_by_structure(std::span<sql_token> tokens)
{
    enum class order_by_state {
        invalid,
        begin,
        table_or_column_name,
        column_name,
        column_index,
        limit_or_offset_value,
        limit_or_offset,
        asc_or_desc,
        comma,
        dot,
        end,
    };

    auto current_state = order_by_state::begin;
    auto current_token = tokens.begin();
    while (current_state != order_by_state::end) {
        auto next_state = order_by_state::invalid;

        // Find the next state
        switch (current_state) {
        case order_by_state::begin:
        case order_by_state::comma:
            if (current_token == tokens.end()) {
                // Not a valid state
                break;
            }

            // The first token can either be a column index or a table or column
            // name, we allow a name to be a quoted string or a non-quoted
            // non-reserved identifier. We can't distinguish between a table name
            // or a column name.
            //
            // Similarly a comma implies another order, so it can either be a
            // column index or a table / column name
            if (current_token->type == sql_token_type::number) {
                next_state = order_by_state::column_index;
            } else if (is_identifier(current_token->type)) {
                next_state = order_by_state::table_or_column_name;
            }
            break;
        case order_by_state::table_or_column_name:
            if (current_token == tokens.end()) {
                // The clause can terminate here
                next_state = order_by_state::end;
                break;
            }

            // A table or column name can be followed by a dot, a comma, an
            // ordinal keyword (ASC, DESC) or LIMIT / OFFSET.
            if (current_token->type == sql_token_type::dot) {
                next_state = order_by_state::dot;
            } else if (current_token->type == sql_token_type::comma) {
                next_state = order_by_state::comma;
            } else if (current_token->type == sql_token_type::command) {
                if (regex_match(*order_sequence_regex, current_token->str)) {
                    next_state = order_by_state::asc_or_desc;
                } else if (regex_match(*limit_offset_regex, current_token->str)) {
                    next_state = order_by_state::limit_or_offset;
                }
            }
            break;
        case order_by_state::column_index:
        case order_by_state::column_name:
            if (current_token == tokens.end()) {
                // The clause can terminate here
                next_state = order_by_state::end;
                break;
            }

            // A column name or index can only be followed by a comma, an
            // ordinal keyword (ASC, DESC) or LIMIT / OFFSET
            if (current_token->type == sql_token_type::comma) {
                next_state = order_by_state::comma;
            } else if (current_token->type == sql_token_type::command) {
                if (regex_match(*order_sequence_regex, current_token->str)) {
                    next_state = order_by_state::asc_or_desc;
                } else if (regex_match(*limit_offset_regex, current_token->str)) {
                    next_state = order_by_state::limit_or_offset;
                }
            }
            break;
        case order_by_state::limit_or_offset_value:
            if (current_token == tokens.end()) {
                // The clause can terminate here
                next_state = order_by_state::end;
                break;
            }

            // An offset value can only be followed by another offset or limit
            // keyword, otherwise the end state is covered above
            if (current_token->type == sql_token_type::command &&
                regex_match(*limit_offset_regex, current_token->str)) {
                next_state = order_by_state::limit_or_offset;
            }

            break;
        case order_by_state::limit_or_offset:
            if (current_token == tokens.end()) {
                // Not a valid state
                break;
            }

            // The limit or offset must be followed by a numerical value
            if (current_token->type == sql_token_type::number) {
                next_state = order_by_state::limit_or_offset_value;
            }

            break;
        case order_by_state::asc_or_desc:
            if (current_token == tokens.end()) {
                // The clause can terminate here
                next_state = order_by_state::end;
                break;
            }

            // After ASC / DESC we can have another order clause, separated by a
            // comma, or LIMIT / OFFSET.
            if (current_token->type == sql_token_type::comma) {
                next_state = order_by_state::comma;
            } else if (current_token->type == sql_token_type::command &&
                       regex_match(*limit_offset_regex, current_token->str)) {
                next_state = order_by_state::limit_or_offset;
            }

            break;
        case order_by_state::dot:
            if (current_token == tokens.end()) {
                // Not a valid state
                break;
            }

            // A dot is only used as part of the table.column notation, so the
            // next token must be the column name
            if (is_identifier(current_token->type)) {
                next_state = order_by_state::column_name;
            }
            break;
        default:
            // Unreachable
            return false;
        }

        if (next_state == order_by_state::invalid) {
            return false;
        }

        current_state = next_state;
        current_token++;
    }

    return true;
}

bool is_benign_order_by_clause(const std::vector<sql_token> &resource_tokens,
    std::span<sql_token> param_tokens, std::size_t param_tokens_begin)
{
    if (param_tokens_begin < 1) {
        return false;
    }

    std::string_view order_by = resource_tokens[param_tokens_begin - 1].str;

    if (!string_iequals(order_by, "order by")) {
        return false;
    }

    return has_order_by_structure(param_tokens);
}

bool contains_harmful_tokens(std::span<sql_token> tokens)
{
    if (tokens.size() < min_token_count) {
        return false;
    }

    for (const auto &token : tokens) {
        auto t = token.type;
        if (t != sql_token_type::comma && t != sql_token_type::parenthesis_close &&
            t != sql_token_type::parenthesis_open && t != sql_token_type::number &&
            t != sql_token_type::single_quoted_string &&
            t != sql_token_type::double_quoted_string) {
            return true;
        }
    }
    return false;
}

std::pair<std::span<sql_token>, std::size_t> get_consecutive_tokens(
    std::vector<sql_token> &resource_tokens, std::size_t begin, std::size_t end)
{
    std::size_t index_begin = std::numeric_limits<std::size_t>::max();
    std::size_t index_end = 0;
    for (std::size_t i = 0; i < resource_tokens.size(); ++i) {
        const auto &rtoken = resource_tokens[i];
        auto rtoken_end = rtoken.index + rtoken.str.size();
        if (rtoken_end > begin) {
            if (rtoken.index <= end) {
                if (i < index_begin) {
                    index_begin = i;
                }

                if (i > index_end || i == (resource_tokens.size() - 1)) {
                    index_end = i;
                }
            } else {
                break;
            }
        }
    }

    if (index_begin > index_end) {
        return {};
    }

    return {std::span<sql_token>{&resource_tokens[index_begin], index_end - index_begin + 1},
        index_begin};
}

namespace {

sqli_result sqli_impl(std::string_view resource, std::vector<sql_token> &resource_tokens,
    const ddwaf_object &params, sql_flavour /*flavour*/,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer &deadline)
{
    static constexpr std::size_t min_str_len = 3;

    object::kv_iterator it(&params, {}, objects_excluded, limits);
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const ddwaf_object &param = *(*it);
        if (param.type != DDWAF_OBJ_STRING || param.nbEntries < min_str_len) {
            continue;
        }

        std::string_view value{param.stringValue, static_cast<std::size_t>(param.nbEntries)};
        std::size_t param_index = resource.find(value);
        if (param_index == npos) {
            continue;
        }

        if (resource_tokens.empty()) {
            // We found a potential injection, so we tokenize the resource which will
            // then be used by all remaining calls to this function
            sql_tokenizer tokenizer(resource);
            resource_tokens = tokenizer.tokenize();
            if (resource_tokens.empty()) {
                return sqli_error::invalid_sql;
            }
        }

        auto [param_tokens, param_tokens_begin] =
            get_consecutive_tokens(resource_tokens, param_index, param_index + value.size());
        if (param_tokens.empty()) {
            continue;
        }

        /*                for (auto token : param_tokens) {*/
        /*std::cout << "Token: " << token.type << " - " << token.str << '\n';*/
        /*}*/
        /*bool harmful = contains_harmful_tokens(param_tokens);*/
        /*DDWAF_DEBUG("Contains harmful {}", harmful);*/
        /*bool benign_order_by =*/
        /*!is_benign_order_by_clause(resource_tokens, param_tokens, param_tokens_begin);*/
        /*DDWAF_DEBUG("Is Benign order by {}", benign_order_by);*/
        /*bool tautology = is_where_tautology(resource_tokens, param_tokens, param_tokens_begin);*/
        /*DDWAF_DEBUG("Is where tautology {}", tautology);*/
        /*bool query_comment = is_query_comment(param_tokens);*/
        /*DDWAF_DEBUG("Query comment {}", query_comment);*/

        if ((contains_harmful_tokens(param_tokens) &&
                !is_benign_order_by_clause(resource_tokens, param_tokens, param_tokens_begin)) ||
            (param_tokens.size() < min_token_count &&
                (is_where_tautology(resource_tokens, param_tokens, param_tokens_begin) ||
                    is_query_comment(param_tokens)))) {
            return matched_param{std::string(value), it.get_current_path()};
        }
    }

    return {};
}

} // namespace

} // namespace internal

[[nodiscard]] eval_result sqli_detector::eval_impl(const unary_argument<std::string_view> &sql,
    const variadic_argument<const ddwaf_object *> &params,
    const unary_argument<std::string_view> &db_type, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, ddwaf::timer &deadline) const
{
    auto flavour = sql_flavour_from_type(db_type.value);

    std::vector<sql_token> resource_tokens;

    for (const auto &param : params) {
        auto res = internal::sqli_impl(
            sql.value, resource_tokens, *param.value, flavour, objects_excluded, limits_, deadline);
        if (std::holds_alternative<internal::matched_param>(res)) {
            std::vector<std::string> sql_kp{sql.key_path.begin(), sql.key_path.end()};
            bool ephemeral = sql.ephemeral || param.ephemeral;

            // TODO remove literals from resource
            auto &[highlight, param_kp] = std::get<internal::matched_param>(res);
            cache.match =
                condition_match{{{"resource"sv, std::string{sql.value}, sql.address, sql_kp},
                                    {"params"sv, highlight, param.address, param_kp},
                                    {"db_type"sv, std::string{db_type.value}, db_type.address, {}}},
                    {std::move(highlight)}, "sqli_detector", {}, ephemeral};

            return {true, sql.ephemeral || param.ephemeral};
        }

        if (std::holds_alternative<std::monostate>(res)) {
            continue;
        }

        if (std::holds_alternative<internal::sqli_error>(res)) {
            // The only error for now is returned when the resource couldn't be
            // parsed, we don't do anything specific for now other than stopping
            // the evaluation of the parameters
            break;
        }
    }

    return {};
}

} // namespace ddwaf