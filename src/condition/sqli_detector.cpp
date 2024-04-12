// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/sqli_detector.hpp"
#include "exception.hpp"
#include "iterator.hpp"
#include "platform.hpp"
#include "sql_tokenizer.hpp"
#include "utils.hpp"

#include <iostream>
#include <type_traits>
#include <variant>

using namespace std::literals;

namespace ddwaf {

namespace {

constexpr auto &npos = std::string_view::npos;
constexpr std::size_t min_token_count = 4;

enum class sqli_error {
    none,
    invalid_sql,
};

using matched_param = std::pair<std::string, std::vector<std::string>>;
using sqli_result = std::variant<sqli_error, matched_param, std::monostate>;

template <typename State, typename Metadata>
    requires std::is_enum_v<State>
class simple_fsm {
public:
    using state_table_type = std::unordered_map<State, std::vector<State>>;
    using graph_node_type = std::pair<State, std::reference_wrapper<Metadata>>;
    using graph_type = std::unordered_map<State, std::vector<graph_node_type>>;

    simple_fsm(std::unordered_map<State, Metadata> state_metadata, const state_table_type &table)
        : state_metadata_(std::move(state_metadata))
    {
        graph_.reserve(table.size());
        for (auto [state, next_set] : table) {
            std::vector<graph_node_type> state_metadata_vec;
            state_metadata_vec.reserve(next_set.size());

            for (auto next_state : next_set) {
                auto it = state_metadata_.find(next_state);
                if (it == state_metadata_.end()) {
                    throw std::invalid_argument("unknown state found in state table");
                }
                state_metadata_vec.emplace_back(next_state, it->second);
            }

            graph_.emplace(state, std::move(state_metadata_vec));
        }
    }

    template <typename T, typename Comparator>
    bool evaluate(const std::span<T> &tokens, const Comparator &comp) const
    {
        State current_state = State::Begin;
        auto current_token = tokens.begin();

        while (current_state != State::End) {
            auto it = graph_.find(current_state);
            if (it == graph_.end()) {
                // Should this ever happen?
                throw std::runtime_error("unknown state in graph");
            }

            current_state = State::Invalid;
             //std::cout << "Current token: " << current_token->str << std::endl;
            for (const auto &[next_state, metadata] : it->second) {
                if (next_state == State::End) {
                    if (current_token == tokens.end()) {
                        current_state = next_state;
                    } else {
                        continue;
                    }
                }

                if (comp(metadata, *current_token)) {
                     //std::cout << "State found: " << (int)next_state << " ? " << (int)State::End << std::endl;
                    current_state = next_state;
                    current_token++;
                    break;
                }
            }

            if (current_state == State::Invalid) {
                //std::cout << "State false!!\n";
                return false;
            }
        }

        return true;
    }

protected:
    std::unordered_map<State, Metadata> state_metadata_;
    graph_type graph_;
};

bool is_query_comment(const std::span<sql_token> &tokens)
{
    for (std::size_t i = 1; i < tokens.size(); ++i) {
        if (tokens[i].type == sql_token_type::eol_comment) {
            return true;
        }
    }
    return false;
}

bool is_where_tautology(const std::vector<sql_token> &resource_tokens,
    const std::span<sql_token> &param_tokens, std::size_t param_tokens_begin)
{
    if (param_tokens.size() != 3 || param_tokens_begin == 0) {
        return false;
    }

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

    auto middle_token = param_tokens[1];
    std::cout << "Middle token : " << middle_token.type << std::endl;
    if (middle_token.type != sql_token_type::binary_operator) {
        static std::unordered_set<std::string_view> or_ops{"or", "||", "xor", "OR", "XOR", "oR", "Or"};
        std::cout << "OP : " << middle_token.str << '\n';
        return or_ops.contains(middle_token.str);
    }

    if (param_tokens[0].type != param_tokens[2].type && middle_token.str.find('=') != npos) {
        return param_tokens[0].type != sql_token_type::command &&
               param_tokens[2].type != sql_token_type::command;
    }

    return true;
}

bool has_order_by_structure(const std::span<sql_token> &tokens)
{
    using type = sql_token_type;

    enum class state { Begin, L1, L2, C1, C2, C3, C4, Dot, Comma, End, Invalid };

    struct token_node {
        std::unordered_set<sql_token_type> types;
        std::unordered_set<std::string_view> values;
    };

    static auto comparator = [](const token_node &node, const sql_token &token) -> bool {
        return (node.types.empty() || node.types.contains(token.type)) &&
               (node.values.empty() || node.values.contains(token.str));
    };

    static const simple_fsm<state, token_node> fsm{
        {{state::Begin, {}}, {state::L1, {{type::number}, {}}}, {state::L2, {{type::number}, {}}},
            {state::C1, {{type::command, type::single_quoted_string, type::double_quoted_string,
                             type::back_quoted_string},
                            {}}},
            {state::C2, {{type::command, type::single_quoted_string, type::double_quoted_string,
                             type::back_quoted_string},
                            {}}},
            {state::C3, {{}, {"asc", "desc", "ASC", "DESC"}}}, // TODO: Mixed casing?
            {state::C4, {{}, {"limit", "offset", "LIMIT", "OFFSET"}}},
            {state::Dot, {{type::dot}, {}}}, {state::Comma, {{type::comma}, {}}}, {state::End, {}}},
        {
            {state::Begin, {state::L1, state::C1}},
            {state::L1, {state::C3, state::Comma, state::End}},
            {state::L2, {state::C4, state::End}},
            {state::C1, {state::Dot, state::C3, state::Comma, state::End}},
            {state::C2, {state::C3, state::Comma, state::End}},
            {state::C3, {state::C4, state::Comma, state::End}},
            {state::C4, {state::L2}},
            {state::Dot, {state::C2}},
            {state::Comma, {state::L1, state::C1}},
        }};

    return fsm.evaluate(tokens, comparator);
}

bool is_benign_order_by_clause(const std::vector<sql_token> &resource_tokens,
    const std::span<sql_token> &param_tokens, std::size_t param_tokens_begin)
{
    if (param_tokens_begin < 2) {
        return false;
    }

    std::string_view order = resource_tokens[param_tokens_begin - 2].str;
    std::string_view by = resource_tokens[param_tokens_begin - 1].str;

    if (!string_iequals(order, "order") || !string_iequals(by, "by")) {
        return false;
    }

    return has_order_by_structure(param_tokens);
}

bool contains_harmful_tokens(const std::span<sql_token> &tokens)
{
    if (tokens.size() < min_token_count) {
        return false;
    }

    for (const auto &token : tokens) {
        auto t = token.type;
        if (t != sql_token_type::comma && t != sql_token_type::parenthesis_close &&
            t != sql_token_type::parenthesis_open && t != sql_token_type::number &&
            t != sql_token_type::hex && t != sql_token_type::single_quoted_string &&
            t != sql_token_type::double_quoted_string) {
            return true;
        }
    }
    return false;
}

std::tuple<std::span<sql_token>, std::size_t, std::size_t> get_consecutive_tokens(
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
        index_begin, index_end};
}

sqli_result sqli_impl(std::string_view resource, std::vector<sql_token> &resource_tokens,
    const ddwaf_object &params, sql_flavour flavour,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer &deadline)
{
    static constexpr std::size_t min_str_len = 4;

    object::kv_iterator it(&params, {}, objects_excluded, limits);
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const ddwaf_object &param = *(*it);
        if (param.type != DDWAF_OBJ_STRING) {// || param.nbEntries < min_str_len) {
            continue;
        }

        std::string_view value{param.stringValue, static_cast<std::size_t>(param.nbEntries)};
        std::size_t param_index = resource.find(value);
        if (param_index == npos) {
            continue;
        }

        if (resource_tokens.empty()) {
            if (flavour == sql_flavour::mysql) {
                resource_tokens = mysql_tokenize(resource, flavour);
            } else {
                resource_tokens = sql_tokenize(resource, flavour);
            }

            if (resource_tokens.empty()) {
                return sqli_error::invalid_sql;
            }
        }

        auto [param_tokens, param_tokens_begin, param_tokens_end] =
            get_consecutive_tokens(resource_tokens, param_index, param_index + value.size());
        if (param_tokens.empty()) {
            continue;
        }

        for (auto token : param_tokens) {
            std::cout << "Token: " << token.type << " - " << token.str <<  '\n';
        }
        bool harmful = contains_harmful_tokens(param_tokens);
        DDWAF_DEBUG("Contains harmful {}", harmful);
        bool benign_order_by = !is_benign_order_by_clause(resource_tokens, param_tokens, param_tokens_begin);
        DDWAF_DEBUG("Is Benign order by {}", benign_order_by);
        bool tautology = is_where_tautology(resource_tokens, param_tokens, param_tokens_begin);
        DDWAF_DEBUG("Is where tautology {}", tautology);
        bool query_comment =  is_query_comment(param_tokens);
        DDWAF_DEBUG("Query comment {}", query_comment);

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

[[nodiscard]] eval_result sqli_detector::eval_impl(const unary_argument<std::string_view> &sql,
    const variadic_argument<const ddwaf_object *> &params,
    const unary_argument<std::string_view> &db_type, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, ddwaf::timer &deadline) const
{
    auto flavour = sql_flavour_from_type(db_type.value);

    std::vector<sql_token> resource_tokens;
    /* // TODO only tokenize if there's a potential injection*/

    for (const auto &param : params) {
        auto res = sqli_impl(
            sql.value, resource_tokens, *param.value, flavour, objects_excluded, limits_, deadline);
        if (std::holds_alternative<matched_param>(res)) {
            std::vector<std::string> sql_kp{sql.key_path.begin(), sql.key_path.end()};
            bool ephemeral = sql.ephemeral || param.ephemeral;

            auto &[highlight, param_kp] = std::get<matched_param>(res);
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

        if (std::holds_alternative<sqli_error>(res)) {
            // The only error for now is returned when the resource couldn't be
            // parsed, we don't do anything specific for now other than stopping
            // the evaluation of the parameters
            break;
        }
    }

    return {};
}

} // namespace ddwaf
