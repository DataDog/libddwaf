// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

%top{
#include "sql_tokenizer.hpp"

#include "utils.hpp"
}

%option fast freespace unicode
%option lexer=sql_tokenizer
%option namespace=ddwaf

%class{
    public:
        void set_token(sql_token_type type) {
            std::size_t offset = matcher().first();
            std::string_view str{in_.cstring() + offset, size()};

            /*std::cout << "Token[" << offset << "]: " << str << std::endl;*/
            tokens_.emplace_back(type, str, offset);
        }
        std::vector<sql_token> &&get_tokens() {
            return std::move(tokens_);
        }
    protected:
        std::vector<sql_token> tokens_;
}

command                     [a-zA-Z_][a-zA-Z_0-9$]*
utf8command                 [\x0080-\xFFFFa-zA-Z_][\x0080-\xFFFFa-zA-Z_0-9$]*
hex                         0x[0-9a-fA-F]+
number                      [-+]*(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?\b
par_open                    \(
par_close                   \)
comma                       ,
questionmark                \?
label                       :
dot                         \.
asterisk                    \*
semicolon                   ;
whitespace                  [[:space:]][[:space:]]*
double_quoted_string        \"(\\\"|[^\"])*\"
single_quoted_string        '(\\'|[^'])*'
back_quoted_string          `(\\`|[^`])*`
inline_comment              \/\*.*\*\/
binary_operator             @@|@>|<@|\+|-|\/|~|<=>|<>|!=|<=|=|>=|<|>|:=|%|!|NOT|OR|XOR|\|\||AND|IS|IN|BETWEEN|LIKE|REGEXP|SOUNDS LIKE|IS NULL|IS NOT NULL
bitwise_operator            \||&|<<|>>|\+|-|\*|\/|DIV|MOD|%|\^
eol_comment                 --.*
%%
{whitespace}           { /* Ignore Whitespaces */ }
{command}              { set_token(sql_token_type::command); }
{hex}                  { set_token(sql_token_type::hex); }
{single_quoted_string} { set_token(sql_token_type::single_quoted_string); }
{double_quoted_string} { set_token(sql_token_type::double_quoted_string); }
{back_quoted_string}   { set_token(sql_token_type::back_quoted_string); }
{asterisk}             { set_token(sql_token_type::asterisk); }
{par_open}             { set_token(sql_token_type::parenthesis_open); }
{par_close}            { set_token(sql_token_type::parenthesis_close); }
{comma}                { set_token(sql_token_type::comma); }
{questionmark}         { set_token(sql_token_type::questionmark); }
{label}                { set_token(sql_token_type::label); }
{dot}                  { set_token(sql_token_type::dot); }
{inline_comment}       { set_token(sql_token_type::inline_comment); }
{semicolon}            { set_token(sql_token_type::query_end); }
{number}               { set_token(sql_token_type::number); }
{binary_operator}      { set_token(sql_token_type::binary_operator); }
{bitwise_operator}     { set_token(sql_token_type::bitwise_operator); }
{eol_comment}          { set_token(sql_token_type::eol_comment); }
{utf8command}          { set_token(sql_token_type::command); }
%%

namespace ddwaf {

std::vector<sql_token> sql_tokenize(std::string_view resource, sql_flavour /*flavour*/)
{
    null_ostream nos;
    reflex::Input input(resource.data(), resource.size());
    sql_tokenizer lexer(input, nos);
    lexer.lex();
    return lexer.get_tokens();
}

}
