#include <memory>
#include <re2/re2.h>
#include <string_view>
#include <iostream>
#include <vector>

namespace ddwaf { // compat
inline bool isalpha(char c) { return (static_cast<unsigned>(c) | 32) - 'a' < 26; }
inline bool isdigit(char c) { return static_cast<unsigned>(c) - '0' < 10; }
inline bool isxdigit(char c) { return isdigit(c) || ((unsigned)c | 32) - 'a' < 6; }
inline bool isspace(char c)
{
    return c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v';
}
inline bool isupper(char c) { return static_cast<unsigned>(c) - 'A' < 26; }
inline bool islower(char c) { return static_cast<unsigned>(c) - 'a' < 26; }
inline bool isalnum(char c) { return isalpha(c) || isdigit(c); }
inline bool isboundary(char c) { return !isalnum(c) && c != '_'; }
inline char tolower(char c) { return isupper(c) ? static_cast<char>(c | 32) : c; }

}

enum class sql_token_type {
    command,
    identifier,
    hex,
    number,
    string,
    single_quoted_string,
    double_quoted_string,
    back_quoted_string,
    whitespace,
    asterisk,
    eol_comment,
    parenthesis_open,
    parenthesis_close,
    comma,
    questionmark,
    label,
    dot,
    query_end,
    binary_operator,
    bitwise_operator,
    inline_comment,
};

struct sql_token {
    sql_token_type type;
    std::string_view str;
    std::size_t begin;
    std::size_t end;
};

std::ostream& operator<<(std::ostream &os, sql_token_type type) {
    switch(type) {
    case sql_token_type::command:
        std::cout << "command" ;
        break;
    case sql_token_type::identifier:
        std::cout << "identifier" ;
        break;
    case sql_token_type::hex:
        std::cout << "hex" ;
        break;
    case sql_token_type::number:
        std::cout << "number" ;
        break;
    case sql_token_type::string:
        std::cout << "string" ;
        break;
    case sql_token_type::single_quoted_string:
        std::cout << "single_quoted_string" ;
        break;
    case sql_token_type::double_quoted_string:
        std::cout << "double_quoted_string" ;
        break;
    case sql_token_type::back_quoted_string:
        std::cout << "back_quoted_string" ;
        break;
    case sql_token_type::whitespace:
        std::cout << "whitespace" ;
        break;
    case sql_token_type::asterisk:
        std::cout << "asterisk" ;
        break;
    case sql_token_type::eol_comment:
        std::cout << "eol_comment" ;
        break;
    case sql_token_type::parenthesis_open:
        std::cout << "parenthesis_open" ;
        break;
    case sql_token_type::parenthesis_close:
        std::cout << "parenthesis_close" ;
        break;
    case sql_token_type::comma:
        std::cout << "comma" ;
        break;
    case sql_token_type::questionmark:
        std::cout << "questionmark" ;
        break;
    case sql_token_type::label:
        std::cout << "label" ;
        break;
    case sql_token_type::dot:
        std::cout << "dot" ;
        break;
    case sql_token_type::query_end:
        std::cout << "query_end" ;
        break;
    case sql_token_type::binary_operator:
        std::cout << "binary_operator" ;
        break;
    case sql_token_type::bitwise_operator:
        std::cout << "bitwise_operator" ;
        break;
    case sql_token_type::inline_comment:
        std::cout << "inline_comment" ;
        break;
    }
    return os;
}

std::ostream& operator<<(std::ostream &os, const sql_token &token)
{
    std::cout << "[" << token.type << "] : " << token.str << "\n";
    return os;
}

class sql_tokenizer {
public:
    explicit sql_tokenizer(std::string_view str): buffer_(str) {
        constexpr unsigned regex_max_mem = 512 * 1024;

        re2::RE2::Options options;
        options.set_max_mem(regex_max_mem);
        options.set_log_errors(false);
        options.set_case_sensitive(false);

        identifier_regex = std::make_unique<re2::RE2>(R"((?P<command>SELECT|FROM|WHERE|ORDER BY)|(?P<binary_operator>NOT|OR|XOR|AND|IS|IN|BETWEEN|LIKE|REGEXP|SOUNDS LIKE|IS NULL|IS NOT NULL)|(?P<bitwise_operator>DIV|MOD)|(?P<identifier>[\x{0080}-\x{FFFF}a-zA-Z_][\x{0080}-\x{FFFF}a-zA-Z_0-9$\.]*))", options);
        if (!identifier_regex->ok()) {
            throw std::runtime_error("failed");
        }

        number_regex = std::make_unique<re2::RE2>(R"((0x[0-9a-fA-F]+|[-+]*(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?))", options);
        if (!number_regex->ok()) {
            throw std::runtime_error("failed");
        }
        std::cout << "buffer(" << buffer_ << ")\n";
    }

    std::vector<sql_token> tokenize();

    void tokenize_command_operator_or_identifier();
    void tokenize_string(char quote);
    void tokenize_inline_comment_or_operator();
    void tokenize_eol_comment();
    void tokenize_eol_comment_operator_or_number();
    void tokenize_operator_or_number();
    bool tokenize_number();

protected:
    char peek() const {
        if (idx_ >= buffer_.size()) { [[unlikely]] return '\0'; }
        return buffer_[idx_];
    }
    char prev() const {
        if (idx_  == 0) { [[unlikely]] return '\0'; }
        return buffer_[idx_ - 1];
    }

    bool advance(std::size_t offset = 1) { return (idx_ += offset) < buffer_.size(); }

    char next(std::size_t offset = 1) {
        if ((idx_ + offset) >= buffer_.size()) { [[unlikely]] return '\0'; }
        return buffer_[idx_ + offset];
    }

    bool eof() { return idx_ >= buffer_.size(); }

    std::size_t index() { return idx_; }

    std::string_view substr(std::size_t start, std::size_t size = std::string_view::npos) {
        return buffer_.substr(start, size);
    }

    void add_token(sql_token_type type, std::size_t size = 1) {
        sql_token token;
        token.begin = index();
        token.type = type;
        token.end = index() + size - 1;
        token.str = substr(token.begin, size);
        tokens_.emplace_back(token);
        advance(size);
    }

    std::string_view buffer_;
    std::size_t idx_{0};
    std::vector<sql_token> tokens_{};

    std::unique_ptr<re2::RE2> identifier_regex;
    std::unique_ptr<re2::RE2> number_regex;
};

void sql_tokenizer::tokenize_command_operator_or_identifier()
{
    sql_token token;
    token.begin = index();

    auto remaining_str = substr(index());

    re2::StringPiece binary_op, bitwise_op, command, ident;
    const re2::StringPiece ref(remaining_str.data(), remaining_str.size());
    if (re2::RE2::PartialMatch(ref, *identifier_regex, &command, &bitwise_op, &binary_op, &ident)) {
        if (!binary_op.empty()) {
            token.type = sql_token_type::binary_operator;
            token.str = substr(token.begin, binary_op.size());
            token.end = token.begin + token.str.size() - 1;
            advance(token.str.size());
        } else if (!bitwise_op.empty()) {
            token.type = sql_token_type::bitwise_operator;
            token.str = substr(token.begin, bitwise_op.size());
            token.end = token.begin + token.str.size() - 1;
            advance(token.str.size());
        } else if (!command.empty()) {
            token.type = sql_token_type::command;
            token.str = substr(token.begin, command.size());
            token.end = token.begin + token.str.size() - 1;
            advance(token.str.size());
        } else if (!ident.empty()) {
            token.type = sql_token_type::identifier;
            token.str = substr(token.begin, ident.size());
            token.end = token.begin + token.str.size() - 1;
            advance(token.str.size());
        }
        tokens_.emplace_back(token);
        return;
    }

    advance();
}

void sql_tokenizer::tokenize_string(char quote)
{
    sql_token token;
    token.begin = index();
    token.type = sql_token_type::double_quoted_string;
    while (advance()) {
        if (peek() == quote && prev() != '\\') {
            break;
        }
    }
    token.end = index();
    token.str = substr(token.begin, index() - token.begin + 1);
    tokens_.emplace_back(token);

    advance();
}

void sql_tokenizer::tokenize_inline_comment_or_operator()
{
    // The first character is / so it can be a comment or a binary operator
    sql_token token;
    token.begin = index();
    if (advance() && peek() == '*') {
        // Comment
        advance(); // Skip the '*' in prev()
        while (advance()) {
            if (prev() == '*' && peek() == '/') {
                break;
            }
        }
        token.str = substr(token.begin, index() - token.begin + 1);
        token.end = index();
        token.type = sql_token_type::inline_comment;
        advance();
    } else {
        token.str = substr(token.begin, 1);
        token.end = token.begin;
        token.type = sql_token_type::binary_operator;
    }
    tokens_.emplace_back(token);
}

bool sql_tokenizer::tokenize_number()
{
    sql_token token;
    token.begin = index();

    auto remaining_str = substr(index());

    re2::StringPiece number;
    const re2::StringPiece ref(remaining_str.data(), remaining_str.size());
    if (re2::RE2::PartialMatch(ref, *number_regex, &number)) {
        if (!number.empty()) {
            token.str = substr(token.begin, number.size());
            token.end = token.begin + token.str.size() - 1;
            token.type = sql_token_type::number;
            advance(token.str.size());
            tokens_.emplace_back(token);
            return true;
        }
    }
    advance();
    return false;
}

void sql_tokenizer::tokenize_eol_comment()
{
    // Inline comment
    sql_token token;
    token.begin = index();

    while (advance() && peek() != '\n' ) {}

    token.end = index() - 1;
    token.str = substr(token.begin, index() - token.begin);
    token.type = sql_token_type::eol_comment;
    tokens_.emplace_back(token);
}

void sql_tokenizer::tokenize_eol_comment_operator_or_number()
{
    if (next() == '-') {
        tokenize_eol_comment();
    } else if (!tokenize_number()) {
        // If it's not a number, it must be an operator
        sql_token token;
        token.begin = index();
        token.end = index();
        token.str = substr(token.begin, 1);
        token.type = sql_token_type::binary_operator;
        tokens_.emplace_back(token);
    }
}

void sql_tokenizer::tokenize_operator_or_number()
{
    if (!tokenize_number()) {
        // If it's not a number, it must be an operator
        sql_token token;
        token.begin = index();
        token.end = index();
        token.str = substr(token.begin, 1);
        token.type = sql_token_type::binary_operator;
        tokens_.emplace_back(token);
    }
}

std::vector<sql_token> sql_tokenizer::tokenize()
{
    //std::cout << "Tokenizing\n";
    while (!eof()) {
        auto c = ddwaf::tolower(peek());
        //std::cout << "Char: " << c << '\n';
        if (ddwaf::isalpha(c) || c == '_') { // Command or identifier
            tokenize_command_operator_or_identifier();
        } else if (ddwaf::isdigit(c)) {
            tokenize_number();
        } else if (c == '"') { // Double-quoted string
            tokenize_string('"');
        } else if (c == '\'') { // Single-quoted string
            tokenize_string('\'');
        } else if (c == '`') { // Backtick-quoted string
            tokenize_string('`');
        } else if (c == '(') {
            add_token(sql_token_type::parenthesis_open);
        } else if (c == ')') {
            add_token(sql_token_type::parenthesis_close);
        } else if (c == '.') {
            add_token(sql_token_type::dot);
        } else if (c == ',') {
            add_token(sql_token_type::comma);
        } else if (c == '?') {
            add_token(sql_token_type::questionmark);
        } else if (c == '*') {
            add_token(sql_token_type::asterisk);
        } else if (c == ';') {
            add_token(sql_token_type::query_end);
        } else if (c == '/') {
            tokenize_inline_comment_or_operator();
        } else if (ddwaf::isdigit(c)) {
            tokenize_number();
        } else if (c == '-') {
            tokenize_eol_comment_operator_or_number();
        } else if (c == '#') {
            tokenize_eol_comment();
        } else if (c == '+') {
            tokenize_operator_or_number();
        } else if (c == '@') {
            auto n = next();
            if (n == '@' || n == '>') {
                add_token(sql_token_type::binary_operator, 2);
            }
        } else if (c == '!') {
            add_token(sql_token_type::binary_operator, next() == '=' ? 2 : 1);
        } else if (c == '<') {
            auto n = next();
            if (n == '=' || n == '@') {
                add_token(sql_token_type::binary_operator, next(2) == '>' ? 3 : 2);
            } else if (n == '<' || n == '>') {
                add_token(sql_token_type::bitwise_operator, 2);
            } else {
                add_token(sql_token_type::binary_operator);
            }
        } else if (c == '>') {
            add_token(sql_token_type::binary_operator, next() == '=' ? 2 : 1);
        } else if (c == '=' || c == '%') {
            add_token(sql_token_type::binary_operator);
        } else if (c == '|') {
            add_token(sql_token_type::binary_operator, next() == '|' ? 2 : 1);
        } else if (c == '&' || c == '^' || c == '~') {
            add_token(sql_token_type::bitwise_operator);
        } else if (c == ':') {
            if (next() == '=') {
                add_token(sql_token_type::binary_operator);
            } else {
                add_token(sql_token_type::label);
            }
        } else if (ddwaf::isspace(c)) {
            advance();
            continue;
        } else {
            advance();
            continue;
        }

    }
    return tokens_;
}

int main(int argc, char *argv[])
{
    if (argc < 2) { return 1; }

    sql_tokenizer tokenizer(argv[1]);
    auto tokens = tokenizer.tokenize();
    for (const auto &token: tokens) {
        std::cout << token;
    }
    return 0;
}
