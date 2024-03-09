select     [Ss][Ee][Ll][Ee][Cc][Tt] 
%%
{select}    out() << text()[0] << "SELECT!!";
%%

namespace ddwaf {

void sql_tokenize() {
    Lexer().lex(); 
}

}
