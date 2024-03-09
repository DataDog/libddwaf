// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

select     [Ss][Ee][Ll][Ee][Cc][Tt] 
%%
{select}    out() << text()[0] << "SELECT!!";
%%

namespace ddwaf {

void sql_tokenize() {
    Lexer().lex(); 
}

}
