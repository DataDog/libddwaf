#include <iostream>
#include <re2/stringpiece.h>
#include <re2/regexp.h>
#include <re2/re2.h>
#include <vector>

int main(int argc, char *argv[])
{
    std::vector<std::string> args{argv, argv + argc};

    if (args.size() < 2){
        return 1;
    }

    auto arg_str = args[1];
    re2::RE2 regex(arg_str);

    auto regexp = regex.Regexp();

    auto regexp_str = regexp->ToString();
    if (regexp_str != arg_str) {
        std::cout << regexp_str << std::endl;
    }

    return 0;
}
