#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

#include "rapidjson/prettywriter.h"
#include "rapidjson/schema.h"

using namespace rapidjson;

std::string read_file(const std::string_view& filename)
{
    std::ifstream rule_file(filename.data(), std::ios::in);
    if (!rule_file)
    {
        throw std::system_error(errno, std::generic_category());
    }

    std::string buffer;
    rule_file.seekg(0, std::ios::end);
    buffer.resize(rule_file.tellg());
    rule_file.seekg(0, std::ios::beg);

    rule_file.read(&buffer[0], buffer.size());
    rule_file.close();
    return buffer;
}

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        std::cerr << "Usage " << argv[0] << " <schema> <json>\n";
        return EXIT_FAILURE;
    }

    auto schemaJson = read_file(argv[1]);
    Document sd;
    if (sd.Parse(schemaJson).HasParseError())
    {
        std::cout << "Failed to parse schema" << std::endl;
        return EXIT_FAILURE;
    }
    SchemaDocument schema(sd);

    auto inputJson = read_file(argv[2]);
    Document d;
    if (d.Parse(inputJson).HasParseError())
    {
        std::cout << "Failed to parse input json" << std::endl;
        return EXIT_FAILURE;
    }

    SchemaValidator validator(schema);
    if (!d.Accept(validator))
    {
        StringBuffer sb;
        PrettyWriter<StringBuffer> w(sb);
        validator.GetError().Accept(w);
        std::cout << "Validation error: " << sb.GetString() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
