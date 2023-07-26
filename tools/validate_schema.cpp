#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

#include "common/utils.hpp"

#include "rapidjson/prettywriter.h"
#include "rapidjson/schema.h"
#include "rapidjson/error/en.h"

using namespace rapidjson;

int main(int argc, char* argv[])
{
    if (argc < 3) {
        std::cerr << "Usage " << argv[0] << " <schema> <json>\n";
        return EXIT_FAILURE;
    }

    auto schemaJson = read_file(argv[1]);
    Document sd;
    if (sd.Parse(schemaJson).HasParseError()) {
        std::cout << "Failed to parse schema" << std::endl;
        return EXIT_FAILURE;
    }
    SchemaDocument schema(sd);

    auto inputJson = read_file(argv[2]);
    Document d;
    rapidjson::ParseResult result = d.Parse(inputJson);
    if (result == nullptr) {
        std::cout << "Failed to parse input json: " 
                  << rapidjson::GetParseError_En(result.Code())
                  << result.Offset() << std::endl;
        return EXIT_FAILURE;
    }

    SchemaValidator validator(schema);
    if (!d.Accept(validator)) {
        StringBuffer sb;
        PrettyWriter<StringBuffer> w(sb);
        validator.GetError().Accept(w);
        std::cout << "Validation error: " << sb.GetString() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
