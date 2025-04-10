#include <iostream>
#include <string_view>

#include "common/utils.hpp"

#include "rapidjson/error/en.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/schema.h"

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
        std::cout << "Failed to parse schema\n";
        return EXIT_FAILURE;
    }

    SchemaDocument schema(sd);

    auto inputJson = read_file(argv[2]);
    Document d;
    if (d.Parse(inputJson).HasParseError()) {
        std::cout << "Failed to parse input json\n";
        return EXIT_FAILURE;
    }

    SchemaValidator validator(schema);

    if (!d.Accept(validator)) {
        StringBuffer sb;
        validator.GetInvalidSchemaPointer().StringifyUriFragment(sb);
        std::cout << "Invalid schema: " << sb.GetString() << '\n';
        std::cout << "Invalid keyword: " << validator.GetInvalidSchemaKeyword() << '\n';

        sb.Clear();
        validator.GetInvalidDocumentPointer().StringifyUriFragment(sb);
        std::cout << "Invalid document: " << sb.GetString() << '\n';


        sb.Clear();
        PrettyWriter<StringBuffer> w(sb);
        validator.GetError().Accept(w);
        std::cout << "Validation error: " << sb.GetString() << '\n';
        return EXIT_FAILURE;
    }

    std::cout << "Validation success\n";
    return EXIT_SUCCESS;
}
