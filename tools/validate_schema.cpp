#include <filesystem>
#include <iostream>
#include <string_view>

#include "common/utils.hpp"

#include "rapidjson/error/en.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/schema.h"

using namespace rapidjson;
namespace fs = std::filesystem;

class schema_doc_provider : public IRemoteSchemaDocumentProvider {
public:
    explicit schema_doc_provider(std::string parent_path): parent_path_(std::move(parent_path)) {}
    const SchemaDocument* GetRemoteDocument(const char* uri, SizeType length) override {
        // Resolve the uri and returns a pointer to that schema.
        std::string uri_str = parent_path_ + '/' +  std::string{uri, length};
        auto schema = read_file(uri_str);
        Document sd;
        if (sd.Parse(schema).HasParseError()) {
            std::cout << "Failed to load " << uri_str << '\n';
            std::abort();
        }
        docs_.emplace_back(sd);
        return &docs_.back();
    }

protected:
    std::string parent_path_;
    std::vector<SchemaDocument> docs_;
};

int main(int argc, char* argv[])
{
    if (argc < 3) {
        std::cerr << "Usage " << argv[0] << " <schema> <json>\n";
        return EXIT_FAILURE;
    }

    fs::path schema_file(argv[1]);

    auto schema_json = read_file(schema_file.string());
    Document sd;
    if (sd.Parse(schema_json).HasParseError()) {
        std::cout << "Failed to parse schema\n";
        return EXIT_FAILURE;
    }

    schema_doc_provider provider{schema_file.parent_path()};
    SchemaDocument schema(sd, "schema", sizeof("schema") - 1, &provider);

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
