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
    explicit schema_doc_provider(fs::path parent_path): parent_path_(std::move(parent_path)) {}
    const SchemaDocument* GetRemoteDocument(const char* uri, SizeType length) override {
        // Resolve the uri and returns a pointer to that schema.
        std::filesystem::path file_path = fs::path(parent_path_) / std::string{uri, length};
        auto schema = read_file(file_path.string());
        Document sd;
        if (sd.Parse(schema).HasParseError()) {
            std::cerr << "Failed to parse schema: " << file_path << '\n';
            std::exit(EXIT_FAILURE); // NOLINT(concurrency-mt-unsafe)
        }
        docs_.emplace_back(sd);
        return &docs_.back();
    }

protected:
    fs::path parent_path_;
    std::vector<SchemaDocument> docs_;
};

int main(int argc, char* argv[])
{
    if (argc < 3) {
        std::cerr << "Usage " << argv[0] << " <schema file> <json file>\n";
        return EXIT_FAILURE;
    }

    fs::path schema_file(argv[1]);

    auto schema_json = read_file(schema_file.string());
    Document sd;
    if (sd.Parse(schema_json).HasParseError()) {
        std::cerr << "Failed to parse schema: " << schema_file << '\n';
        return EXIT_FAILURE;
    }

    schema_doc_provider provider{schema_file.parent_path()};
    SchemaDocument schema(sd, "schema", sizeof("schema") - 1, &provider);

    auto inputJson = read_file(argv[2]);
    Document d;
    if (d.Parse(inputJson).HasParseError()) {
        std::cerr << "Failed to parse input json\n";
        return EXIT_FAILURE;
    }

    SchemaValidator validator(schema);

    if (!d.Accept(validator)) {
        StringBuffer sb;
        validator.GetInvalidSchemaPointer().StringifyUriFragment(sb);
        std::cerr << "Invalid schema: " << sb.GetString() << '\n';
        std::cerr << "Invalid keyword: " << validator.GetInvalidSchemaKeyword() << '\n';

        sb.Clear();
        validator.GetInvalidDocumentPointer().StringifyUriFragment(sb);
        std::cerr << "Invalid document: " << sb.GetString() << '\n';


        sb.Clear();
        PrettyWriter<StringBuffer> w(sb);
        validator.GetError().Accept(w);
        std::cerr << "Validation error: " << sb.GetString() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
