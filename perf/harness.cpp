// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <filesystem>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include <rapidjson/document.h>
#include <rapidjson/filereadstream.h>

#include <PowerWAF.h>
#define PWI_CONTAINER_TYPES (PWI_ARRAY | PWI_MAP)

using namespace std;
using namespace rapidjson;

struct ref
{
	string name;
	uint64_t percentage;

	FILE* file = NULL;

	Document jsonData;

	ref(const std::string& _name, uint64_t _percentage) : name(_name), percentage(_percentage) {}

	ref(ref&& other)
	{
		name       = move(other.name);
		percentage = other.percentage;
		file       = other.file;
		jsonData   = move(other.jsonData);
	}

	~ref()
	{
		fclose(file);
	}
};

// The number is % of triggers coming from this vuln, * 100
vector<struct ref> reference;

size_t getFileSize(const char* filename)
{
	struct stat st;
	size_t output = 0;

	if (stat(filename, &st) == 0 && st.st_size > 0)
		output = (uint64_t) st.st_size;

	return output;
}

const char* readFile(const char* filename)
{
	string basePath = "/Users/ehs/Projects/PowerWAF/perf/";
	auto fileSize   = getFileSize((basePath + filename).c_str());
	if (fileSize == 0)
		return nullptr;

	char* buffer = (char*) malloc(fileSize + 1);
	if (buffer == nullptr)
		return nullptr;

	FILE* file = fopen((basePath + filename).c_str(), "rb");
	if (file == nullptr)
	{
		free(buffer);
		return nullptr;
	}

	if (fread((void*) buffer, fileSize, 1, file) != 1)
	{
		free(buffer);
		fclose(file);
		return nullptr;
	}

	fclose(file);
	buffer[fileSize] = 0;
	return buffer;
}

vector<string> targets = {
	"#.header.user-agent",
	"#.header.connection",
	"#.header.content-length",
	"#.header.content-type",
	"#.header.referer",
	"#.header.x-file-name",
	"#.header.x-filename",
	"#.header.x.filename",
	"#.header_keys",
	"#.header_values",
	"#.req_old",
	"#.uri"
};

PWArgs _convertTypeToArg(const Value& value)
{
	switch (value.GetType())
	{
		case kObjectType:
		{
			PWArgs output = pw_createMap();

			for (auto iter = value.MemberBegin(); iter != value.MemberEnd(); ++iter)
			{
				PWArgs val = _convertTypeToArg(iter->value);
				if (val.type != PWI_INVALID)
					pw_addMap(&output, iter->name.GetString(), iter->name.GetStringLength(), val);
			}

			return output;
		}

		case kArrayType:
		{
			PWArgs output = pw_createArray();

			for (const auto& _item : value.GetArray())
			{
				PWArgs val = _convertTypeToArg(_item);
				if (val.type != PWI_INVALID)
					pw_addArray(&output, val);
			}

			return output;
		}

		case kStringType:
		{
			return pw_createStringWithLength(value.GetString(), value.GetStringLength());
		}

		case kNumberType:
		{
			if (value.IsDouble())
			{
				return pw_getInvalid();
			}
			else if (value.IsUint64())
			{
				return pw_createUint(value.GetUint64());
			}
			else
			{
				return pw_createInt(value.GetInt64());
			}
		}

		case kTrueType:
		{
			return pw_createUintForce(1);
		}

		case kFalseType:
		{
			return pw_createUintForce(0);
		}

		default:
			break;
	}

	return pw_getInvalid();
}

void flattenArg(PWArgs* arg, int skipLevel, PWArgs* outputKey, PWArgs* outputVal)
{
	if (arg->parameterName != NULL && skipLevel <= 0)
		pw_addArray(outputKey, pw_createStringWithLength(arg->parameterName, arg->parameterNameLength));

	if (arg->type & PWI_CONTAINER_TYPES)
	{
		for (uint64_t i = 0; i < arg->nbEntries; ++i)
			flattenArg((PWArgs*) &arg->array[i], skipLevel - 1, outputKey, outputVal);
	}
	else
	{
		PWArgs newArg              = *arg;
		newArg.parameterName       = NULL;
		newArg.parameterNameLength = 0;

		pw_addArray(outputVal, newArg);

		// We steal ownership of the string
		if (arg->type == PWI_STRING)
			arg->stringValue = NULL;
	}
}

void searchAndDestroy(PWArgs* root, const string& target)
{
	if (root->parameterName != NULL && target == root->parameterName)
	{
		// Shitty hash to break the match
		for (uint64_t i = 0; i < root->parameterNameLength; ++i)
			((char*) root->parameterName)[i] = (0x9e - root->parameterName[i]) & 0x7f;
	}

	switch (root->type)
	{
		case PWI_STRING:
		{
			if (target == root->stringValue)
			{
				// Shitty hash to break the match
				for (uint64_t i = 0; i < root->nbEntries; ++i)
					((char*) root->stringValue)[i] = (0x9e - root->stringValue[i]) & 0x7f;
			}
			break;
		}

		case PWI_MAP:
		case PWI_ARRAY:
		{
			for (uint64_t i = 0; i < root->nbEntries; ++i)
				searchAndDestroy((PWArgs*) &root->array[i], target);
		}

		default:
			break;
	}
}

PWArgs convertToArg(const Value& value, bool shouldRedactAttack)
{
	PWArgs map = pw_createMap();

	if (!value.IsObject())
		return pw_getInvalid();

	for (const auto& target : targets)
	{
		if (target.find("#.header.") == 0)
		{
			if (!value.HasMember("headers") || !value["headers"].IsObject())
				continue;

			const Value& headers  = value["headers"];
			const char* startName = &target.c_str()[9];
			for (auto iter = headers.MemberBegin(); iter != headers.MemberEnd(); ++iter)
			{
				string keyName = iter->name.GetString();
				std::transform(keyName.begin(), keyName.end(), keyName.begin(),
							   [](unsigned char c) { return std::tolower(c); });
				if (keyName == startName && iter->value.IsString())
				{
					const auto& str = iter->value;
					pw_addMap(&map, target.c_str(), target.length(), pw_createStringWithLength(str.GetString(), str.GetStringLength()));
					break;
				}
			}
		}
		else if (target.find("#.header_") == 0)
		{
			if (!value.HasMember("headers") || !value["headers"].IsObject())
				continue;

			const bool wantKeys  = target == "#.header_keys";
			const Value& headers = value["headers"];

			PWArgs headerArray = pw_createArray();
			for (auto iter = headers.MemberBegin(); iter != headers.MemberEnd(); ++iter)
			{
				if (wantKeys)
					pw_addArray(&headerArray, pw_createStringWithLength(iter->name.GetString(), iter->name.GetStringLength()));
				else if (iter->value.IsString())
					pw_addArray(&headerArray, pw_createStringWithLength(iter->value.GetString(), iter->value.GetStringLength()));
			}

			pw_addMap(&map, target.c_str(), target.length(), headerArray);
		}

		else if (target == "#.req_old")
		{
			if (!value.HasMember("parameters") || !value["parameters"].IsObject())
				continue;

			PWArgs outputKey = pw_createArray(), outputVal = pw_createArray();

			PWArgs parameters = _convertTypeToArg(value["parameters"]);
			flattenArg(&parameters, 2, &outputKey, &outputVal);

			pw_addMap(&map, "#.req_keys", 0, outputKey);
			pw_addMap(&map, "#.req_values", 0, outputVal);

			pw_freeArg(&parameters);
		}
		else if (target == "#.uri")
		{
			if (!value.HasMember("path") || !value["path"].IsString())
			{
				cerr << "Invalid or missing URI!" << endl;
				continue;
			}

			const Value& path = value["path"];
			pw_addMap(&map, target.c_str(), target.length(), pw_createStringWithLength(path.GetString(), path.GetStringLength()));
		}
	}

	if (shouldRedactAttack && value.HasMember("attack"))
		searchAndDestroy(&map, value["attack"].GetString());

	return map;
}

void init()
{
	reference.emplace_back("sql_injection", 3279);
	reference.emplace_back("security_scanner", 2585);
	reference.emplace_back("lfi", 1214);
	reference.emplace_back("rfi", 745);
	reference.emplace_back("php_eval", 745);
	reference.emplace_back("shell_injection", 667);
	reference.emplace_back("xss", 480);
	reference.emplace_back("paranoid", 189);
	reference.emplace_back("protocol", 96);
}

void loadPowerWAF()
{
	const char* rule = readFile("test_files/rules_node.json");
	char* errors     = NULL;
	bool output      = pw_init("rule", rule, NULL, &errors);

	if (errors != NULL)
		cerr << errors << endl;

	if (!output)
		exit(-1);

	pw_freeDiagnotics(errors);
	free((void*) rule);

	for (auto& ref : reference)
	{
		string path = "/Users/ehs/Projects/PowerWAF/perf/test_files/parsed_" + ref.name + ".json";
		ref.file    = fopen(path.c_str(), "r");

		char readBuffer[65536];
		FileReadStream inputStream(ref.file, readBuffer, sizeof(readBuffer));
		ref.jsonData.ParseStream(inputStream);
	}

	time_t seed = time(0);
	cout << "This run's seed is " << seed << endl;
	srand((uint) seed);
}

void loadRequests(vector<pair<PWArgs, bool>>& parameters, uint targetRuns)
{
	parameters.reserve(targetRuns);

	for (uint i = 0; i < targetRuns; ++i)
	{
		// Pick a random ruleset
		const auto& ref = reference[(uint) rand() % reference.size()];

		const uint itemIndexToPick    = (uint) rand() % ref.jsonData.Size();
		const bool shouldRedactAttack = ((uint) rand() % 10000) >= ref.percentage;

		parameters.push_back({ convertToArg(ref.jsonData.GetArray()[itemIndexToPick], shouldRedactAttack), !shouldRedactAttack });
	}
}

int main()
{
	vector<pair<PWArgs, bool>> parameters;
	size_t timeoutCount = 0, success = 0;

	cout << "Initializing..." << endl;

	init();
	loadPowerWAF();
	loadRequests(parameters, 10000);

	reference.clear();

	cout << "Initialized. Waiting 500ms then running!" << endl;

	usleep(500000);

	for (const auto& group : parameters)
	{
		PWRet ret = pw_run("rule", group.first, 5000);

		bool matched = ret.action != PW_MONITOR;

		if (matched == group.second)
		{
			if (ret.data != NULL)
			{
				Document data;
				data.Parse(ret.data);
				if (data.GetArray()[0]["ret_code"].GetInt() == PW_ERR_TIMEOUT)
				{
					timeoutCount += 1;
				}
				else
				{
					// This usually happen when the redaction failed, often because a transformer pervented us from making a perfect match
					cout << "Failed with code " << ret.action << "!" << endl;
				}
			}
			else
				cout << "Didn't trigger!" << endl;
		}
		else
			success += 1;

		pw_freeReturn(ret);
	}

	cout << "Done running (" << success << " worked, " << timeoutCount << " timed out), freeing everything!" << endl;

	for (auto group : parameters)
		pw_freeArg(&group.first);

	pw_clearRule("rule");
	return 0;
}
