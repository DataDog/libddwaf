// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <yaml-cpp/yaml.h>

#include "ddwaf.h"
#include "log.hpp"
#include <fstream>
#include <parameter.hpp>

#define LONG_TIME 1000000

#ifdef VERBOSE

const char* level_to_str(DDWAF_LOG_LEVEL level)
{
	switch (level)
	{
		case DDWAF_LOG_TRACE:
			return "trace";
		case DDWAF_LOG_DEBUG:
			return "debug";
		case DDWAF_LOG_ERROR:
			return "error";
		case DDWAF_LOG_WARN:
			return "warn";
		case DDWAF_LOG_INFO:
			return "info";
		case DDWAF_LOG_OFF:
			break;
	}
	
	return "off";
}

void log_cb(DDWAF_LOG_LEVEL level,
			const char* function, const char* file, unsigned line,
			const char* message, uint64_t)
{
	printf("[%s][%s:%s:%u]: %s\n", level_to_str(level), file, function, line, message);
}

#endif

namespace YAML
{
	ddwaf_object node_to_arg(const Node& node)
	{
		switch (node.Type())
		{
			case NodeType::Sequence:
			{
				ddwaf_object arg;
				ddwaf_object_array(&arg);
				for (auto it = node.begin(); it != node.end(); ++it)
				{
					ddwaf_object child = node_to_arg(*it);
					ddwaf_object_array_add(&arg, &child);
				}
				return arg;
			}
			case NodeType::Map:
			{
				ddwaf_object arg;
				ddwaf_object_map(&arg);
				for (auto it = node.begin(); it != node.end(); ++it)
				{
					std::string key    = it->first.as<std::string>();
					ddwaf_object child = node_to_arg(it->second);
					ddwaf_object_map_addl(&arg, key.c_str(), key.size(), &child);
				}
				return arg;
			}
			case NodeType::Scalar:
			{
				const std::string& value = node.Scalar();
				ddwaf_object arg;
				ddwaf_object_stringl(&arg, value.c_str(), value.size());
				return arg;
			}
			case NodeType::Null:
			case NodeType::Undefined:
				ddwaf_object arg;
				ddwaf_object_invalid(&arg);
				return arg;
		}
		
		throw std::runtime_error("Invalid YAML node type");
	}
	
	template <>
	struct as_if<ddwaf_object, void>
	{
		explicit as_if(const Node& node_) : node(node_) {}
		ddwaf_object operator()() const { return node_to_arg(node); }
		const Node& node;
	};
	
}

std::string read_rule_file(const std::string_view& filename)
{
	std::ifstream rule_file(filename.data(), std::ios::in);
	if (!rule_file)
	{
		throw std::system_error(errno, std::generic_category());
	}
	
	// Create a buffer equal to the file size
	std::string buffer;
	rule_file.seekg(0, std::ios::end);
	buffer.resize(rule_file.tellg());
	rule_file.seekg(0, std::ios::beg);
	
	rule_file.read(&buffer[0], buffer.size());
	rule_file.close();
	return buffer;
}

ddwaf_object convertRuleToRuleset(YAML::Node rulePayload)
{
	ddwaf_object rule   = rulePayload.as<ddwaf_object>(), root, version, array;
	
	ddwaf_object_map(&root);
	ddwaf_object_array(&array);
	ddwaf_object_array_add(&array, &rule);
	
	ddwaf_object_map_add(&root, "version", ddwaf_object_string(&version, "2.1"));
	ddwaf_object_map_add(&root, "rules", &array);
	return root;
}

bool runVectors(YAML::Node rule, ddwaf_handle handle, bool runPositiveMatches)
{
	bool success = true;
	std::string ruleID = rule["id"].as<std::string>();
	YAML::Node matches = rule["test_vectors"][runPositiveMatches ? "matches" : "no_matches"];
	if (matches != nullptr)
	{
		size_t counter = 0;
		for (YAML::const_iterator vector = matches.begin(); vector != matches.end(); ++vector, ++counter) {
			ddwaf_object root = vector->as<ddwaf_object>();
			if(root.type != DDWAF_OBJ_INVALID) {
				ddwaf_context ctx = ddwaf_context_init(handle, NULL);
				DDWAF_RET_CODE ret = ddwaf_run(ctx, &root, NULL, LONG_TIME);
				
				bool hadError = ret < DDWAF_GOOD;
				bool hadMatch = !hadError && ret != DDWAF_GOOD;
				
				if (hadError) {
					printf("The WAF encountered an error processing rule %s and %s test vector #%zu\n", rule["id"].as<std::string>().data(), runPositiveMatches ? "positive" : "negative", counter);
					success = false;
				} else if (runPositiveMatches && !hadMatch) {
					printf("Rule %s didn't match positive test vector #%zu\n", rule["id"].as<std::string>().data(), counter);
					success = false;
				} else if (!runPositiveMatches && hadMatch) {
					printf("Rule %s matched negative test vector #%zu\n", rule["id"].as<std::string>().data(), counter);
					success = false;
				}
				
				ddwaf_context_destroy(ctx);
				ddwaf_object_free(&root);
			}
		}
	}
	return success;
}

int main(int argc, char* argv[])
{
#ifdef VERBOSE
	ddwaf_set_log_cb(log_cb, DDWAF_LOG_TRACE);
#endif
	
	if (argc < 2)
	{
		printf("Usage: %s <json/yaml file>\n", argv[0]);
		return EXIT_FAILURE;
	}
	
	bool success = true;
	for(int fileIndex = 1; fileIndex < argc; ++fileIndex)
	{
#ifdef VERBOSE
		printf("Processing %s\n", argv[fileIndex]);
#endif
		YAML::Node rule = YAML::Load(read_rule_file(argv[fileIndex]));
		ddwaf_object convertedRule = convertRuleToRuleset(rule);
		ddwaf_handle handle = ddwaf_init(&convertedRule, nullptr);
		ddwaf_object_free(&convertedRule);
		
		if (handle == nullptr)
		{
			printf("Failed to load rule %s\n", argv[fileIndex]);
			success = false;
			continue;
		}
		
		if(rule["test_vectors"] != nullptr)
		{
			// Run positive test vectors (patterns the rule should match)
			success &= runVectors(rule, handle, true);
			
			// Run negative test vectors (patterns the rule shouldn't match)
			success &= runVectors(rule, handle, false);
		}
		
		ddwaf_destroy(handle);
	}
	
	if (success)
	{
		printf("Validated a total of %d rules\n", argc);
	}
	
	return success ? EXIT_SUCCESS : EXIT_FAILURE;
}

