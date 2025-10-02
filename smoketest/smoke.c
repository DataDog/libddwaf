#include <ddwaf.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <math.h>

#define STRL(value) value, sizeof(value) - 1

static ddwaf_object prepare_rule(ddwaf_allocator alloc) {
    ddwaf_object ret;
    ddwaf_object_set_map(&ret, 2, alloc);

    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(&ret, STRL("version"), alloc), STRL("2.1"));

    ddwaf_object *rules = ddwaf_object_insert_key(&ret, STRL("rules"), alloc);
    ddwaf_object_set_array(rules, 1, alloc);

    ddwaf_object *rule = ddwaf_object_insert(rules, alloc);
    ddwaf_object_set_map(rule, 5, alloc);

    ddwaf_object_set_string(
        ddwaf_object_insert_key(rule, STRL("id"), alloc), STRL("arachni_rule"), alloc);

    ddwaf_object_set_string(
        ddwaf_object_insert_key(rule, STRL("name"), alloc), STRL("Arachni"), alloc);

    ddwaf_object *conditions = ddwaf_object_insert_key(rule, STRL("conditions"), alloc);
    ddwaf_object_set_array(conditions, 1, alloc);

    ddwaf_object *condition = ddwaf_object_insert(conditions, alloc);
    ddwaf_object_set_map(condition, 2, alloc);

    ddwaf_object_set_string(
        ddwaf_object_insert_key(condition, STRL("operator"), alloc), STRL("match_regex"), alloc);

    ddwaf_object *parameters = ddwaf_object_insert_key(condition, STRL("parameters"), alloc);
    ddwaf_object_set_map(parameters, 2, alloc);

    ddwaf_object *inputs = ddwaf_object_insert_key(parameters, STRL("inputs"), alloc);
    ddwaf_object_set_array(inputs, 1, alloc);

    ddwaf_object *key = ddwaf_object_insert(inputs, alloc);
    ddwaf_object_set_map(key, 1, alloc);

    ddwaf_object_set_string(
        ddwaf_object_insert_key(key, STRL("address"), alloc), STRL("key"), alloc);

    ddwaf_object_set_string(
        ddwaf_object_insert_key(parameters, STRL("regex"), alloc), STRL("Arachni"), alloc);

    ddwaf_object *tags = ddwaf_object_insert_key(rule, STRL("tags"), alloc);
    ddwaf_object_set_map(tags, 1, alloc);
    ddwaf_object_set_string(
            ddwaf_object_insert_key(tags, STRL("type"), alloc), STRL("arachni_detection"), alloc);


    ddwaf_object *actions = ddwaf_object_insert_key(rule, STRL("actions"), alloc);
    ddwaf_object_set_array(actions, 1, alloc);
    ddwaf_object_set_string(ddwaf_object_insert(actions, alloc), STRL("record"), alloc);

    return ret;
}

typedef struct {
    char *buffer;
    size_t capacity;
    size_t offset;
} hstring;

#define INITIAL_CAPACITY ((size_t)16)

#if defined(__GNUC__) || defined(__clang__)
# define max(a, b)                                                              \
    ({                                                                         \
        __typeof__(a) _a = (a);                                                \
        __typeof__(b) _b = (b);                                                \
        _a > _b ? _a : _b;                                                     \
    })
#else
// this evaluates a and b twice though
# define max(a, b)  (((a) > (b)) ? (a) : (b))
#endif

static bool _hstring_ensure_extra_capacity(hstring *str, size_t data_size)
{
    size_t left = str->capacity - str->offset;
    if (left < data_size) {
        size_t new_capacity = max(str->capacity * 2, str->capacity + data_size);
        if (new_capacity < str->capacity) { // wrap-around
            return false;
        }
        char *new_buffer = realloc(str->buffer, new_capacity);
        if (!new_buffer) {
            return false;
        }
        str->buffer = new_buffer;
        str->capacity = new_capacity;
    }
    return true;

}
static void _hstring_append(hstring *str, const char *data, size_t data_size)
{
    if (data_size == 0) {
        return;
    }
    if (!_hstring_ensure_extra_capacity(str, data_size)) {
        return;
    }
#ifndef __clang_analyzer__
    // clang analyzer doesn't seem to look into ensure_extra_capacity
    memcpy(str->buffer + str->offset, data, data_size);
#endif
    str->offset += data_size;
}
#define HSTRING_APPEND_CONST(str, constant) \
    do { _hstring_append(str, constant "", sizeof(constant) - 1); } while (0)

static void _hstring_repeat(hstring *str, char c, size_t repeat_times)
{
    if (repeat_times == 0) {
        return;
    }
    if (!_hstring_ensure_extra_capacity(str, repeat_times)) {
        return;
    }
    for (size_t i = 0; i < repeat_times; i++) {
#ifndef __clang_analyzer__
    // clang analyzer doesn't seem to look into ensure_extra_capacity
        str->buffer[str->offset + i] = c;
#endif
    }
    str->offset += repeat_times;
}

static void _hstring_write_pwargs(hstring *str, size_t depth,
                                  const ddwaf_object *pwargs)
{
    if (depth > 25) { // arbitrary cutoff to avoid stackoverflows
        return;
    }
    _hstring_repeat(str, ' ', depth * 2);
    switch (pwargs->type) {
    case DDWAF_OBJ_INVALID:
        HSTRING_APPEND_CONST(str, "<INVALID>\n");
        break;
    case DDWAF_OBJ_SIGNED: {
        HSTRING_APPEND_CONST(str, "<SIGNED> ");
        char scratch[sizeof("-9223372036854775808")];
        int len = snprintf(scratch, sizeof(scratch), "%" PRId64,
                           ddwaf_object_get_signed(pwargs));
        if ((size_t) len < sizeof scratch) {
            _hstring_append(str, scratch, (size_t) len);
        } // else should never happen
        HSTRING_APPEND_CONST(str, "\n");
        break;
    }
    case DDWAF_OBJ_UNSIGNED: {
        HSTRING_APPEND_CONST(str, "<UNSIGNED> ");
        char scratch[sizeof("18446744073709551615")];
        int len = snprintf(scratch, sizeof(scratch), "%" PRIu64,
                           ddwaf_object_get_unsigned(pwargs));
        if ((size_t) len < sizeof scratch) {
            _hstring_append(str, scratch, (size_t) len);
        } // else should never happen
        HSTRING_APPEND_CONST(str, "\n");
        break;
    }
    case DDWAF_OBJ_STRING: {
        HSTRING_APPEND_CONST(str, "<STRING> ");
        size_t len;
        const char *data = ddwaf_object_get_string(pwargs, &len);
        _hstring_append(str, data, len);
        HSTRING_APPEND_CONST(str, "\n");
        break;
    }
    case DDWAF_OBJ_ARRAY: {
        HSTRING_APPEND_CONST(str, "<ARRAY>\n");
        for (size_t i = 0; i < ddwaf_object_get_size(pwargs); i++) {
            _hstring_write_pwargs(str, depth + 1, ddwaf_object_at_value(pwargs, i));
        }
        break;
    case DDWAF_OBJ_MAP: {
        HSTRING_APPEND_CONST(str, "<MAP>\n");
        for (size_t i = 0; i < ddwaf_object_get_size(pwargs); i++) {
            const ddwaf_object *key = ddwaf_object_at_key(pwargs, i);
            size_t key_len;
            const char *key_data = ddwaf_object_get_string(key, &key_len);
            _hstring_append(str, key_data, key_len);
            HSTRING_APPEND_CONST(str, ": ");
            _hstring_write_pwargs(str, depth + 1, ddwaf_object_at_value(pwargs, i));
        }
        break;
    }
    default:
        HSTRING_APPEND_CONST(str, "<UNKNOWN>\n");
        break;
    }
    }
}

static void dump(ddwaf_object *obj) {
    hstring str = {
        .buffer = malloc(INITIAL_CAPACITY),
        .capacity = INITIAL_CAPACITY
    };
    _hstring_write_pwargs(&str, 0, obj);
    fprintf(stderr, "%.*s\n", (int)str.offset, str.buffer);
}

static void log_cb(
    DDWAF_LOG_LEVEL level, const char* function, const char* file, unsigned line,
    const char* message, uint64_t message_len)
{
    fprintf(stderr, "%.*s\n", (int) message_len, message);
}

int main() {
    const char * version = ddwaf_get_version();
    printf("ddwaf version: %s\n", version);

    ddwaf_set_log_cb(log_cb, DDWAF_LOG_DEBUG);

    ddwaf_allocator alloc = ddwaf_get_default_allocator();

    ddwaf_object rule = prepare_rule(alloc);
    dump(&rule);

    ddwaf_handle handle = ddwaf_init(&rule, NULL);
    if (!handle) {
        puts("handle is null");
        return 1;
    }

    puts("addresses:");
    uint32_t addrs_size = 0;
    const char * const* addrs = ddwaf_known_addresses(handle, &addrs_size);
    for (uint32_t i = 0; i < addrs_size; ++i) {
        puts(addrs[i]);
    }

    puts("actions:");
    uint32_t actions_size = 0;
    const char * const* actions = ddwaf_known_actions(handle, &actions_size);
    for (uint32_t i = 0; i < actions_size; ++i) {
        puts(actions[i]);
    }

    ddwaf_context ctx = ddwaf_context_init(handle, alloc);
    if (!ctx) {
        puts("ctx is null");
        return 1;
    }

    ddwaf_object data;
    ddwaf_object_set_map(&data, 1, alloc);

    ddwaf_object_set_string(
        ddwaf_object_insert_key(&data, STRL("key"), alloc), STRL("Arachni"), alloc);

    ddwaf_object result = {0};
    ddwaf_context_eval(ctx, &data, alloc, &result, (uint32_t)-1);
    

    const ddwaf_object *events = ddwaf_object_find(&result, "events", sizeof("events") - 1);
    if (ddwaf_object_get_size(events) == 0) {
        puts("result is empty");
        return 1;
    }
    puts("result is valid");
    ddwaf_object_destroy(&result, alloc);

    return 0;
}
