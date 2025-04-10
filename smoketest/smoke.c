#include <ddwaf.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <math.h>

static ddwaf_object *prepare_rule() {
    ddwaf_object *ret = malloc(sizeof *ret);
    ddwaf_object_map(ret);

    ddwaf_object version;
    ddwaf_object_map_add(ret, "version", ddwaf_object_string(&version, "2.1"));

    ddwaf_object events;
    ddwaf_object_array(&events);

    ddwaf_object event;
    ddwaf_object_map(&event);

#define DDSTR(str) (ddwaf_object_string(&(ddwaf_object){0}, str ""))

    ddwaf_object_map_add(&event, "id", DDSTR("arachni_rule"));
    ddwaf_object_map_add(&event, "name", DDSTR("Arachni"));

    ddwaf_object conditions;
    ddwaf_object_array(&conditions);

    ddwaf_object condition;
    ddwaf_object_map(&condition);

    ddwaf_object_map_add(&condition, "operator", DDSTR("match_regex"));

    ddwaf_object parameters;
    ddwaf_object_map(&parameters);

    ddwaf_object inputs;
    ddwaf_object_array(&inputs);
    ddwaf_object key;
    ddwaf_object_map(&key);
    ddwaf_object_map_add(&key, "address", DDSTR("key"));
    ddwaf_object_array_add(&inputs, &key);
    ddwaf_object_map_add(&parameters, "inputs", &inputs);
    ddwaf_object_map_add(&parameters, "regex", DDSTR("Arachni"));
    ddwaf_object_map_add(&condition, "parameters", &parameters);

    ddwaf_object_array_add(&conditions, &condition);
    ddwaf_object_map_add(&event, "conditions", &conditions);

    ddwaf_object tags;
    ddwaf_object_map(&tags);
    ddwaf_object_map_add(&tags, "type", DDSTR("arachni_detection"));
    ddwaf_object_map_add(&event, "tags", &tags);

    ddwaf_object_map_add(&event, "action", DDSTR("record"));

    ddwaf_object_array_add(&events, &event);
    ddwaf_object_map_add(ret, "rules", &events);

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
                           pwargs->via.i64);
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
                           pwargs->via.u64);
        if ((size_t) len < sizeof scratch) {
            _hstring_append(str, scratch, (size_t) len);
        } // else should never happen
        HSTRING_APPEND_CONST(str, "\n");
        break;
    }
    case DDWAF_OBJ_STRING:
        HSTRING_APPEND_CONST(str, "<STRING> ");
        _hstring_append(str, pwargs->via.str, pwargs->size);
        HSTRING_APPEND_CONST(str, "\n");
        break;
    case DDWAF_OBJ_ARRAY: {
        HSTRING_APPEND_CONST(str, "<ARRAY>\n");
        for (size_t i = 0; i < pwargs->size; i++) {
            _hstring_write_pwargs(str, depth + 1, pwargs->via.array + i);
        }
        break;
    case DDWAF_OBJ_MAP: {
        HSTRING_APPEND_CONST(str, "<MAP>\n");
        for (size_t i = 0; i < pwargs->size; i++) {
            const ddwaf_object *key = &pwargs->via.map[i].key;
            _hstring_append(str, key->via.str, key->size);
            HSTRING_APPEND_CONST(str, ": ");
            _hstring_write_pwargs(str, depth + 1, &pwargs->via.map[i].val);
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

    ddwaf_object *rule = prepare_rule();
    dump(rule);

    ddwaf_handle handle = ddwaf_init(rule, NULL, NULL);
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


    ddwaf_context ctx = ddwaf_context_init(handle);
    if (!ctx) {
        puts("ctx is null");
        return 1;
    }

    ddwaf_object data;
    ddwaf_object_map(&data);
    ddwaf_object_map_add(&data, "key", DDSTR("Arachni"));

    ddwaf_result result = {0};
    ddwaf_run(ctx, &data, NULL, &result, (uint32_t)-1);

    if (ddwaf_object_size(&result.events) == 0) {
        puts("result is empty");
        return 1;
    }
    puts("result is valid");

    return 0;
}
