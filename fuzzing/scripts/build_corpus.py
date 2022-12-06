#!/usr/bin/env python3

import ipaddress
import json
import yaml
import os
from random import randint, random, choice, choices
# from string import printable as printable_chars
import struct

# No \n or \r
printable_chars='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\x0b\x0c'

class data():
    re2_regexs_with_metadata = json.load(open("fuzzing/data/regex.json", "r"))
    blns = json.load(open("fuzzing/data/blns.json", "r"))


class cached_property(object):
    """
    Descriptor (non-data) for building an attribute on-demand on first use.
    """
    def __init__(self, factory):
        """
        <factory> is called such: factory(instance) to build the attribute.
        """
        self._attr_name = factory.__name__
        self._factory = factory

    def __get__(self, instance, owner):
        # Build the attribute.
        attr = self._factory(instance)

        # Cache the value; hide ourselves.
        setattr(instance, self._attr_name, attr)

        return attr


class _UnicodeMap(object):
    def get_random_unicode(self, min_length=1, max_length=255):
        length = randint(min_length, max_length)
        return "".join(choices(self._unicode_list, k=length))

    def get_random_unicode_char(self):
        return choice(self._unicode_list)

    @cached_property
    def _unicode_list(self):
        result = []

        def append(*args):
            value = bytes(args).decode()
            result.append(value)

        for i in range(0b01111111 + 1):
            append(i)

        for i in range(0b11000010, 0b11011111 + 1):
            for j in range(0b10000000, 0b10111111 + 1):
                append(i, j)

        # 11100000 101xxxxx 10xxxxxx
        for j in range(0b10100000, 0b10111111 + 1):
            for k in range(0b10000000, 0b10111111 + 1):
                append(0b11100000, j, k)

        # 11100001 10xxxxxx 10xxxxxx
        for j in range(0b10000000, 0b10111111 + 1):
            for k in range(0b10000000, 0b10111111 + 1):
                append(0b11100001, j, k)

        # 1110001x 10xxxxxx 10xxxxxx
        for i in range(0b11100010, 0b11100011 + 1):
            for j in range(0b10000000, 0b10111111 + 1):
                for k in range(0b10000000, 0b10111111 + 1):
                    append(i, j, k)

        # 111001xx 10xxxxxx 10xxxxxx
        for i in range(0b11100100, 0b11100111 + 1):
            for j in range(0b10000000, 0b10111111 + 1):
                for k in range(0b10000000, 0b10111111 + 1):
                    append(i, j, k)

        # 111010xx 10xxxxxx 10xxxxxx
        for i in range(0b11101000, 0b11101011 + 1):
            for j in range(0b10000000, 0b10111111 + 1):
                for k in range(0b10000000, 0b10111111 + 1):
                    append(i, j, k)

        # 11101100 10xxxxxx 10xxxxxx
        for j in range(0b10000000, 0b10111111 + 1):
            for k in range(0b10000000, 0b10111111 + 1):
                append(0b11101100, j, k)

        # 11101101 100xxxxx 10xxxxxx
        for j in range(0b10000000, 0b10011111 + 1):
            for k in range(0b10000000, 0b10111111 + 1):
                append(0b11101101, j, k)

        # 1110111x 10xxxxxx 10xxxxxx
        for i in range(0b11101110, 0b11101111 + 1):
            for j in range(0b10000000, 0b10111111 + 1):
                for k in range(0b10000000, 0b10111111 + 1):
                    append(i, j, k)

        # 11110000 1001xxxx 10xxxxxx 10xxxxxx
        for j in range(0b10010000, 0b10011111 + 1):
            for k in range(0b10000000, 0b10111111 + 1):
                for l in range(0b10000000, 0b10111111 + 1):
                    append(0b11110000, j, k, l)

        # 11110000 101xxxxx 10xxxxxx 10xxxxxx
        for j in range(0b10100000, 0b10111111 + 1):
            for k in range(0b10000000, 0b10111111 + 1):
                for l in range(0b10000000, 0b10111111 + 1):
                    append(0b11110000, j, k, l)

        # 11110001 10xxxxxx 10xxxxxx 10xxxxxx
        for j in range(0b10000000, 0b10111111 + 1):
            for k in range(0b10000000, 0b10111111 + 1):
                for l in range(0b10000000, 0b10111111 + 1):
                    append(0b11110001, j, k, l)

        # 1111001x 10xxxxxx 10xxxxxx 10xxxxxx
        for i in range(0b11110010, 0b11110011 + 1):
            for j in range(0b10000000, 0b10111111 + 1):
                for k in range(0b10000000, 0b10111111 + 1):
                    for l in range(0b10000000, 0b10111111 + 1):
                        append(i, j, k, l)

        # 11110100 1000xxxx 10xxxxxx 10xxxxxx
        for j in range(0b10000000, 0b10001111 + 1):
            for k in range(0b10000000, 0b10111111 + 1):
                for l in range(0b10000000, 0b10111111 + 1):
                    append(0b11110100, j, k, l)

        return result


_unicode_map = _UnicodeMap()
get_random_unicode = _unicode_map.get_random_unicode
get_random_unicode_char = _unicode_map.get_random_unicode_char


def _lograndint(a, b, flatness=10):
    return int(random()**flatness * (b - a + 1)) + a


def _get_random_array2(alphabet, min_length=0, max_length=2, allow_none=True, unique=False):
    length = randint(min_length, max_length)

    if allow_none and randint(0, length + 1) == 0:
        return None

    result = choices(alphabet, k=length)

    if unique:
        result = list(set(result))

    return result


def _get_random_array(builder, min_length=0, max_length=2, allow_none=True, **kwargs):
    length = randint(min_length, max_length)

    if allow_none and randint(0, length + 1) == 0:
        return None

    return [builder(i=i, **kwargs) for i in range(length)]


def _get_random_ipv4():
    return  ipaddress.IPv4Address._string_from_ip_int(
        randint(0, ipaddress.IPv4Address._ALL_ONES)
    )


def _get_random_ipv6():
    return ipaddress.IPv6Address._string_from_ip_int(
        randint(0, ipaddress.IPv6Address._ALL_ONES)
    )


def get_random_ip():
    return choice([_get_random_ipv6, _get_random_ipv4])()


class InitPayloadGenerator:
    rule_id_max_length = 32
    address_name_length = 32

    # Arrays max sizes
    condition_max_count = 8
    rule_max_count = 100
    filter_max_count = 100
    key_path_max_count = 10

    address_max_count = 16
    transformation_max_count = 10

    ip_max_count = 100

    operators = [
        "match_regex",
        "phrase_match",
        "is_xss",
        "is_sqli",
        "exact_match",
        "ip_match"
    ]

    def __init__(self):
        self.addresses = None
        self.rule_ids = None

        self.regexs = data.re2_regexs_with_metadata

        self.possible_values = choices(data.blns, k=20)

        self.possible_values += [get_random_unicode(10, 100) for _ in range(20)]

        self.possible_values += [
            "",
            0,
            -1,
            1.12,
            256,
            257,
            1024,
            1025,
            True,
            False,
            2**64 - 1,
            -(2**63),
            # " " * 1000000,
        ]

        self.possible_values += [get_random_ip() for _ in range(100)]
        self.possible_values += [ "block", "block_request", "monitor", "redirect" ]

        self.used_operators = None

    def save_value(self, value, addresses):
        self.values.add(value)

        if value is None:
            pass
        else:
            for address in addresses:
                self.address_values.add((address.get("address"), value))

    def get_payload(self):
        self.used_operators = set()

        # At least one address with a ':'
        self.rule_ids = []
        self.values = set()
        self.address_values = set()

        def get_random_rule_id():
            result = "".join(choices(printable_chars, k=_lograndint(1, self.rule_id_max_length)))
            while result in self.rule_ids:
                result = "".join(choices(printable_chars, k=_lograndint(1, self.rule_id_max_length)))
            self.rule_ids.append(result)
            return result

        def get_random_rule_name():
            result = "".join(choices(printable_chars, k=_lograndint(1, self.rule_id_max_length)))
            return result

        def get_random_rule():
            return {
                "id": get_random_rule_id(),
                "name": get_random_rule_name(),
                "tags": {
                    "type": "".join(choices(printable_chars, k=10)),
                    "crs_id": "".join(choices(printable_chars, k=10)),
                },
                "on_match": get_random_action_array(),
                "conditions": get_random_condition_array(),
                "transformers": get_random_transformation_array(),
            }

        def get_random_exclusion_filter(i):
            # Conditions
            ex_filter = {
                "id": get_random_rule_id(),
            }
            if choice((True, False)):
                ex_filter["conditions"] = get_random_condition_array();

            # Rules
            if choice((True, False)):
                rules = _get_random_array2(self.rule_ids, 1, len(self.rule_ids), allow_none=False, unique=True)
                if rules is not None:
                    ex_filter["rules_target"] =  [{"rule_id": value} for value in rules]

            # Inputs
            if choice((True, False)):
                ex_filter["inputs"] = get_random_address_array()

            return ex_filter;

        def get_random_condition_array():
            return _get_random_array(get_random_condition, 1, self.condition_max_count, allow_none=False)

        def get_random_operator():
            operator = choice(self.operators)
            self.used_operators.add(operator)

            return operator

        def get_random_address_array():
            addresses = _get_random_array2(self.addresses, 1, self.address_max_count, allow_none=False, unique=True)
            final_addresses = []
            for address in addresses:
                if choices((True, False)):
                    key_path = ["".join(choices(printable_chars, k=_lograndint(1, self.address_name_length)))
                        for _ in range(_lograndint(1, self.key_path_max_count))
                    ]

                    final_addresses.append({"address": address, "key_path": key_path})
                else:
                    final_addresses.append({"address": address})
            return final_addresses

        def get_random_transformation_array():
            """Id are presents in getIDForString function"""

            return _get_random_array2(
                [
                    "urlDecodeUni",
                    "htmlEntityDecode",
                    "jsDecode",
                    "cssDecode",
                    "cmdLine",
                    "base64Decode",
                    "base64DecodeExt",
                    "urlDecode",
                    "removeNulls",
                    "normalizePath",
                    "normalizePathWin",
                    "compressWhiteSpace",
                    "lowercase",
                    # "length",  # no really complex, and will skip a lot of use cases
                    "base64Encode",
                    "_sqr_basename",
                    "_sqr_filename",
                    "_sqr_querystring",
                    "removeComments",
                    "numerize",
                    "keys_only",
                    "unicode_normalize",
                ],
                0,
                self.transformation_max_count,
                allow_none=True,
            )

        def get_random_value(addresses):
            result = choice(self.possible_values, )
            result = result if result is not None else ""

            self.save_value(result, addresses)

            return result

        def get_random_condition(i):
            operator = get_random_operator()
            addresses = get_random_address_array()

            result = {
                "operator": operator,
                "parameters": {
                    "inputs": addresses
                },
            }

            if operator == "phrase_match":
                result["parameters"]["list"] = [get_random_value(addresses) for _ in range(randint(1, 200))]
            elif operator == "match_regex":
                temp = choice(self.regexs)

                self.save_value(temp["MatchingText"], addresses)
                self.save_value(temp["NonMatchingText"], addresses)

                result["parameters"]["regex"] = temp["Pattern"]
                result["parameters"]["options"] = {
                  "case_sensitive": choice((True, False)),
                  "min_length": randint(0, 5),
                }
            elif operator == "is_xss":
                # TODO: get interesting XSS patterns
                result["parameters"]["list"] = [get_random_value(addresses) for _ in range(randint(1, 200))]

            elif operator == "is_sqli":
                # TODO: get interesting SQLI patterns
                result["parameters"]["list"] = [get_random_value(addresses) for _ in range(randint(1, 200))]

            elif operator == "exact_match":
                result["parameters"]["list"] = [get_random_value(addresses) for _ in range(randint(1, 200))]

            elif operator == "ip_match":
                result["parameters"]["list"] = [get_random_value(addresses) for _ in range(randint(1, 200))]

            return result

        def get_random_rules():
            return [get_random_rule() for _ in range(self.rule_max_count)]

        def get_random_exclusion_filters():
            return _get_random_array(get_random_exclusion_filter, 1, self.filter_max_count, allow_none=True)

        def get_random_action_array():
            return [choice(self.possible_values, ) for _ in range(randint(0, 3))]

        def get_random_addresses():
            return ["".join(choices(printable_chars, k=_lograndint(1, self.address_name_length)))
                for _ in range(self.address_max_count)
            ]

        # Some of these inputs and rules will be excluded
        self.addresses = get_random_addresses()
        excluded_rules = get_random_rules()
        filters = get_random_exclusion_filters()

        all_addresses = self.addresses

        # None of these inputs and rules should be excluded
        self.addresses = get_random_addresses()
        non_excluded_rules = get_random_rules()

        all_addresses += self.addresses

        result = {
            "init_payload": {
                "version": "2.1",
                # "exclusions": filters,
                "rules": excluded_rules + non_excluded_rules
            },

            "addresses": all_addresses,
            "values": self.values,
            "address_values": self.address_values
        }

        return result

    def __iter__(self):
        while True:
            yield self.get_payload()


def main():
    generator = InitPayloadGenerator()

    def to_fuzz_dict(c):

        if c == '"':
            return r"\""

        if c == "\\":
            return "\\\\"

        if 32 <= ord(c) < 127: # 127 is DEL, libfuzz does not like it as is
            return c

        return "".join("\\x{:02x}".format(i) for i in c.encode("utf-8"))

    payload = generator.get_payload()
    yaml.dump(payload["init_payload"], open("fuzzing/sample_rules.yml", "w"), default_flow_style=False)

    with open("fuzzing/sample_dict.txt", "w") as f:
        libfuzz_magics = [
            "\x06\x06\x06",
        ]

        for item in payload["addresses"] + list(payload["values"]) + libfuzz_magics:
            if isinstance(item, str):
                f.write("# " + repr(item) + "\n")
                f.write('"\\x02' + "".join(map(to_fuzz_dict, str(item))) + '\\x1f"\n')
                f.write("\n")

    try:
        os.mkdir('fuzzing/corpus')
    except FileExistsError:
        pass

    for i, (input, value) in enumerate(payload["address_values"]):
        write_corpus_file(f"corpus_{i}", {input: value})

    print(f"{len(generator.used_operators)} operators")
    print(f"{len(payload['addresses'])} addresses")
    print(f"{len(payload['values'])} values")


def build_string_corpus(item):
    return list(item.encode("utf-8")) + [31 ,]


def build_payload_corpus(data):
    if isinstance(data, dict):
        result = [0, len(data)]

        for key, value in data.items():
            result += build_string_corpus(key)
            result += build_payload_corpus(value)

    elif isinstance(data, list):
        result = [1, len(data)]

        for value in data:
            result += build_payload_corpus(value)

    elif isinstance(data, str):
        result = [2, ] + build_string_corpus(data)

    elif isinstance(data, int) and -2**63 <= data < 0:
        result = [3, ] + list(struct.pack('<q', data))

    elif isinstance(data, int) and 0<= data <= 2**64-1:
        result = [4, ] + list(struct.pack('<Q', data))

    elif isinstance(data, (int, float)):
        result = [4, ] + list(struct.pack('<Q', 0))

    else:
        raise Exception(f"not supported : {data}")

    return result

def write_corpus_file(filename, data, log_byte=0, reload_rules=False):
    reload_rules = 66 if reload_rules else 0

    with open(f"fuzzing/corpus/{filename}", "wb") as f:
        f.write(bytearray([log_byte, 0, reload_rules]))
        f.write(bytearray(build_payload_corpus(data)))


if __name__ == "__main__":
    main()
