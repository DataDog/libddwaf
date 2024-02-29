"""
This script build a fuzzing dict from a samle_rules.json
May be useful for fuzzing other rules set
"""

import yaml


def to_fuzz_dict(c):

    if c == '"':
        return r"\""

    if c == "\\":
        return "\\\\"

    if 32 <= ord(c) <= 127:
        return c

    return "".join("\\x{:02x}".format(i) for i in c.encode("utf-8"))


def load_values():
    data = yaml.safe_load(open("fuzzer/global/sample_rules.yml", "r"))

    results = set()
    for rule in data["rules"]:
        for filter in rule["filters"]:
            for target in filter["targets"]:
                results.add(target)

            if filter["operator"].endswith("rx"):
                pass
            else:
                value = filter["value"]
                if isinstance(value, list):
                    for item in value:
                        results.add(item)
                elif isinstance(value, str):
                    results.add(value)
                elif isinstance(value, (int, float)):
                    results.add(str(value))
                else:
                    raise Exception(f"Not supported : {value}")

    return results


def write_values(values):
    values.add("\x06\x06\x06")  # fuzzer magics

    with open("fuzzer/global/sample_dict.txt", "w") as f:

        for value in values:
            f.write("# " + repr(value) + "\n")
            f.write('"\\x02' + "".join(map(to_fuzz_dict, str(value))) + '\\x1f"\n\n')


def main():

    values = load_values()
    write_values(values)

    for value in values:
        print(value)


main()
