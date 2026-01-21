#!/usr/bin/env python3
"""
Generate C API documentation for libddwaf.

This script:
1. Runs Doxygen to generate XML from include/ddwaf.h
2. Converts the XML to a single Markdown file
3. Cleans up the intermediate Doxygen files

Usage:
    ./tools/generate_documentation.py [--keep-xml]

Options:
    --keep-xml    Keep the intermediate Doxygen XML files
"""

import xml.etree.ElementTree as ET
import subprocess
import shutil
import sys
import re
import tempfile
from pathlib import Path


def get_text(element):
    """Extract all text content from an element, handling nested elements."""
    if element is None:
        return ""

    result = []
    if element.text:
        result.append(element.text)

    for child in element:
        if child.tag == "para":
            result.append(get_text(child))
            result.append("\n\n")
        elif child.tag == "parameterlist":
            pass  # Handle separately
        elif child.tag == "simplesect":
            pass  # Handle separately
        elif child.tag == "ref":
            result.append(child.text or "")
        elif child.tag == "computeroutput":
            result.append(f"`{child.text or ''}`")
        elif child.tag == "emphasis":
            result.append(f"*{child.text or ''}*")
        elif child.tag == "bold":
            result.append(f"**{child.text or ''}**")
        elif child.tag == "itemizedlist":
            for item in child.findall("listitem"):
                result.append(f"\n- {get_text(item).strip()}")
            result.append("\n")
        elif child.tag == "orderedlist":
            for i, item in enumerate(child.findall("listitem"), 1):
                result.append(f"\n{i}. {get_text(item).strip()}")
            result.append("\n")
        else:
            result.append(get_text(child))

        if child.tail:
            result.append(child.tail)

    return "".join(result).strip()


def extract_description(memberdef):
    """Extract brief and detailed description from a memberdef."""
    brief = memberdef.find("briefdescription")
    detailed = memberdef.find("detaileddescription")

    brief_text = get_text(brief) if brief is not None else ""
    detailed_text = get_text(detailed) if detailed is not None else ""

    if detailed_text:
        return detailed_text
    return brief_text


def extract_params(memberdef):
    """Extract parameter documentation from a memberdef."""
    params = []
    detailed = memberdef.find("detaileddescription")
    if detailed is None:
        return params

    for paramlist in detailed.iter("parameterlist"):
        if paramlist.get("kind") == "param":
            for item in paramlist.findall("parameteritem"):
                name_elem = item.find(".//parametername")
                desc_elem = item.find("parameterdescription")
                if name_elem is not None:
                    name = name_elem.text or ""
                    desc = get_text(desc_elem) if desc_elem is not None else ""
                    params.append((name, desc))

    return params


def extract_return(memberdef):
    """Extract return value documentation."""
    detailed = memberdef.find("detaileddescription")
    if detailed is None:
        return ""

    for simplesect in detailed.iter("simplesect"):
        if simplesect.get("kind") == "return":
            return get_text(simplesect)

    return ""


def extract_retvals(memberdef):
    """Extract return value codes documentation."""
    retvals = []
    detailed = memberdef.find("detaileddescription")
    if detailed is None:
        return retvals

    for paramlist in detailed.iter("parameterlist"):
        if paramlist.get("kind") == "retval":
            for item in paramlist.findall("parameteritem"):
                name_elem = item.find(".//parametername")
                desc_elem = item.find("parameterdescription")
                if name_elem is not None:
                    name = name_elem.text or ""
                    desc = get_text(desc_elem) if desc_elem is not None else ""
                    retvals.append((name, desc))

    return retvals


def extract_notes(memberdef):
    """Extract notes from documentation."""
    notes = []
    detailed = memberdef.find("detaileddescription")
    if detailed is None:
        return notes

    for simplesect in detailed.iter("simplesect"):
        if simplesect.get("kind") == "note":
            notes.append(get_text(simplesect))

    return notes


def format_function_signature(memberdef):
    """Format a function signature."""
    return_type = memberdef.find("type")
    name = memberdef.find("name")

    ret_text = ""
    if return_type is not None:
        ret_text = get_text(return_type)
        for ref in return_type.findall(".//ref"):
            if ref.text:
                ret_text = ret_text.replace(ref.text, ref.text)

    func_name = name.text if name is not None else ""

    params = []
    for param in memberdef.findall("param"):
        param_type = param.find("type")
        param_name = param.find("declname")

        type_text = get_text(param_type) if param_type is not None else ""
        name_text = param_name.text if param_name is not None else ""

        if type_text or name_text:
            params.append(f"{type_text} {name_text}".strip())

    return f"{ret_text} {func_name}({', '.join(params)})"


def format_typedef_signature(memberdef):
    """Format a typedef signature."""
    definition = memberdef.find("definition")
    argsstring = memberdef.find("argsstring")

    def_text = definition.text if definition is not None else ""
    args_text = argsstring.text if argsstring is not None and argsstring.text else ""

    if args_text and args_text in def_text:
        return def_text

    return f"{def_text}{args_text}"


def parse_header_xml(xml_path):
    """Parse the main header XML file."""
    tree = ET.parse(xml_path)
    root = tree.getroot()

    data = {
        "enums": [],
        "typedefs": [],
        "functions": [],
    }

    compounddef = root.find("compounddef")
    if compounddef is None:
        return data

    for sectiondef in compounddef.findall("sectiondef"):
        for memberdef in sectiondef.findall("memberdef"):
            member_kind = memberdef.get("kind")
            name_elem = memberdef.find("name")
            name = name_elem.text if name_elem is not None else ""

            # Skip internal/compiler-specific stuff
            if name.startswith("__") or name.startswith("_ddwaf_object_"):
                continue

            if member_kind == "enum":
                enum_data = {
                    "name": name,
                    "description": extract_description(memberdef),
                    "values": []
                }

                for enumvalue in memberdef.findall("enumvalue"):
                    val_name = enumvalue.find("name")
                    val_init = enumvalue.find("initializer")
                    val_desc = enumvalue.find("detaileddescription")

                    enum_data["values"].append({
                        "name": val_name.text if val_name is not None else "",
                        "value": val_init.text if val_init is not None else "",
                        "description": get_text(val_desc) if val_desc is not None else ""
                    })

                data["enums"].append(enum_data)

            elif member_kind == "typedef":
                typedef_data = {
                    "name": name,
                    "signature": format_typedef_signature(memberdef),
                    "description": extract_description(memberdef),
                    "params": extract_params(memberdef),
                }
                data["typedefs"].append(typedef_data)

            elif member_kind == "function":
                func_data = {
                    "name": name,
                    "signature": format_function_signature(memberdef),
                    "description": extract_description(memberdef),
                    "params": extract_params(memberdef),
                    "return": extract_return(memberdef),
                    "retvals": extract_retvals(memberdef),
                    "notes": extract_notes(memberdef),
                }
                data["functions"].append(func_data)

    return data


def categorize_functions(functions):
    """Categorize functions by their purpose."""
    categories = {
        "Initialization/Destruction": [],
        "Builder": [],
        "Context": [],
        "Subcontext": [],
        "Allocator": [],
        "Object Creation": [],
        "Object Inspection": [],
        "Object Container Operations": [],
        "Object Type Checking": [],
        "Utility": [],
    }

    for func in functions:
        name = func["name"]

        if name in ("ddwaf_init", "ddwaf_destroy"):
            categories["Initialization/Destruction"].append(func)
        elif "builder" in name:
            categories["Builder"].append(func)
        elif "subcontext" in name:
            categories["Subcontext"].append(func)
        elif "context" in name:
            categories["Context"].append(func)
        elif "allocator" in name or name.endswith("_allocator_init"):
            categories["Allocator"].append(func)
        elif name.startswith("ddwaf_object_set_") or name == "ddwaf_object_from_json":
            categories["Object Creation"].append(func)
        elif name.startswith("ddwaf_object_get_"):
            categories["Object Inspection"].append(func)
        elif name.startswith("ddwaf_object_is_"):
            categories["Object Type Checking"].append(func)
        elif name.startswith("ddwaf_object_"):
            categories["Object Container Operations"].append(func)
        elif name.startswith("ddwaf_known_"):
            categories["Initialization/Destruction"].append(func)
        else:
            categories["Utility"].append(func)

    order = [
        "Initialization/Destruction",
        "Builder",
        "Context",
        "Subcontext",
        "Allocator",
        "Object Creation",
        "Object Inspection",
        "Object Container Operations",
        "Object Type Checking",
        "Utility",
    ]

    return [(cat, categories[cat]) for cat in order if categories[cat]]


def generate_markdown(data):
    """Generate markdown from parsed data."""
    lines = []

    # Header
    lines.append("# libddwaf C API Reference")
    lines.append("")
    lines.append("This document describes the public C API of libddwaf.")
    lines.append("")

    # Table of Contents
    lines.append("## Table of Contents")
    lines.append("")
    lines.append("- [Enumerations](#enumerations)")
    for enum in data["enums"]:
        lines.append(f"  - [{enum['name']}](#{enum['name'].lower().replace('_', '-')})")
    lines.append("- [Type Definitions](#type-definitions)")
    lines.append("- [Functions](#functions)")

    func_categories = categorize_functions(data["functions"])
    for category, _ in func_categories:
        anchor = category.lower().replace(" ", "-").replace("/", "")
        lines.append(f"  - [{category}](#{anchor})")

    lines.append("")

    # Enumerations
    lines.append("---")
    lines.append("")
    lines.append("## Enumerations")
    lines.append("")

    for enum in data["enums"]:
        lines.append(f"### {enum['name']}")
        lines.append("")
        if enum["description"]:
            lines.append(enum["description"])
            lines.append("")

        lines.append("| Value | Code | Description |")
        lines.append("|-------|------|-------------|")
        for val in enum["values"]:
            desc = val["description"].replace("\n", " ").strip()
            lines.append(f"| `{val['name']}` | `{val['value']}` | {desc} |")
        lines.append("")

    # Type Definitions
    lines.append("---")
    lines.append("")
    lines.append("## Type Definitions")
    lines.append("")

    notable_typedefs = [t for t in data["typedefs"] if t["description"] or t["params"]]
    simple_typedefs = [t for t in data["typedefs"] if not t["description"] and not t["params"]]

    if simple_typedefs:
        lines.append("### Handle Types")
        lines.append("")
        lines.append("| Type | Definition |")
        lines.append("|------|------------|")
        for typedef in simple_typedefs:
            sig = typedef["signature"].replace("|", "\\|")
            lines.append(f"| `{typedef['name']}` | `{sig}` |")
        lines.append("")

    for typedef in notable_typedefs:
        lines.append(f"### {typedef['name']}")
        lines.append("")
        lines.append("```c")
        lines.append(typedef["signature"])
        lines.append("```")
        lines.append("")

        if typedef["description"]:
            lines.append(typedef["description"])
            lines.append("")

        if typedef["params"]:
            lines.append("**Parameters:**")
            lines.append("")
            for pname, pdesc in typedef["params"]:
                lines.append(f"- `{pname}`: {pdesc}")
            lines.append("")

    # Functions
    lines.append("---")
    lines.append("")
    lines.append("## Functions")
    lines.append("")

    for category, funcs in func_categories:
        lines.append(f"### {category}")
        lines.append("")

        for func in funcs:
            lines.append(f"#### {func['name']}")
            lines.append("")
            lines.append("```c")
            lines.append(func["signature"])
            lines.append("```")
            lines.append("")

            desc = func["description"]
            desc_clean = re.split(r'\n\n', desc)[0] if desc else ""
            if desc_clean:
                lines.append(desc_clean)
                lines.append("")

            if func["params"]:
                lines.append("**Parameters:**")
                lines.append("")
                for pname, pdesc in func["params"]:
                    lines.append(f"- `{pname}`: {pdesc}")
                lines.append("")

            if func["return"]:
                lines.append(f"**Returns:** {func['return']}")
                lines.append("")

            if func["retvals"]:
                lines.append("**Return Values:**")
                lines.append("")
                for rname, rdesc in func["retvals"]:
                    lines.append(f"- `{rname}`: {rdesc}")
                lines.append("")

            if func["notes"]:
                for note in func["notes"]:
                    lines.append(f"> **Note:** {note}")
                    lines.append("")

    return "\n".join(lines)


def run_doxygen(root_dir, output_dir):
    """Run Doxygen to generate XML output."""
    # Create a temporary Doxyfile
    doxyfile_content = f"""
PROJECT_NAME = libddwaf
OUTPUT_DIRECTORY = {output_dir}
INPUT = {root_dir / 'include' / 'ddwaf.h'}
FILE_PATTERNS = *.h
RECURSIVE = NO
EXTRACT_ALL = YES
EXTRACT_STATIC = YES
EXTRACT_PRIVATE = NO
GENERATE_HTML = NO
GENERATE_LATEX = NO
GENERATE_MAN = NO
GENERATE_RTF = NO
GENERATE_DOCBOOK = NO
GENERATE_XML = YES
XML_OUTPUT = xml
QUIET = YES
WARNINGS = NO
"""

    doxyfile_path = output_dir / "Doxyfile"
    doxyfile_path.write_text(doxyfile_content)

    # Run doxygen
    result = subprocess.run(
        ["doxygen", str(doxyfile_path)],
        cwd=root_dir,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"Doxygen error: {result.stderr}")
        return False

    return True


def main():
    # Parse arguments
    keep_xml = "--keep-xml" in sys.argv

    # Determine paths
    script_path = Path(__file__).resolve()
    root_dir = script_path.parent.parent
    output_file = root_dir / "docs" / "c-api" / "api.md"

    # Check for doxygen
    if shutil.which("doxygen") is None:
        print("Error: doxygen not found in PATH")
        print("Please install doxygen: apt install doxygen / brew install doxygen")
        sys.exit(1)

    # Create temporary directory for doxygen output
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        print("Running Doxygen...")
        if not run_doxygen(root_dir, temp_path):
            print("Error: Doxygen failed")
            sys.exit(1)

        # Find the XML file
        xml_file = temp_path / "xml" / "ddwaf_8h.xml"
        if not xml_file.exists():
            print(f"Error: Expected XML file not found: {xml_file}")
            sys.exit(1)

        print("Parsing XML...")
        data = parse_header_xml(xml_file)

        print(f"Found {len(data['enums'])} enums, {len(data['typedefs'])} typedefs, {len(data['functions'])} functions")

        print("Generating Markdown...")
        markdown = generate_markdown(data)

        # Ensure output directory exists
        output_file.parent.mkdir(parents=True, exist_ok=True)

        print(f"Writing {output_file}...")
        output_file.write_text(markdown)

        # Optionally keep XML files
        if keep_xml:
            xml_dest = root_dir / "docs" / "c-api" / "doxygen"
            if xml_dest.exists():
                shutil.rmtree(xml_dest)
            shutil.copytree(temp_path, xml_dest)
            print(f"XML files saved to {xml_dest}")

    print("Done!")


if __name__ == "__main__":
    main()
