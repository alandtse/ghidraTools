# based on GPL3 code https://github.com/Starfield-Reverse-Engineering/CommonLibSF/pull/221/files by @nikitalita
import re
import argparse
import xml.etree.ElementTree as ET
from collections import deque
from typing import List, Dict, Tuple, Set

# Global variable to store parent map
parent_map: Dict[ET.Element, ET.Element] = {}

# Helper Functions


def stringify_node(node: ET.Element) -> str:
    return ET.tostring(node, encoding="unicode")


def generate_msvc_mangled_name(qualified_name: str) -> str:
    """
    Generate a simplified MSVC mangled name from a C++ qualified name.

    Args:
        qualified_name (str): The qualified name to mangle (e.g., 'RE::DirectInput8').

    Returns:
        str: The mangled name.

    Example:
        >>> generate_msvc_mangled_name("RE::DirectInput8")
        '@DirectInput8@RE@@'

        >>> def test_generate_msvc_mangled_name():
        >>>     patterns = [
        >>>         "RE::DirectInput8",
        >>>         "RE::DirectX",
        >>>         "SFSE::WinAPI",
        >>>         "SFSE::stl",
        >>>         "RE"
        >>>     ]
        >>>     expected_mangled_names = [
        >>>         "@DirectInput8@RE@@",
        >>>         "@DirectX@RE@@",
        >>>         "@WinAPI@SFSE@@",
        >>>         "@stl@SFSE@@",
        >>>         "@RE@@"
        >>>     ]
        >>>     for pattern, expected in zip(patterns, expected_mangled_names):
        >>>         assert generate_msvc_mangled_name(pattern) == expected
    """
    # Generate a mangled name by replacing '::' with '@' and surrounding with '@@'
    parts = qualified_name.split("::")
    mangled_name = "@" + "@".join(reversed(parts)) + "@@"
    return mangled_name


# Function to clean the XML data
def clean_xml(
    data: str, patterns: List[str], replace_patterns: List[Tuple[str, str]]
) -> str:
    """
    Clean the XML data by removing specific patterns and replacing others.

    Args:
        data (str): The XML data as a string.
        patterns (List[str]): List of patterns to remove.
        replace_patterns (List[Tuple[str, str]]): List of patterns and their replacements.

    Returns:
        str: The cleaned XML data.
    """
    for pattern in patterns:
        demangled = r"\b" + re.escape(pattern) + r"::"
        mangled = generate_msvc_mangled_name(pattern)

        # Remove regular pattern
        data = re.sub(demangled, "", data)

        if mangled:
            # Remove mangled pattern
            data = re.sub(re.escape(mangled), "@@", data)

    for pattern, replacement in replace_patterns:
        data = re.sub(pattern, replacement, data)

    return data


def fix_class_inheritance(root: ET.Element) -> None:
    """
    Fix class inheritance by updating 'member' nodes with 'Unknown' kind to 'Member' sequentially,
    stopping when a node with a different kind or both offset and length equal to '0x0' is encountered.

    Args:
        root (ET.Element): The root element of the XML tree.
    """
    for class_node in root.iter("class"):
        seen_non_unknown = False
        total_length = 0
        member_index = 0
        for member in class_node.findall("member"):
            name_attr = member.get("name")
            datatype_attr = member.get("datatype")
            kind_attr = member.get("kind")
            offset_attr = member.get("offset")
            length_attr = member.get("length")

            if offset_attr is not None:
                offset = int(offset_attr, 16)
            else:
                offset = 0

            if length_attr is not None:
                length = int(length_attr, 16)
            else:
                length = 0

            if (
                name_attr
                and not name_attr.startswith("std")
                and not name_attr == "enum_type"
                and not datatype_attr.endswith("*")
                and kind_attr == "Unknown"
                and length_attr
                and not seen_non_unknown
            ):
                if member_index and offset == 0:
                    # offsets need to be increasing if we're handling inheritance
                    break
                if datatype_attr and datatype_attr == class_node.get("name"):
                    # classes cannot inherit from themselves
                    break
                # disabling length check since offsets are not guaranteed to be in order
                # if offset < total_length:
                #     print(
                #         f"Warning: {class_node.get("name")}::{stringify_node(member)} with offset {offset_attr} is less than expected total length {hex(total_length)}. Stopping conversion."
                #     )
                #     break

                member.set("kind", "Member")
                total_length = offset + length
                member_index += 1
            elif (
                datatype_attr == "void *"
                or kind_attr != "Unknown"
                or (offset_attr == "0x0" and length_attr == "0x0")
            ):
                seen_non_unknown = True


def parse_and_modify_xml(xml_data: str, delete_patterns: Dict[str, List[str]]) -> str:
    """
    Parse the XML data, find the <functions> node and clear all its child nodes,
    and delete <class>, <symbol>, <enum>, or <datatype> nodes where the name starts with certain strings.

    Args:
        xml_data (str): The cleaned XML data as a string.
        delete_patterns (Dict[str, List[str]]): Dict of prefixes to identify nodes to be deleted.

    Returns:
        str: The modified XML data as a string.
    """
    tree = ET.ElementTree(ET.fromstring(xml_data))
    root = tree.getroot()

    # Create a parent map during traversal
    global parent_map
    parent_map = {}
    stack = deque([(root, None)])

    while stack:
        node, parent = stack.pop()
        parent_map[node] = parent
        for child in node:
            stack.append((child, node))

    nodes_to_remove = []

    for node in root.iter():
        # Clear all child nodes of <functions>
        if node.tag == "functions":
            node.clear()

        # Check for nodes to remove
        if node.tag in {"class", "symbol", "enum", "datatype", "typedef"}:
            for key, delete_list in delete_patterns.items():
                name_attr = node.get(key)
                if name_attr and any(
                    name_attr.startswith(pattern) for pattern in delete_list
                ):
                    nodes_to_remove.append(node)

    # Remove nodes in a separate step to avoid modifying the tree while iterating
    for node in nodes_to_remove:
        parent = parent_map.get(node)
        if parent is not None and node in parent:
            parent.remove(node)

    # Fix class inheritance by modifying 'member' nodes
    fix_class_inheritance(root)

    # Remove duplicate nodes
    remove_duplicate_nodes(root)

    # Convert the modified XML tree back to a string
    modified_xml_data = ET.tostring(root, encoding="unicode")

    return modified_xml_data


def remove_duplicate_nodes(root: ET.Element) -> None:
    """
    Remove duplicate children containing nodes from the XML tree.

    Args:
        root (ET.Element): The root element of the XML tree.
    """
    seen = set()

    count = 0
    for parent in list(root.iter()):
        duplicates = []
        for child in parent:
            if not len(child):
                # only prune nodes with children
                continue
            if stringify_node(child) in seen:
                duplicates.append(child)
            else:
                seen.add(stringify_node(child))

        for duplicate in duplicates:
            parent.remove(duplicate)
        count += len(duplicates)
    print(f"Removed {count} duplicates")


def collect_related_nodes(root: ET.Element, keep_only_name: str) -> Set[ET.Element]:
    """
    Collect all nodes related to the specified class or datatype name, including those cross-referencing it.

    Args:
        root (ET.Element): The root of the XML tree.
        keep_only_name (str): The name of the class or datatype to keep.

    Returns:
        Set[ET.Element]: A set of related nodes to be retained.
    """
    related_nodes = set()
    queue = deque([root])
    referenced_nodes = set()

    while queue:
        node = queue.popleft()
        name_attr = node.get("name", "")
        datatype_attr = node.get("datatype", "")

        if name_attr.startswith(keep_only_name) or datatype_attr.startswith(
            keep_only_name
        ):
            if node not in related_nodes:
                related_nodes.add(node)
                for child in node.findall(".//*"):
                    if child not in related_nodes:
                        queue.append(child)
                # Add node's name for recursive check
                if name_attr:
                    referenced_nodes.add(name_attr)

    # Check recursively for any node referencing previously found related nodes
    while referenced_nodes:
        current_references = referenced_nodes.copy()
        referenced_nodes.clear()
        for node in root.iter():
            name_attr = node.get("name")
            datatype_attr = node.get("datatype")
            if (
                name_attr in current_references or datatype_attr in current_references
            ) and node not in related_nodes:
                related_nodes.add(node)
                for child in node.findall(".//*"):
                    if child not in related_nodes:
                        queue.append(child)
                # Add node's name for further recursive check
                if name_attr:
                    referenced_nodes.add(name_attr)

    return related_nodes


def retain_only_related_nodes(xml_data: str, keep_only_name: str) -> str:
    """
    Retain only the nodes related to the specified class or datatype name, removing all others.

    Args:
        xml_data (str): The modified XML data as a string.
        keep_only_name (str): The name of the class or datatype to keep.

    Returns:
        str: The final XML data as a string with only related nodes retained.
    """
    tree = ET.ElementTree(ET.fromstring(xml_data))
    root = tree.getroot()
    global parent_map

    related_nodes = collect_related_nodes(root, keep_only_name)

    stack = deque([root])
    while stack:
        node = stack.pop()
        if node not in related_nodes:
            parent = parent_map.get(node)
            if parent is not None and node in parent:
                parent.remove(node)
        else:
            for child in node.findall(".//*"):
                stack.append(child)

    modified_xml_data = ET.tostring(root, encoding="unicode")
    return modified_xml_data


def main():
    # Command line argument parsing
    parser = argparse.ArgumentParser(
        description="Clean XML data by removing specific patterns."
    )
    parser.add_argument("input_file", help="The path to the input XML file.")
    parser.add_argument(
        "-o",
        "--output_file",
        help="The path to the output XML file. If not specified, the input file will be replaced.",
    )
    parser.add_argument("--keep_only", help="Name of the class or datatype to keep.")

    args = parser.parse_args()

    # Read the large XML file
    with open(args.input_file, "r", encoding="utf-8") as file:
        data = file.read()

    # List of patterns to remove (only regular versions)
    patterns = [
        # Starfield
        "SFSE::WinAPI",
        "SFSE::stl",
        # Skyrim
        "SKSE::WinAPI",
        "SKSE::stl",
        # Fallout
        "F4SE::WinAPI",
        "F4SE::stl",
        # CommonLib
        "RE::DirectInput8",
        "RE::DirectX",
        "RE",
        # CommonLibNG
        "REX::W32",
    ]

    # List of replace patterns (regex pattern, replacement string with capture groups)
    replace_patterns = [
        (  # replace stl::enum
            r'datatype="enumeration&lt;enum ([\w:]+),[^"]*"',
            r'datatype="\1"',
        ),
        (  # replace addresses
            r'address="0x[1-9a-f][0-9a-f]*"',
            r'address="0x0"',
        ),
        # template pointers
        (  # BSTSmartPointer since no way for Ghidra to know it's a pointer and it fails `checkAncestry``
            r'datatype="BSTSmartPointer&lt;([\w:,&;]+)(?:,BSTSmartPointerIntrusiveRefCount)?&gt;"',
            r'datatype="\1*"',
        ),
        (  # GPtr, hkRefPtr since no way for Ghidra to know it's a pointer and it fails `checkAncestry``
            r'datatype="(?:G|hkRef)Ptr&lt;([\w:,&;]+)&gt;"',
            r'datatype="\1*"',
        ),
        (  # NiPointer since no way for Ghidra to know it's a pointer and it fails `checkAncestry``
            r'datatype="NiPointer&lt;([\w:,&;]+)&gt;"',
            r'datatype="\1*"',
        ),
    ]

    # List of name prefixes to delete <class> or <symbol> nodes
    delete_patterns = {
        "name": [
            "enumeration&lt;enum ",
            "fmt::",
            "Catch::",
            "spdlog::",
            "std::",
            "binary_io::"
        ],
        "datatype": [
            "enumeration&lt;enum ",
            "fmt::",
            "Catch::",
            "spdlog::",
        ],
    }

    # Clean the data
    cleaned_data = clean_xml(data, patterns, replace_patterns)

    # Parse and modify the cleaned XML
    modified_xml_data = parse_and_modify_xml(cleaned_data, delete_patterns)

    # Retain only the related nodes if keep_only is specified
    if args.keep_only:
        modified_xml_data = retain_only_related_nodes(modified_xml_data, args.keep_only)

    # Write the modified XML data to the output file or replace in place
    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as file:
            file.write(modified_xml_data)
        print(f"Modified XML data written to {args.output_file}")
    else:
        with open(args.input_file, "w", encoding="utf-8") as file:
            file.write(modified_xml_data)
        print(f"Modified XML data replaced in {args.input_file}")


if __name__ == "__main__":
    main()
