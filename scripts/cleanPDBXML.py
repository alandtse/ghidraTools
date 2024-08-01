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
    inheritance_fixes_count = 0

    for class_node in root.iter("class"):
        stop_processing = False
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
                datatype_attr.endswith("*")  # no pointers
                or not name_attr
                or name_attr in ["", "enum_type", "element_type", "value_type"]
                or datatype_attr
                in [
                    "double",
                    "boolean",
                    "float",
                    "long",
                    "char",
                    "short",
                    "byte",
                    "int",
                    "uint",
                ]
                or kind_attr != "Unknown"
                or (member_index == 0 and offset != 0)  # first inheritance must be at 0
                or (offset_attr == "0x0" and length_attr == "0x0")
            ):
                stop_processing = True
                break
            elif (
                name_attr
                and not name_attr.startswith("std")
                and kind_attr == "Unknown"
                and length_attr
                and not stop_processing
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
                inheritance_fixes_count += 1
                total_length = offset + length
                member_index += 1

    print(f"Inheritance Fixes Applied: {inheritance_fixes_count}")


def fix_enumeration_and_enum_sizes(root: ET.Element) -> None:
    """
    Fix enumeration definitions and replace integer types with enum types in classes and structures.

    Args:
        root (ET.Element): The root element of the XML tree.

    Doctest:
    >>> xml_content = '''
    ... <root>
    ...     <class name="enumeration&lt;enum GString::HeapType,unsigned __int64&gt;" length="0x8">
    ...         <member name="enum_type" datatype="int" offset="0x0" kind="Unknown" length="0x4" />
    ...         <member name="underlying_type" datatype="__uint64" offset="0x0" kind="Unknown" length="0x8" />
    ...         <member name="enumeration&lt;enum GString::HeapType,unsigned __int64&gt;" datatype="void *"
    ... offset="0x0" kind="Unknown" length="0x0" />
    ...         <member name="enumeration&lt;enum GString::HeapType,unsigned __int64&gt;" datatype="void *"
    ... offset="0x0" kind="Unknown" length="0x0" />
    ...         <member name="operator bool" datatype="void *" offset="0x0" kind="Unknown" length="0x0" />
    ...         <member name="operator*" datatype="void *" offset="0x0" kind="Unknown" length="0x0" />
    ...         <member name="get" datatype="void *" offset="0x0" kind="Unknown" length="0x0" />
    ...         <member name="underlying" datatype="void *" offset="0x0" kind="Unknown" length="0x0" />
    ...         <member name="_impl" datatype="__uint64" offset="0x0" kind="Member" length="0x8" />
    ...     </class>
    ...     <enum name="HeapType" length="0x8" datatype="unsigned __int64">
    ...         <element name="DEFAULT" value="0" />
    ...         <element name="CUSTOM" value="1" />
    ...     </enum>
    ... </root>
    ... '''
    >>> root = ET.fromstring(xml_content)
    >>> fix_enumeration_and_enum_sizes(root)
    Updated Enums Count: 1
    Added Enums Count: 0
    Member Enum Fixes Count: 1
    >>> ET.dump(root)
    <root>
        <class name="enumeration&lt;enum GString::HeapType,unsigned __int64&gt;" length="0x8">
            <member name="enum_type" datatype="int" offset="0x0" kind="Unknown" length="0x4" />
            <member name="underlying_type" datatype="__uint64" offset="0x0" kind="Unknown" length="0x8" />
            <member name="enumeration&lt;enum GString::HeapType,unsigned __int64&gt;" datatype="void *"
            offset="0x0" kind="Unknown" length="0x0" />
            <member name="enumeration&lt;enum GString::HeapType,unsigned __int64&gt;" datatype="void *"
            offset="0x0" kind="Unknown" length="0x0" />
            <member name="operator bool" datatype="void *" offset="0x0" kind="Unknown" length="0x0" />
            <member name="operator*" datatype="void *" offset="0x0" kind="Unknown" length="0x0" />
            <member name="get" datatype="void *" offset="0x0" kind="Unknown" length="0x0" />
            <member name="underlying" datatype="void *" offset="0x0" kind="Unknown" length="0x0" />
            <member name="_impl" datatype="HeapType" offset="0x0" kind="Member" length="0x8" />
        </class>
        <enum name="HeapType" length="0x8" datatype="unsigned __int64">
            <element name="DEFAULT" value="0" />
            <element name="CUSTOM" value="1" />
        </enum>
    </root>
    """

    updated_enums_count = 0
    added_enums_count = 0
    member_enum_fixes_count = 0

    # Map to store existing enums by name and length
    enum_map = {}

    # Find the parent node for enums
    enums_parent = root.find(".//enums") or root

    for enum_elem in root.findall(".//enum"):
        enum_name = enum_elem.get("name")
        enum_type = enum_elem.get("datatype")
        enum_length = int(enum_elem.get("length"), 16)
        if enum_name:
            enum_map[(enum_name, enum_length)] = enum_elem

    # Map for the shortened version of datatypes
    short_type_map = {
        "unsigned char": "uchar",
        "unsigned short": "ushort",
        "unsigned int": "uint",
        "unsigned long long": "ulonglong",
    }

    size_map = {
        "uchar": 1,
        "ushort": 2,
        "uint": 4,
        "ulonglong": 8,
    }

    # Fix enum size mismatches in class members and iterate through all 'class' elements
    for class_elem in root.findall(".//class"):
        class_name = class_elem.get("name")
        for member in class_elem.findall("member"):
            datatype = member.get("datatype")
            if datatype and datatype.startswith("enumeration<enum "):
                original_wrapper_name = datatype
                enum_name_and_size = datatype.split("<enum ")[1].split(">")[0]
                if "," in enum_name_and_size:
                    enum_name, enum_size = enum_name_and_size.rsplit(",", 1)
                    enum_name = enum_name.strip()
                    enum_size = enum_size.strip()

                    # Convert enum_size to integer
                    enum_length = size_map.get(short_type_map.get(enum_size, enum_size))

                    if enum_length and (enum_name, enum_length) not in enum_map:
                        # Find the original enum with the same name but different size
                        original_enum_key = next(
                            (key for key in enum_map if key[0] == enum_name), None
                        )
                        if original_enum_key:
                            original_enum = enum_map[original_enum_key]
                            # Create a new enum of the appropriate size and same values
                            new_enum = ET.Element("enum")
                            new_enum.set("name", f"{enum_name}_{enum_length}")
                            new_enum.set(
                                "datatype", short_type_map.get(enum_size, enum_size)
                            )
                            new_enum.set("length", f"0x{enum_length:X}")
                            for value in original_enum:
                                new_enum.append(value)

                            # Append the new enum to the enums parent node
                            enums_parent.append(new_enum)
                            enum_map[(enum_name, enum_length)] = new_enum
                            added_enums_count += 1

                            # Correct the use in the class member
                            member.set("datatype", f"{enum_name}_{enum_length}")
                            member.set("length", f"0x{enum_length:X}")
                            member_enum_fixes_count += 1

                            # Update the _impl member in the wrapper class
                            wrapper_xpath = f".//class[@name='{original_wrapper_name}']"
                            original_wrapper = root.find(wrapper_xpath)
                            if original_wrapper is not None:
                                for wrapper_member in original_wrapper.findall(
                                    "member"
                                ):
                                    if wrapper_member.get("name") == "_impl":
                                        wrapper_member.set(
                                            "datatype", f"{enum_name}_{enum_length}"
                                        )
                                        wrapper_member.set(
                                            "length", f"0x{enum_length:X}"
                                        )
                                        updated_enums_count += 1
                                        break

                    # Ensure the 'impl' member is updated to use the correct enum even if no new enum was created
                    else:
                        wrapper_xpath = f".//class[@name='{original_wrapper_name}']"
                        original_wrapper = root.find(wrapper_xpath)
                        if original_wrapper is not None:
                            for wrapper_member in original_wrapper.findall("member"):
                                if wrapper_member.get("name") == "_impl":
                                    enum_length = next(
                                        (
                                            length
                                            for name, length in enum_map.keys()
                                            if name == enum_name
                                        ),
                                        None,
                                    )
                                    wrapper_member.set("datatype", f"{enum_name}")
                                    wrapper_member.set(
                                        "length",
                                        f"0x{enum_length:X}" if enum_length else "0x0",
                                    )
                                    updated_enums_count += 1
                                    break

    print(f"Updated Enums Count: {updated_enums_count}")
    print(f"Added Enums Count: {added_enums_count}")
    print(f"Member Enum Fixes Count: {member_enum_fixes_count}")


def parse_and_modify_xml(
    xml_data: str, delete_patterns: Dict[str, List[str]], keep_only_name: List[str]
) -> str:
    """
    Parse the XML data, find the <functions> node and clear all its child nodes,
    and delete <class>, <symbol>, <enum>, or <datatype> nodes where the name starts with certain strings.

    Args:
        xml_data (str): The cleaned XML data as a string.
        delete_patterns (Dict[str, List[str]]): Dict of prefixes to identify nodes to be deleted.
        keep_only_name (List[str]): The list of names of the classes or datatypes to keep.

    Returns:
        str: The modified XML data as a string.
    """
    tree = ET.ElementTree(ET.fromstring(xml_data))
    root = tree.getroot()

    # Create a parent map during traversal
    global parent_map
    parent_map = {}
    stack = deque([(root, None)])

    # Apply keep_only filtering earlier for performance
    if keep_only_name:
        all_related_nodes = set()
        for name in keep_only_name:
            related_nodes = collect_related_nodes(root, name)
            all_related_nodes.update(related_nodes)
        nodes_to_remove.update(set(root.iter()) - all_related_nodes)

    # Remove nodes in a separate step to avoid modifying the tree while iterating
    for node in nodes_to_remove:
        parent = parent_map.get(node)
        if parent is not None and node in parent:
            parent.remove(node)

    # Fix class inheritance by modifying 'member' nodes
    fix_class_inheritance(root)

    # Remove duplicate nodes
    remove_duplicate_nodes(root)

    # Fix enumerations and enum size mismatches
    fix_enumeration_and_enum_sizes(root)

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

    # Create a parent map during traversal
    parent_map = {}
    for parent in root.iter():
        for node in parent:
            parent_map[node] = parent

    related_nodes = collect_related_nodes(root, keep_only_name)

    # Remove nodes that are not related to the specified class or datatype name
    for node in list(root.iter()):
        if node not in related_nodes:
            parent = parent_map.get(node)
            if parent is not None and node in parent:
                parent.remove(node)

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
    parser.add_argument(
        "--keep_only",
        nargs="*",  # 0 or more values expected => creates a list
        type=str,
        default=[],  # default if nothing is provide
        help="List of names of the classes or datatypes to keep.",
    )

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
        # (  # replace stl::enum
        #     # r'datatype="enumeration&lt;enum ([\w:]+),[^"]*"',
        #     # r'datatype="\1"',
        #     r'(<member name="underlying_type"[^/]*kind=")Unknown"',
        #     r'\1Member"',
        # ),
        (  # replace addresses
            r'address="0x[1-9a-f][0-9a-f]*"',
            r'address="0x0"',
        ),
        # template pointers
        (  # BSTSmartPointer since no way for Ghidra to know it's a pointer and it fails `checkAncestry``
            r'datatype="BSTSmartPointer&lt;([\w:&;]+)(?:,BSTSmartPointerIntrusiveRefCount)?&gt;"',
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
            # "enumeration&lt;enum ",
            "fmt::",
            "Catch::",
            "spdlog::",
            "REL::",
            "binary_io::",
            "std::basic_ostream<",
        ],
        "datatype": [
            # "enumeration&lt;enum ",
            "fmt::",
            "Catch::",
            "spdlog::",
        ],
    }

    # Clean the data
    cleaned_data = clean_xml(data, patterns, replace_patterns)

    # Parse and modify the cleaned XML
    modified_xml_data = parse_and_modify_xml(
        cleaned_data, delete_patterns, args.keep_only
    )

    # Write the modified XML data to the output file or replace in place
    if args.output_file:
        if not args.output_file.endswith(".pdb.xml"):
            args.output_file += ".pdb.xml"
        with open(args.output_file, "w", encoding="utf-8") as file:
            file.write(modified_xml_data)
        print(f"Modified XML data written to {args.output_file}")
    else:
        with open(args.input_file, "w", encoding="utf-8") as file:
            file.write(modified_xml_data)
        print(f"Modified XML data replaced in {args.input_file}")


if __name__ == "__main__":
    main()
