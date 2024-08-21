# based on GPL3 code https://github.com/Starfield-Reverse-Engineering/CommonLibSF/pull/221/files by @nikitalita
import re
import argparse
import xml.etree.ElementTree as ET
from collections import deque
from typing import Any, List, Dict, Tuple, Set, Optional, Union

node_addition_queue: deque[Tuple[ET.Element, ET.Element, int]] = deque()
node_addition_stats: Dict[str, int] = {}
processed_classes = set()


def process_node_additions(root: ET.Element) -> None:
    """
    Process and add nodes from the node addition queue to their respective parent nodes efficiently,
    assuming each node addition is for a single parent node.

    Args:
        root (ET.Element): The root element of the XML tree.
    """
    # Cache for parent nodes to avoid redundant searches
    global parent_node_cache

    while node_addition_queue:
        parent_node, child_node, index = node_addition_queue.popleft()

        if index == -1:
            parent_node.append(child_node)
        else:
            parent_node.insert(index, child_node)


def prepass_symbols_table(symbols_node: ET.Element) -> Dict[str, List[Dict[str, str]]]:
    """
    Prepass the symbols table to build a cache of potential classes with their vfuncs.

    Args:
        symbols_node (ET.Element): The XML element representing the symbols table.

    Returns:
        Dict[str, List[Dict[str, str]]]: A dictionary where keys are class names and values are lists of vfunc details.
    """
    symbol_cache = {}
    last_class = ""
    class_name = ""
    for symbol in symbols_node.findall("symbol"):
        symbol_name = symbol.get("name")
        class_name_match = re.match(r"~([\w:]+)", symbol_name)
        if class_name_match:
            class_name = class_name_match.group(1)
            last_class = class_name
            if class_name not in symbol_cache:
                symbol_cache[class_name] = []
        if class_name and class_name == last_class:
            if symbol.get("tag") == "Function" and symbol.get("undecorated"):
                function_signature = symbol.get("undecorated")
                function_details = get_function_details(function_signature, class_name)
                if function_details["name"] and function_details["return_type"]:
                    symbol_cache[class_name].append(
                        {
                            "name": symbol_name,
                            "index": int(symbol.get("index"), 16),
                            "details": function_details,
                        }
                    )
            else:  # reset now that saw last vfunc
                last_class = ""

    return symbol_cache


def process_class_vtables(
    root: ET.Element,
    class_node: ET.Element,
    symbol_cache: Dict[str, List[Dict[str, str]]],
    insert_vtable: bool = False
) -> None:
    """
    Update the class vtable by replacing void* placeholders with function pointers.

    Args:
        root (ET.Element): The XML root.
        class_node (ET.Element): The XML element representing the class.
        symbol_cache (Dict[str, List[Dict[str, str]]]): The preprocessed symbol cache.
        insert_vtable (bool): Whether the vtable should be inserted at the front of the class.
    """
    class_name = class_node.get("name")

    # Check if this class has already been processed
    if class_name in processed_classes:
        return

    datatype_name = f"{class_name}::vftable"
    datatype_vtable_node = ET.Element(
        "class", name=datatype_name, kind="Structure", length="0x0"
    )
    vtable_node = ET.Element(
        "member",
        name="vftable",
        datatype=f"{datatype_name} *",
        offset="0x0",
        kind="Member",
        length="0x8",
    )
    vtable_funcs = []

    if class_name in symbol_cache:
        in_class = False

        for member in class_node.findall("member"):
            name_attr = member.get("name")
            datatype_attr = member.get("datatype")
            kind_attr = member.get("kind")

            if datatype_attr == "void *" and kind_attr == "Unknown":
                in_class = True

                for symbol in symbol_cache[class_name]:
                    symbol_name = symbol["name"]
                    function_details = symbol["details"]

                    if symbol_name == name_attr:
                        vtable_funcs.append(function_details)
                        break

                if not in_class:
                    break
            elif datatype_attr != "void *" and in_class:
                break

    if insert_vtable:
        class_node.insert(0, vtable_node)

    # Replace placeholder with function definitions
    for idx, func_detail in enumerate(vtable_funcs):
        class_index = f"{class_node.get('name')}_vtable_{idx}"
        function_def = create_function_definition(func_detail)

        # ghidra does not like datatypes with [] endings
        fixed_function_name = f"{function_def.get('name')[:-2]}__" if function_def.get('name').endswith("]") else function_def.get('name')
        datatype_vtable_node.append(
            ET.Element(
                "member",
                name=f"{function_def.get('name')}()",
                datatype=f"{fixed_function_name}*",
                offset=f"0x{idx * 8:X}",
                kind="Member",
                comment=class_index,
                length="0x8",
            )
        )
        datatype_member_node = ET.Element(
            "class", name=f"{fixed_function_name}", kind="Structure", length="0x8"
        )
        root.find("classes").append(datatype_member_node)
        datatype_vtable_node.set("length", f"0x{(idx + 1) * 8:X}")

    length_attr = datatype_vtable_node.get("length")

    if length_attr is not None:
        length = int(length_attr, 16)
    else:
        length = 0
    # Attach datatype
    if length > 0:
        root.find("classes").append(datatype_vtable_node)

    # Mark this class as processed
    processed_classes.add(class_name)


def create_function_definition(func_details: dict) -> ET.Element:
    """
    Create a function definition XML element.

    Args:
        func_details (dict): A dictionary containing function details.

    Returns:
        ET.Element: The XML element representing the function definition.
    """
    func_def = ET.Element("function")
    func_def.set("name", func_details["name"])
    func_def.set("address", "0x0")
    func_def.set("return_type", func_details["return_type"])
    params_node = ET.SubElement(func_def, "parameters")
    for param in func_details["parameters"]:
        param_node = ET.SubElement(params_node, "parameter")
        param_node.set("name", param[1])
        param_node.set("type", param[0])
    return func_def


def convert_to_ghidra_type(param_type: str) -> str:
    """
    Convert common C++ types to Ghidra recognized types.

    Args:
        param_type (str): The C++ parameter type.

    Returns:
        str: The Ghidra recognized parameter type.
    """
    # Remove 'const' qualifiers
    param_type = param_type.replace("const ", "").replace(" &", "*").replace("&", "*")

    type_mappings = {
        "unsigned __int64": "uint64",
        "signed __int64": "int64",
        "unsigned long long": "uint64",
        "signed long long": "int64",
        "unsigned long": "ulong",
        "signed long": "long",
        "unsigned int": "uint",
        "signed int": "int",
        "unsigned short": "ushort",
        "signed short": "short",
        "unsigned char": "uchar",
        "signed char": "char",
        "const char*": "char*",
        "const char *": "char*",
    }
    for k, v in type_mappings.items():
        param_type = param_type.replace(k, v)

    return param_type


def parse_function_parameters(param_string: str) -> List[Tuple[str, str]]:
    """
    Parse a parameter string and return a list of parameter type and name pairs.

    Args:
        param_string (str): The parameter string.

    Returns:
        List[Tuple[str, str]]: A list of tuples where each tuple contains the parameter type and name.
    """
    param_string = param_string.strip("()")
    if not param_string:
        return []

    # Split parameters by comma while handling nested templates
    param_list = split_parameters(param_string)
    parameters = []

    for i, param in enumerate(param_list):
        param = param.strip()
        if " " in param:
            param_type, param_name = param.rsplit(" ", 1)
        else:
            param_type = param
            param_name = f"a_{i+1}"  # Placeholder parameter name

        # Handle common types conversion for Ghidra
        param_type = convert_to_ghidra_type(param_type)

        parameters.append((param_type, param_name))

    return parameters


def split_parameters(param_string: str) -> List[str]:
    """
    Split a parameter string into individual parameters, handling nested templates.

    Args:
        param_string (str): The parameter string.

    Returns:
        List[str]: A list of parameter strings.
    """
    params = []
    nested_level = 0
    current_param = []

    for char in param_string:
        if char == "<":
            nested_level += 1
        elif char == ">":
            nested_level -= 1
        elif char == "," and nested_level == 0:
            params.append("".join(current_param).strip())
            current_param = []
            continue
        current_param.append(char)

    if current_param:
        params.append("".join(current_param).strip())

    return params


def clean_signature(signature: str) -> str:
    """
    Clean up the function signature for easier parsing.

    Args:
        signature (str): The original function signature.

    Returns:
        str: The cleaned function signature.
    """
    # Convert known types to Ghidra-compatible types
    signature = convert_to_ghidra_type(signature)

    # Remove unnecessary spaces around pointers and references
    signature = re.sub(r"\s*\*", "*", signature)
    signature = re.sub(r"\s*&", "&", signature)

    # Remove unnecessary spaces around end of templates
    signature = re.sub(r">\s+>", ">>", signature)
    signature = re.sub(r">\s+(?=>)", ">", signature)
    signature = re.sub(r"\s+>", ">", signature)

    # Remove unnecessary const qualifiers
    signature = re.sub(r"\s*const\s*", "", signature)

    # Remove redundant spaces around brackets, parentheses, and commas
    signature = re.sub(r"\s*\[\s*", "[", signature)
    signature = re.sub(r"\s*\]\s*", "]", signature)
    signature = re.sub(r"\s*\(\s*", "(", signature)
    signature = re.sub(r"\s*\)\s*", ")", signature)
    signature = re.sub(r"\s*,\s*", ",", signature)

    # Simplify multiple spaces into a single space
    signature = re.sub(r"\s+", " ", signature).strip()

    return signature


def get_function_details(signature: str, class_name: str = "") -> Dict[str, Any]:
    """
    Parse a function signature and return its details.

    Args:
        signature (str): The function signature.

    Returns:
        Dict[str, Any]: A dictionary with the return type, function name, and parameters.
    """
    # Clean up the signature before parsing
    signature = clean_signature(signature)

    # Define patterns to identify and extract function details
    operator_pattern = r"((operator\s*(?:\(\)|\[\]|==|!=|<=|>=|<<|>>|\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|\^=|\+|-|\*|/|%|&|\||\^|~|!|new[?]?|delete[?]?|<|>)|[\w\[\]:~<>,\(\)%^&/+=\|*-]+))\s*\("
    function_name_regex = rf"({operator_pattern}|[\w\[\]:~<>,\(\)%^&/+=\|*-]+)"
    return_type_pattern = rf"^(class|struct|enum)?\s*([\w:\*&\s<>*\]\[,]+?)\s+({function_name_regex})\s*\("
    function_name_pattern = rf"({function_name_regex})\s*\("
    param_string_pattern = r"\((.*)\)"

    # Extract return type
    return_type_match = re.search(return_type_pattern, signature)
    if not return_type_match:
        print(f"Warning: Invalid return signature format: {signature}")
        return {
            "return_type": "",
            "name": "",
            "parameters": [],
            "signature": signature,
        }
    return_type = return_type_match.group(2).strip()
    return_type = convert_to_ghidra_type(return_type)

    # Extract function name
    function_name_match = re.search(function_name_pattern, signature)
    if not function_name_match:
        print(f"Warning: Invalid function signature format: {signature}")
        return {
            "return_type": return_type,
            "name": "",
            "parameters": [],
            "signature": signature,
        }
    function_name = function_name_match.group(1).strip()

    # Extract parameter string
    param_string_match = re.search(param_string_pattern, signature)
    param_string = param_string_match.group(1) if param_string_match else ""

    # Ensure param_string is always in parenthesis format
    param_string = f"({param_string})"

    # Parse the parameters
    parameters = parse_function_parameters(param_string)

    return {
        "return_type": return_type,
        "name": f"{class_name}::{function_name}" if class_name else function_name,
        "parameters": parameters,
        "signature": signature,
    }


def add_xml_node(
    parent_name: ET.Element, child_node: ET.Element, index: int = -1
) -> None:
    """
    Queue a new child node addition under a specified parent node and collect statistics.

    :param parent_name: The name of the parent node
    :param child_node: The new child node to add
    :param index: The index to insert the new child node at (-1 to append)
    """
    # Queue the node addition
    node_addition_queue.append((parent_name, child_node, index))

    # Collect statistics
    if parent_name in node_addition_stats:
        node_addition_stats[parent_name] += 1
    else:
        node_addition_stats[parent_name] = 1


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


def fix_class_inheritance(root: ET.Element, add_parents: bool = False) -> None:
    """
    Fix class inheritance by updating 'member' nodes with 'Unknown' kind to 'Member' sequentially,
    stopping when a node with a different kind or both offset and length equal to '0x0' is encountered.
    Also updates vtable placeholders with function definitions.

    Args:
        root (ET.Element): The root element of the XML tree.
        add_parents (bool): Whether to add parents to a class. Not needed for RecoverClassesFromRTTIScript.java
    """
    inheritance_fixes_count = 0
    symbols_node = root.find(".//table[@name='Symbols']")
    symbol_cache = prepass_symbols_table(symbols_node)
    class_nodes_with_vtables = []
    for class_node in root.iter("class"):
        stop_processing = False
        member_index = 0
        vtable_found = False
        vtable_node = None  # Track the vtable node if found

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
                or (
                    member_index == 0 and offset not in [0, 8]
                )  # first inheritance must be at 0 or 8 if vtable at 0
                or (offset_attr == "0x0" and length_attr == "0x0")
            ):
                stop_processing = True
                break
            elif (
                add_parents
                and name_attr
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
                if member_index == 0 and offset == 8:  # detected a vtable member
                    vtable_found = True
                member.set("kind", "Member")
                inheritance_fixes_count += 1
                total_length = offset + length
                member_index += 1
        if member_index == 0 and int(class_node.get("length"), 16) == 8:
            # no inheritance, needs vtable
            vtable_found = True
        if vtable_found or int(class_node.get("length"), 16) >= 8:
            # If vtable is confirmed or class big enough to need vtable, check vtable
            class_nodes_with_vtables.append((class_node, vtable_found))
    for class_node, vtable_found in class_nodes_with_vtables:
        print(f"Fixing vtables for : {class_node.get('name')}")

        process_class_vtables(root, class_node, symbol_cache, False)

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
    enums_parent = root.find(".//enums")
    if enums_parent is None:
        enums_parent = root
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
        "unsigned __int64": "ulonglong",
        "unsigned long long": "ulonglong",
        "signed char": "char",
        "signed short": "short",
        "signed int": "int",
        "signed __int64": "longlong",
        "signed long long": "longlong",
    }

    size_map = {
        "uchar": 1,
        "ushort": 2,
        "uint": 4,
        "ulonglong": 8,
        "char": 1,
        "short": 2,
        "int": 4,
        "longlong": 8,
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
                            add_xml_node(root.find("enums"), new_enum)
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
                                    wrapper_member.set("datatype", f"{enum_name}_{enum_length}" if enum_length not in [4,8] else f"{enum_name}")
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
    parent_map = {}
    nodes_to_remove = set()
    total_nodes = 0
    standard_removed_nodes = set()

    # Combined iteration to clear <functions> and mark nodes for removal
    for parent in root.iter():
        for node in parent:
            parent_map[node] = parent
            total_nodes += 1
            if node.tag == "functions":
                node.clear()
            elif node.tag in {"class", "symbol", "enum", "datatype", "typedef"}:
                for key, delete_list in delete_patterns.items():
                    name_attr = node.get(key)
                    if name_attr and any(
                        name_attr.startswith(pattern) for pattern in delete_list
                    ):
                        nodes_to_remove.add(node)
                        standard_removed_nodes.add(node)

    # Remove duplicate nodes
    remove_duplicate_nodes(root)

    # Apply keep_only filtering earlier for performance
    if keep_only_name:
        all_related_nodes = set()
        for name in keep_only_name:
            related_nodes = collect_related_nodes(root, name)
            all_related_nodes.update(related_nodes)
        nodes_to_remove.update(set(root.iter()) - all_related_nodes)

    # Remove marked nodes in a separate step to avoid modifying the tree while iterating
    for node in nodes_to_remove:
        parent = parent_map.get(node)
        if parent is not None and node in parent:
            parent.remove(node)

    # Print stats
    print(f"Total nodes: {total_nodes}")
    print(
        f"Removed nodes (standard cleaning): {len(standard_removed_nodes)} ({len(standard_removed_nodes)/total_nodes:.2%})"
    )
    print(
        f"Removed nodes (keep_only): {len(nodes_to_remove) - len(standard_removed_nodes)} ({(len(nodes_to_remove) - len(standard_removed_nodes))/total_nodes:.2%})"
    )

    # Fix class inheritance by modifying 'member' nodes
    # fix_class_inheritance(root)

    # Fix enumerations and enum size mismatches
    fix_enumeration_and_enum_sizes(root)

    # Process the queued node additions
    process_node_additions(root)

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
        (  # Remove empty nodes
            r'<member name="" datatype="Undefined" offset="0x0" kind="Unknown" length="0x0" />',
            r"",
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
