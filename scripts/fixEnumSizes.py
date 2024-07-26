import os
import re
import argparse
import subprocess
from collections import defaultdict
from typing import Dict, List, Tuple

DEFAULT_ENUM_SIZE = 'std::uint32_t'

def find_enumerations(directory: str) -> Dict[str, List[Tuple[str, str]]]:
    """
    Find all instances of stl::enumeration and the enums they reference.

    Args:
        directory (str): The path to the directory to search in.

    Returns:
        Dict[str, List[Tuple[str, str]]]: A dictionary mapping enum names to their required sizes and file paths.
    """
    enum_map = defaultdict(list)
    pattern = re.compile(r'stl::enumeration<([\w:]+),\s*([\w:_]+)>')

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.cpp') or file.endswith('.h'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r') as f:
                    content = f.read()
                    for match in pattern.finditer(content):
                        enum_name, size = match.groups()
                        enum_map[enum_name].append((size, filepath))

    return enum_map

def find_enum_definitions(directory: str, enum_map: Dict[str, List[Tuple[str, str]]]) -> Dict[str, List[Tuple[str, str, str, int]]]:
    """
    Find definitions of enums and their sizes.

    Args:
        directory (str): The path to the directory to search in.
        enum_map (Dict[str, List[Tuple[str, str]]]): A dictionary mapping enum names to their required sizes and file paths.

    Returns:
        Dict[str, List[Tuple[str, str, str, int]]]: A dictionary mapping enum names to a list of their defined sizes, file paths, full enum names, and line numbers.
    """
    enum_definitions = defaultdict(list)
    pattern = re.compile(r'\benum\s+(?:class\s+)?(\w+)\s*(?::\s*([\w:_]+))?')
    member_pattern = re.compile(r'stl::enumeration<[\w:]+,\s*[\w:_]+>')

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.cpp') or file.endswith('.h'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r') as f:
                    content = f.read()

                    for i, line in enumerate(content.splitlines(), 1):
                        match = pattern.search(line)
                        if match:
                            enum_name, size = match.groups()
                            if member_pattern.search(line, match.end()):
                                continue  # Skip if it matches a member usage

                            full_enum_name = enum_name  # Simplified to just use the enum name
                            if full_enum_name in enum_map:
                                print(f"Found enum definition: {full_enum_name} with size {size or DEFAULT_ENUM_SIZE} in file {filepath}:{i}")
                                enum_definitions[enum_name].append((size or 'int', filepath, full_enum_name, i))

    return enum_definitions


def format_with_clang_format(filepath: str) -> None:
    """
    Format a file using clang-format.

    Args:
        filepath (str): The path to the file to format.
    """
    try:
        subprocess.run(['clang-format', '-i', filepath], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error formatting file {filepath}: {e}")

def correct_enum_sizes(directory: str, enum_map: Dict[str, List[Tuple[str, str]]], enum_definitions: Dict[str, List[Tuple[str, str, str, int]]]) -> None:
    """
    Correct the sizes of enums to match the required sizes and ensure the values fit within the specified size.

    Args:
        directory (str): The path to the directory to search in.
        enum_map (Dict[str, List[Tuple[str, str]]]): A dictionary mapping enum names to their required sizes and file paths.
        enum_definitions (Dict[str, List[Tuple[str, str, str, int]]]): A dictionary mapping enum names to a list of their defined sizes, file paths, full enum names, and line numbers.
    """
    enum_def_pattern = re.compile(r'\benum\s+(?:class\s+)?(\w+)\s*(?::\s*([\w:_]+))?')
    member_pattern = re.compile(r'stl::enumeration<([\w:]+),\s*([\w:_]+)>')
    closing_pattern = re.compile(r'}')

    def check_enum_values_fit(enum_content: str, required_size: str) -> bool:
        """
        Check if the values of the enumeration fit within the specified size.

        Args:
            enum_content (str): The content of the enum definition.
            required_size (str): The required size of the enum.

        Returns:
            bool: True if all values fit within the specified size, False otherwise.
        """
        size_limits = {
            'std::uint8_t': (0, 255),
            'std::uint16_t': (0, 65535),
            'std::uint32_t': (0, 4294967295),
            'std::uint64_t': (0, 18446744073709551615)
        }
        if required_size not in size_limits:
            return True  # If the size is not one of the specified sizes, assume it fits

        min_limit, max_limit = size_limits[required_size]
        value_pattern = re.compile(r'=\s*(-?\d+)')

        for match in value_pattern.finditer(enum_content):
            value = int(match.group(1))
            if value < min_limit or value > max_limit:
                return False

        return True

    for full_enum_name, usages in enum_map.items():
        found_enum = False
        enum_name = full_enum_name.split('::')[-1]
        if enum_name in enum_definitions:
            for required_size, usage_filepath in usages:
                for defined_size, filepath, defined_full_enum_name, line_number in enum_definitions[enum_name]:
                    if defined_full_enum_name != full_enum_name or usage_filepath != filepath:
                        continue

                    with open(filepath, 'r') as f:
                        content = f.readlines()

                    def replacer(match):
                        defined_enum_name, current_size = match.groups()
                        if defined_enum_name == enum_name:
                            if (current_size or DEFAULT_ENUM_SIZE) != required_size:
                                enum_content = ''.join(content)
                                if check_enum_values_fit(enum_content, required_size):
                                    return f"enum{' class' if 'class' in match.group(0) else ''} {defined_enum_name} : {required_size}"
                        return match.group(0)

                    updated_content = re.sub(enum_def_pattern, replacer, ''.join(content))
                    if ''.join(content) != updated_content:
                        found_enum = True
                        with open(filepath, 'w') as f:
                            f.write(updated_content)

                        print(f"Updated enum '{enum_name}' size to {required_size} in file '{filepath}:{line_number}'")
                        format_with_clang_format(filepath)

                if not found_enum:
                    print(f"Warning: Enum definition for '{enum_name}' not found.")

def add_static_asserts(directory: str) -> None:
    """
    Find all instances of stl::enumeration and the enums they reference, and add static_asserts after the closing brace
    of the containing class or struct.

    Args:
        directory (str): The path to the directory to search in.
    """
    member_pattern = re.compile(r'stl::enumeration<([\w:]+),\s*([\w:_]+)>')
    closing_pattern = re.compile(r'}\s*;?\s*(//.*)?')

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.cpp') or file.endswith('.h'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r') as f:
                    content = f.readlines()

                found_enum_uses = []
                insert_places = []

                for i, line in enumerate(content):
                    match = member_pattern.search(line)
                    if match:
                        enum_name, size = match.groups()
                        static_assert_line = f"static_assert(sizeof({enum_name}) == sizeof({size}));\n"
                        found_enum_uses.append(static_assert_line)
                        indent = len(line) - len(line.lstrip())
                    closing_match = closing_pattern.search(line)
                    if closing_match and found_enum_uses:
                        insert_places.append((i, f"{'\t' * indent}// Enumeration asserts\n"))
                        for insert_line in found_enum_uses:
                            insert_places.append((i, f"{'\t' * indent}{insert_line}"))
                        found_enum_uses.clear()

                # Insert the static_assert lines at the correct positions
                for place in reversed(insert_places):
                    content.insert(place[0], place[1])

                with open(filepath, 'w') as f:
                    f.writelines(content)

def main(directory: str) -> None:
    """
    Main function to execute the script.

    Args:
        directory (str): The directory to search for C++ files.

    >>> main('path_to_directory')
    """
    enum_map = find_enumerations(directory)
    enum_definitions = find_enum_definitions(directory, enum_map)
    correct_enum_sizes(directory, enum_map, enum_definitions)
    add_static_asserts(directory)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Check and correct enum sizes.")
    parser.add_argument('directory', type=str, help='Directory to scan for C++ files.')
    args = parser.parse_args()
    main(args.directory)
