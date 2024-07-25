import os
import re
import argparse
import subprocess
from typing import Dict

def find_enumerations(directory: str) -> Dict[str, str]:
    """
    Find all instances of stl::enumeration and the enums they reference.

    Args:
        directory (str): The path to the directory to search in.

    Returns:
        Dict[str, str]: A dictionary mapping enum names to their required sizes.
    """
    enum_map = {}
    pattern = re.compile(r'stl::enumeration<(\w+),\s*([\w:_]+)>')

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.cpp') or file.endswith('.h'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r') as f:
                    content = f.read()
                    for match in pattern.finditer(content):
                        enum_name, size = match.groups()
                        enum_map[enum_name] = size

    return enum_map

def find_enum_definitions(directory: str, enum_map: Dict[str, str]) -> Dict[str, str]:
    """
    Find definitions of enums and their sizes.

    Args:
        directory (str): The path to the directory to search in.
        enum_map (Dict[str, str]): A dictionary mapping enum names to their required sizes.

    Returns:
        Dict[str, str]: A dictionary mapping enum names to their defined sizes.
    """
    enum_definitions = {}
    pattern = re.compile(r'\benum\s*(?:class\s*)?(\w+)\s*(?::\s*([\w:_]+))?')

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.cpp') or file.endswith('.h'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r') as f:
                    content = f.read()
                    for match in pattern.finditer(content):
                        enum_name, size = match.groups()
                        if enum_name and enum_name in enum_map:
                            enum_definitions[enum_name] = size or 'int'

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

def correct_enum_sizes(directory: str, enum_map: Dict[str, str], enum_definitions: Dict[str, str]) -> None:
    """
    Correct the sizes of enums to match the required sizes.

    Args:
        directory (str): The path to the directory to search in.
        enum_map (Dict[str, str]): A dictionary mapping enum names to their required sizes.
        enum_definitions (Dict[str, str]): A dictionary mapping enum names to their defined sizes.
    """
    enum_def_pattern = re.compile(r'\benum\s*(?:class\s*)?(\w+)\s*(?::\s*([\w:_]+))?')

    for enum_name, required_size in enum_map.items():
        found_enum = False
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.cpp') or file.endswith('.h'):
                    filepath = os.path.join(root, file)
                    with open(filepath, 'r') as f:
                        content = f.read()

                    # Correct the enum size if needed
                    updated_content = re.sub(
                        enum_def_pattern,
                        lambda m: f"enum{' class' if 'class' in m.group(0) else ''} {enum_name} : {required_size}"
                        if m.group(1) == enum_name and (m.group(2) != required_size) else m.group(0),
                        content
                    )

                    if content != updated_content:
                        found_enum = True
                        with open(filepath, 'w') as f:
                            f.write(updated_content)
                        print(f"Updated enum '{enum_name}' size to {required_size} in file '{filepath}'")
                        format_with_clang_format(filepath)

        if not found_enum:
            print(f"Warning: Enum definition for '{enum_name}' not found.")

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

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Check and correct enum sizes.")
    parser.add_argument('directory', type=str, help='Directory to scan for C++ files.')
    args = parser.parse_args()
    main(args.directory)