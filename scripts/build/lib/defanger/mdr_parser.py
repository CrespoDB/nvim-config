#!/usr/bin/env python3
"""
MDR Entity Parser - Convert camelCase entity data to readable format
"""

import sys
import re
from typing import List, Tuple


def camel_to_spaced(text: str) -> str:
    """Convert camelCase text to space-separated words, preserving existing spaces and brackets."""
    # Handle underscores - replace with spaces
    text = text.replace('_', ' ')
    
    # Insert space before uppercase letters that follow lowercase letters or digits
    # This handles camelCase while preserving existing spaces
    text = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', text)
    
    # Handle consecutive uppercase letters like XMLParser -> XML Parser
    text = re.sub(r'([A-Z])([A-Z][a-z])', r'\1 \2', text)
    
    return text


def extract_key_value_from_line(line: str) -> Tuple[str, str]:
    """Extract key and value from a single line that might have concatenated data."""
    # Look for pattern: camelCase/snake_case word followed by digits (and possibly more)
    # Example: EmailCount204 -> (EmailCount, 204)
    # Example: FileSize456KB -> (FileSize, 456KB)
    match = re.match(r'^([A-Za-z_][A-Za-z0-9_]*?)(\d+.*)$', line)
    if match:
        return match.group(1), match.group(2)
    
    # If no digits found, return the line as a key with empty value
    return line, ""


def parse_entity_data(content: str) -> str:
    """Parse MDR entity data from camelCase/snake_case key-value format to readable format."""
    lines = content.strip().split('\n')
    if not lines:
        return content
    
    pairs: List[Tuple[str, str]] = []
    i = 0
    
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            continue
        
        # Check if this line has a key with concatenated numeric value
        key, inline_value = extract_key_value_from_line(line)
        
        if inline_value:
            # Found concatenated key-value like EmailCount204
            pairs.append((key, inline_value))
            i += 1
        elif i + 1 < len(lines):
            # Normal key-value pair on separate lines
            next_line = lines[i + 1].strip()
            pairs.append((line, next_line))
            i += 2
        else:
            # Single line without a following value, skip
            i += 1
    
    # Format the pairs
    result_lines = []
    for key, value in pairs:
        formatted_key = camel_to_spaced(key)
        result_lines.append(f"{formatted_key}: {value}")
    
    return '\n'.join(result_lines)


def main():
    """Main entry point for mdr-parse command."""
    if len(sys.argv) > 1:
        # Read from command line arguments
        content = ' '.join(sys.argv[1:])
    else:
        # Read from stdin
        content = sys.stdin.read()
    
    if not content.strip():
        sys.stderr.write("No input provided\n")
        sys.exit(1)
    
    try:
        result = parse_entity_data(content)
        print(result)
    except Exception as e:
        sys.stderr.write(f"Error parsing entity data: {e}\n")
        sys.exit(1)


if __name__ == '__main__':
    main()