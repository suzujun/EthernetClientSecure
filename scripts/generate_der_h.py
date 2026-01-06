#!/usr/bin/env python3
"""
Convert DER format certificate/key file to C header file.

Usage:
    python3 generate_der_h.py <input.der> [output.h]

Example:
    python3 generate_der_h.py certificate.der
    python3 generate_der_h.py private_key.der private_key_der.h
"""

import sys
import os
import argparse


def generate_header(input_file: str, output_file: str = None) -> None:
    """
    Generate C header file from DER binary file.

    Args:
        input_file: Path to input DER file
        output_file: Path to output header file (optional)
    """
    # Read DER file
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(input_file, 'rb') as f:
        der_data = f.read()

    # Determine output filename
    if output_file is None:
        base_name = os.path.splitext(os.path.basename(input_file))[0]
        # Replace hyphens and spaces with underscores
        base_name = base_name.replace('-', '_').replace(' ', '_')
        output_file = f"{base_name}_der.h"

    # Generate variable name from output filename
    var_base = os.path.splitext(os.path.basename(output_file))[0]
    # Ensure valid C identifier
    var_base = var_base.replace('-', '_').replace(' ', '_')
    if not var_base[0].isalpha() and var_base[0] != '_':
        var_base = '_' + var_base

    array_name = var_base

    # Generate header content
    header_guard = f"{var_base.upper()}_H"
    
    header_content = f"""#ifndef {header_guard}
#define {header_guard}

#include <stdint.h>
#include <stddef.h>

// Auto-generated from {os.path.basename(input_file)}
// File size: {len(der_data)} bytes

static const uint8_t {array_name}[] = {{
"""

    # Write data in hex format (16 bytes per line)
    for i in range(0, len(der_data), 16):
        chunk = der_data[i:i+16]
        hex_values = ', '.join(f'0x{b:02x}' for b in chunk)
        if i + 16 < len(der_data):
            header_content += f"    {hex_values},\n"
        else:
            header_content += f"    {hex_values}\n"

    header_content += f"""}};

#endif // {header_guard}
"""

    # Write output file
    with open(output_file, 'w') as f:
        f.write(header_content)

    print(f"Generated: {output_file}")
    print(f"  Array name: {array_name}")
    print(f"  Size: {len(der_data)} bytes (use sizeof({array_name}) to get length)")


def main():
    parser = argparse.ArgumentParser(
        description='Convert DER format certificate/key file to C header file.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 generate_der_h.py certificate.der
  python3 generate_der_h.py private_key.der private_key_der.h
  python3 generate_der_h.py root_ca.der
        """
    )
    parser.add_argument(
        'input',
        help='Input DER file path'
    )
    parser.add_argument(
        'output',
        nargs='?',
        help='Output header file path (optional, defaults to <input_base>_der.h)'
    )

    args = parser.parse_args()

    generate_header(args.input, args.output)


if __name__ == '__main__':
    main()
