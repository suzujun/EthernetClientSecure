#!/usr/bin/env python3
"""
Convert Root CA certificate (DER format) to Trust Anchor header file.

This script extracts the Distinguished Name (DN) and RSA modulus from a DER-format
Root CA certificate and generates a BearSSL Trust Anchor header file.

Usage:
    python3 generate_trust_anchors.py <root_ca.der> [output.h]

Example:
    python3 generate_trust_anchors.py root_ca.der
    python3 generate_trust_anchors.py root_ca.der trust_anchors.h
"""

import sys
import subprocess
import tempfile
import os
import re
import argparse
from pathlib import Path


def bytes_to_c_array(data: bytes, array_name: str, items_per_line: int = 16) -> str:
    """
    Convert byte array to C array format string.
    """
    lines = []
    for i in range(0, len(data), items_per_line):
        chunk = data[i:i + items_per_line]
        hex_values = ', '.join(f'0x{b:02x}' for b in chunk)
        lines.append(f'    {hex_values}')
    
    array_str = ',\n'.join(lines)
    return f'static const unsigned char {array_name}[] = {{\n{array_str}\n}};'


def extract_dn_der(der_path: Path) -> bytes:
    """
    Extract Distinguished Name (DN) DER encoding from certificate using openssl.
    """
    try:
        # Parse certificate with openssl asn1parse
        result = subprocess.run(
            ['openssl', 'asn1parse', '-inform', 'DER', '-in', str(der_path)],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Read certificate data
        with open(der_path, 'rb') as f:
            cert_data = f.read()
        
        # Find all d=2 SEQUENCE elements (subject and issuer are typically at depth 2)
        d2_sequences = []
        for line in result.stdout.split('\n'):
            # Example: "  140:d=2  hl=2 l=  57 cons: SEQUENCE"
            m = re.search(r'^\s*(\d+):d=2\s+hl=(\d+)\s+l=\s*(\d+)\s+cons:\s+SEQUENCE', line)
            if m:
                offset = int(m.group(1))
                header_len = int(m.group(2))
                length = int(m.group(3))
                d2_sequences.append((offset, header_len, length))
        
        if not d2_sequences:
            raise ValueError("Could not locate DN (no d=2 SEQUENCE found)")
        
        # Group by length
        length_groups = {}
        for offset, header_len, length in d2_sequences:
            if length not in length_groups:
                length_groups[length] = []
            length_groups[length].append((offset, header_len, length))
        
        # Find subject candidates (typically same length as issuer, appears after issuer)
        subject_candidates = []
        for length, sequences in length_groups.items():
            # DN length is typically tens to hundreds of bytes
            # Too short sequences (< 20 bytes) are likely not DNs
            if length > 20 and len(sequences) >= 2:
                sequences.sort(key=lambda x: x[0])
                subject_candidates.append(sequences[1])  # Second one is likely subject
        
        if not subject_candidates:
            # If no pairs found, use longer sequences as candidates
            for offset, header_len, length in d2_sequences:
                if length > 20:
                    subject_candidates.append((offset, header_len, length))
        
        if not subject_candidates:
            raise ValueError("No DN candidates found")
        
        # Subject typically comes after issuer, so choose the one with larger offset
        if len(subject_candidates) >= 2:
            subject_candidates.sort(key=lambda x: x[0])
            subject_offset, subject_header_len, subject_length = subject_candidates[-1]
        else:
            subject_offset, subject_header_len, subject_length = subject_candidates[0]
        
        # Extract DN DER encoding
        if subject_offset < len(cert_data):
            dn_der = cert_data[subject_offset:subject_offset + subject_header_len + subject_length]
            
            if len(dn_der) == subject_header_len + subject_length:
                return dn_der
        
        raise ValueError("Could not extract DN DER encoding")
        
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"openssl command failed: {e.stderr}")
    except Exception as e:
        raise RuntimeError(f"Error extracting DN: {e}")


def extract_rsa_modulus(der_path: Path) -> tuple[bytes, int]:
    """
    Extract RSA public key modulus from certificate using openssl.
    Returns: (modulus bytes, bit length)
    """
    try:
        # Get public key
        pubkey_result = subprocess.run(
            ['openssl', 'x509', '-inform', 'DER', '-in', str(der_path), '-noout', '-pubkey'],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Save public key to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tmp_pubkey:
            tmp_pubkey.write(pubkey_result.stdout)
            tmp_pubkey_path = tmp_pubkey.name
        
        try:
            # Get RSA modulus
            modulus_result = subprocess.run(
                ['openssl', 'rsa', '-pubin', '-in', tmp_pubkey_path, '-modulus', '-noout'],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Output format: "Modulus=ABCDEF..."
            modulus_hex = modulus_result.stdout.strip().split('=')[1]
            
            # Convert hex string to bytes
            modulus_bytes = bytes.fromhex(modulus_hex)
            
            # Calculate bit length
            modulus_bits = len(modulus_bytes) * 8
            
            return (modulus_bytes, modulus_bits)
            
        finally:
            if os.path.exists(tmp_pubkey_path):
                os.unlink(tmp_pubkey_path)
                
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"openssl command failed: {e.stderr}")
    except Exception as e:
        raise RuntimeError(f"Error extracting RSA modulus: {e}")


def generate_trust_anchors_h(dn_der: bytes, modulus_bytes: bytes, modulus_bits: int, 
                             output_name: str = "trust_anchors") -> str:
    """
    Generate Trust Anchor format C header file.
    """
    dn_array = bytes_to_c_array(dn_der, 'TA_DN0')
    modulus_array = bytes_to_c_array(modulus_bytes, 'TA_RSA_N0')
    
    header_guard = f"{output_name.upper().replace('-', '_').replace('.', '_')}_H"
    
    return f'''#ifndef {header_guard}
#define {header_guard}

#include <bearssl.h>

#ifdef __cplusplus
extern "C" {{
#endif

#define TAs_NUM 1

{dn_array}

{modulus_array}

static const br_x509_trust_anchor TAs[] = {{
  {{
    {{ (unsigned char *)TA_DN0, sizeof(TA_DN0) }},
    BR_X509_TA_CA,
    {{
      BR_KEYTYPE_RSA,
      {{ .rsa = {{
          (unsigned char *)TA_RSA_N0, sizeof(TA_RSA_N0),
          (unsigned char *)"\\x01\\x00\\x01", 3,
        }}
      }}
    }}
  }}
}};

#ifdef __cplusplus
}}
#endif

#endif // {header_guard}
'''


def main():
    parser = argparse.ArgumentParser(
        description='Convert Root CA certificate (DER format) to Trust Anchor header file.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 generate_trust_anchors.py root_ca.der
  python3 generate_trust_anchors.py root_ca.der trust_anchors.h
  python3 generate_trust_anchors.py amazon_root_ca1.der
        """
    )
    parser.add_argument(
        'input',
        help='Input DER file path (Root CA certificate)'
    )
    parser.add_argument(
        'output',
        nargs='?',
        help='Output header file path (optional, defaults to trust_anchors.h)'
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file '{input_path}' not found.", file=sys.stderr)
        sys.exit(1)

    # Determine output filename
    if args.output:
        output_path = Path(args.output)
        output_name = output_path.stem
    else:
        output_path = Path("trust_anchors.h")
        output_name = "trust_anchors"

    # Check if openssl is available
    try:
        subprocess.run(['openssl', 'version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: openssl command not found", file=sys.stderr)
        print("Please ensure openssl is installed and available in PATH", file=sys.stderr)
        sys.exit(1)

    try:
        print(f"Extracting DN (Distinguished Name) from {input_path}...")
        dn_der = extract_dn_der(input_path)
        print(f"  DN length: {len(dn_der)} bytes")
        
        print(f"Extracting RSA modulus from {input_path}...")
        modulus_bytes, modulus_bits = extract_rsa_modulus(input_path)
        print(f"  Modulus length: {modulus_bits} bits ({len(modulus_bytes)} bytes)")
        
        print(f"Generating Trust Anchor header: {output_path}")
        trust_anchors_content = generate_trust_anchors_h(dn_der, modulus_bytes, modulus_bits, output_name)
        
        with open(output_path, 'w') as f:
            f.write(trust_anchors_content)
        
        print(f"Successfully generated: {output_path}")
        print(f"  Array names: TA_DN0, TA_RSA_N0")
        print(f"  Trust Anchor array: TAs (with TAs_NUM = 1)")
        
    except Exception as e:
        print(f"Error: Failed to generate Trust Anchor: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
