# EthernetClientSecure

![Logo](images/logo.png)

A secure Ethernet client library for Arduino/ESP32 that provides TLS/SSL support over Ethernet connections. This library wraps `SSLClient` and `EthernetClient` to offer a simple, secure communication interface with certificate validation and mutual authentication (mTLS) support.

## Features

- **TLS/SSL Support**: Secure communication over Ethernet using TLS/SSL
- **Certificate Validation**: Trust Anchor-based root CA certificate verification
- **Mutual Authentication (mTLS)**: Client certificate authentication support
- **Arduino Client Interface Compatible**: Drop-in replacement for standard `EthernetClient`
- **PIMPL Pattern**: Clean interface with hidden implementation details
- **Easy to Use**: Simple API for secure connections

## Requirements

- **Platform**: ESP32 (tested on M5Stack Core2)
- **Framework**: Arduino
- **Dependencies**:
  - `sstaub/Ethernet3@^1.5.6` - Ethernet library
  - `openslab-osu/SSLClient@^1.6.11` - SSL/TLS client library (includes BearSSL)

## Installation

### Using PlatformIO

Add the library to your `platformio.ini`:

```ini
[env:your_env]
platform = espressif32
board = m5stack-core2
framework = arduino

lib_deps =
    suzujun/EthernetClientSecure@^0.1.0
```

### Manual Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/suzujun/EthernetClientSecure.git
   ```

2. Copy the library to your PlatformIO `lib` directory or Arduino libraries folder.

## Usage

### Basic Example

See [examples/Basic/Basic.ino](examples/Basic/Basic.ino) for a complete example demonstrating basic TLS/SSL connection with certificate validation.

### With Mutual Authentication (mTLS)

See [examples/mTLS/mTLS.ino](examples/mTLS/mTLS.ino) for an example showing how to use client certificates for mutual authentication.

### Utility Scripts

This library includes utility scripts to help you convert certificates to the required formats:

- **`scripts/generate_trust_anchors.py`**: Converts Root CA certificates (DER format) to BearSSL Trust Anchor header files
- **`scripts/generate_der_h.py`**: Converts DER format certificates/keys to C header files with byte arrays

See the [Certificate Format](#certificate-format) section below for detailed usage instructions.

## API Reference

### Constructor

```cpp
EthernetClientSecure();
```

Creates a new `EthernetClientSecure` instance.

### Methods

#### `bool begin(const br_x509_trust_anchor *trust_anchors, size_t trust_anchors_num)`

Initializes the secure client with Trust Anchors (root CA certificates) for server certificate validation.

- **Parameters**:
  - `trust_anchors`: Pointer to Trust Anchor array
  - `trust_anchors_num`: Number of Trust Anchors
- **Returns**: `true` if initialization succeeds, `false` otherwise

#### `bool setCertificate(const uint8_t *certificate_der, size_t certificate_len, const uint8_t *private_key_der, size_t private_key_len)`

Sets the client certificate and private key for mutual authentication (mTLS).

- **Parameters**:
  - `certificate_der`: DER-format client certificate
  - `certificate_len`: Certificate length in bytes
  - `private_key_der`: DER-format private key
  - `private_key_len`: Private key length in bytes
- **Returns**: `true` if configuration succeeds, `false` otherwise
- **Note**: Must be called after `begin()`

#### `bool connect(const char *host, uint16_t port)`

Connects to a secure server.

- **Parameters**:
  - `host`: Hostname or IP address
  - `port`: Port number (typically 443 for HTTPS)
- **Returns**: `true` if connection succeeds, `false` otherwise

#### `void stop()`

Closes the connection.

#### `bool connected()`

Checks if the client is currently connected.

- **Returns**: `true` if connected, `false` otherwise

#### `void setTimeout(uint32_t timeout)`

Sets the connection timeout.

- **Parameters**:
  - `timeout`: Timeout in milliseconds (default: 5000ms)

#### `SSLClient *getSSLClient()`

Gets a pointer to the underlying `SSLClient` instance (for advanced usage).

- **Returns**: Pointer to `SSLClient`, or `nullptr` if not initialized

#### `EthernetClient *getEthernetClient()`

Gets a pointer to the underlying `EthernetClient` instance.

- **Returns**: Pointer to `EthernetClient`, or `nullptr` if not initialized

### Client Interface Methods

The library implements the standard Arduino `Client` interface:

- `int available()` - Returns the number of bytes available for reading
- `int read()` - Reads a single byte
- `int read(uint8_t *buf, size_t size)` - Reads multiple bytes
- `size_t write(uint8_t)` - Writes a single byte
- `size_t write(const uint8_t *buf, size_t size)` - Writes multiple bytes
- `int peek()` - Peeks at the next byte without reading it
- `void flush()` - Flushes the output buffer

## Certificate Format

### Trust Anchors (Root CA Certificates)

Trust Anchors must be in BearSSL `br_x509_trust_anchor` format. First, convert your Root CA certificate to DER format:

```bash
# Convert PEM certificate to DER
openssl x509 -in root_ca.crt -outform DER -out root_ca.der
```

#### Using generate_trust_anchors.py

Use the `generate_trust_anchors.py` script to convert Root CA DER files to Trust Anchor header files:

```bash
# Convert Root CA DER file to Trust Anchor header
python3 scripts/generate_trust_anchors.py root_ca.der
# Output: trust_anchors.h

# Or specify output filename
python3 scripts/generate_trust_anchors.py root_ca.der my_trust_anchors.h
```

The script extracts the Distinguished Name (DN) and RSA modulus from the certificate and generates a BearSSL Trust Anchor format header file.

**Requirements**: The script requires `openssl` command-line tool to be installed and available in PATH.

Then use it in your code:

```cpp
#include "trust_anchors.h"

// Initialize with Trust Anchors
secureClient.begin(TAs, TAs_NUM);
```

### Client Certificates (mTLS)

Client certificates and private keys must be in DER format (binary). Convert from PEM format if needed:

```bash
# Convert PEM certificate to DER
openssl x509 -in client.crt -outform DER -out certificate.der

# Convert PEM private key to DER
openssl rsa -in client.key -outform DER -out private_key.der
```

#### Using generate_der_h.py

Use the `generate_der_h.py` script to convert DER files to C header files:

```bash
# Convert DER file to header file
python3 scripts/generate_der_h.py certificate.der
# Output: certificate_der.h

# Or specify output filename
python3 scripts/generate_der_h.py private_key.der private_key_der.h
```

The script generates a header file with a `uint8_t` array containing the DER data. Use `sizeof()` to get the array length.

Example generated header (`certificate_der.h`):

```cpp
static const uint8_t certificate_der[] = {
    0x30, 0x82, 0x03, 0x12, ...
};

// Use sizeof(certificate_der) to get the length
```

Then include them in your code:

```cpp
#include "certificate_der.h"  // Contains: const uint8_t certificate_der[] = { ... };
#include "private_key_der.h"  // Contains: const uint8_t private_key_der[] = { ... };
```

## Architecture

The library uses the PIMPL (Pointer to Implementation) pattern to hide implementation details and reduce compile-time dependencies. The actual implementation uses:

- **EthernetClient** (from Ethernet3): Base Ethernet connection
- **SSLClient** (from openslab-osu/SSLClient): TLS/SSL layer
- **BearSSL**: Underlying cryptographic library

## Limitations

- Currently tested on ESP32 (M5Stack Core2)
- Requires sufficient memory for certificate storage
- Connection timeout defaults to 5 seconds (configurable)

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues, questions, or contributions, please open an issue on [GitHub](https://github.com/suzujun/EthernetClientSecure/issues).

## Acknowledgments

- Built on top of [SSLClient](https://github.com/OPEnSLab-OSU/SSLClient) by OPEnSLab-OSU
- Uses [Ethernet3](https://github.com/sstaub/Ethernet3) by sstaub
- Based on BearSSL cryptographic library
