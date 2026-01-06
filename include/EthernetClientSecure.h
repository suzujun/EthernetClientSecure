#pragma once

#include <Arduino.h>
#include <bearssl.h>

// Forward declarations
class SSLClient;
class EthernetClient;

/**
 * @brief Secure client supporting Ethernet + TLS/SSL
 *
 * This class provides TLS/SSL communication over Ethernet connections.
 * Supports certificate validation via Trust Anchors and mutual authentication with client certificates.
 */
class EthernetClientSecure {
public:
  EthernetClientSecure();
  ~EthernetClientSecure();

  /**
   * @brief Initialize with Trust Anchors (root CA certificates)
   * @param trust_anchors Pointer to Trust Anchor array
   * @param trust_anchors_num Number of Trust Anchors
   * @return true if initialization succeeds
   */
  bool begin(const br_x509_trust_anchor *trust_anchors, size_t trust_anchors_num);

  /**
   * @brief Set client certificate and private key (for mutual authentication)
   * @param certificate_der DER-format client certificate
   * @param certificate_len Certificate length in bytes
   * @param private_key_der DER-format private key
   * @param private_key_len Private key length in bytes
   * @return true if configuration succeeds
   */
  bool setCertificate(const uint8_t *certificate_der, size_t certificate_len,
                      const uint8_t *private_key_der, size_t private_key_len);

  /**
   * @brief Connect to server
   * @param host Hostname or IP address
   * @param port Port number
   * @return true if connection succeeds
   */
  bool connect(const char *host, uint16_t port);

  /**
   * @brief Close the connection
   */
  void stop();

  /**
   * @brief Check connection status
   * @return true if connected
   */
  bool connected();

  /**
   * @brief Set timeout
   * @param timeout Timeout in milliseconds
   */
  void setTimeout(uint32_t timeout);

  /**
   * @brief Get reference to SSLClient (for use with other libraries)
   * @return Pointer to SSLClient (nullptr if not initialized)
   */
  SSLClient *getSSLClient();

  /**
   * @brief Get reference to EthernetClient
   * @return Pointer to EthernetClient (nullptr if not initialized)
   */
  EthernetClient *getEthernetClient();

  // Client interface compatible methods
  int available();
  int read();
  int read(uint8_t *buf, size_t size);
  size_t write(uint8_t);
  size_t write(const uint8_t *buf, size_t size);
  int peek();
  void flush();

private:
  void *impl_ptr; // Pointer to implementation details (PIMPL pattern)
  bool initialized;
};
