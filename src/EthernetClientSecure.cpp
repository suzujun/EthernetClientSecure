#include "EthernetClientSecure.h"
#include <Ethernet3.h>
#include <EthernetClient.h>
#include <SSLClient.h>
#include <SSLClientParameters.h>
#include <bearssl.h>

// Structure to hide implementation details
struct EthernetClientSecureImpl {
  EthernetClient *eth_client;
  SSLClient *ssl_client;
  SSLClientParameters *mTLS_params;
  bool initialized;
  bool mTLS_configured;
};

EthernetClientSecure::EthernetClientSecure() : impl_ptr(nullptr), initialized(false) {
  EthernetClientSecureImpl *impl = new EthernetClientSecureImpl();
  impl->eth_client = new EthernetClient();
  impl->ssl_client = nullptr;
  impl->mTLS_params = nullptr;
  impl->initialized = false;
  impl->mTLS_configured = false;
  impl_ptr = impl;
}

EthernetClientSecure::~EthernetClientSecure() {
  if (impl_ptr != nullptr) {
    EthernetClientSecureImpl *impl = static_cast<EthernetClientSecureImpl *>(impl_ptr);
    if (impl->mTLS_params != nullptr) {
      delete impl->mTLS_params;
    }
    if (impl->ssl_client != nullptr) {
      delete impl->ssl_client;
    }
    if (impl->eth_client != nullptr) {
      delete impl->eth_client;
    }
    delete impl;
    impl_ptr = nullptr;
  }
}

bool EthernetClientSecure::begin(const br_x509_trust_anchor *trust_anchors, size_t trust_anchors_num) {
  if (impl_ptr == nullptr) {
    return false;
  }

  EthernetClientSecureImpl *impl = static_cast<EthernetClientSecureImpl *>(impl_ptr);

  if (impl->initialized) {
    // Reinitialize if already initialized
    if (impl->ssl_client != nullptr) {
      delete impl->ssl_client;
      impl->ssl_client = nullptr;
    }
  }

  // On ESP32, analog_pin is not used but required by SSLClient constructor (0 is OK)
  int analog_pin = 0;

  // Initialize SSLClient with Trust Anchor format root certificates
  impl->ssl_client = new SSLClient(*impl->eth_client, trust_anchors, trust_anchors_num, analog_pin);

  // Set timeout (default 5 seconds)
  impl->ssl_client->setTimeout(5000);

  impl->initialized = true;
  initialized = true;

  Serial.println("EthernetClientSecure: Initialized with Trust Anchors");
  return true;
}

bool EthernetClientSecure::setCertificate(const uint8_t *certificate_der, size_t certificate_len,
                                          const uint8_t *private_key_der, size_t private_key_len) {
  if (impl_ptr == nullptr || !initialized) {
    Serial.println("EthernetClientSecure: Not initialized. Call begin() first.");
    return false;
  }

  EthernetClientSecureImpl *impl = static_cast<EthernetClientSecureImpl *>(impl_ptr);

  if (impl->ssl_client == nullptr) {
    Serial.println("EthernetClientSecure: SSLClient not initialized");
    return false;
  }

  // Delete existing parameters
  if (impl->mTLS_params != nullptr) {
    delete impl->mTLS_params;
    impl->mTLS_params = nullptr;
  }

  // Create SSLClientParameters from DER format certificate and private key
  impl->mTLS_params = new SSLClientParameters(
      SSLClientParameters::fromDER(
          (const char *)certificate_der, certificate_len,
          (const char *)private_key_der, private_key_len));

  // Set mutual authentication parameters
  impl->ssl_client->setMutualAuthParams(*impl->mTLS_params);
  impl->mTLS_configured = true;

  Serial.println("EthernetClientSecure: Client certificate configured");
  return true;
}

bool EthernetClientSecure::connect(const char *host, uint16_t port) {
  if (impl_ptr == nullptr || !initialized) {
    Serial.println("EthernetClientSecure: Not initialized");
    return false;
  }

  EthernetClientSecureImpl *impl = static_cast<EthernetClientSecureImpl *>(impl_ptr);

  if (impl->ssl_client == nullptr) {
    Serial.println("EthernetClientSecure: SSLClient not initialized");
    return false;
  }

  Serial.printf("EthernetClientSecure: Connecting to %s:%d...\n", host, port);
  bool result = impl->ssl_client->connect(host, port);

  if (result) {
    Serial.println("EthernetClientSecure: Connected");
  } else {
    Serial.println("EthernetClientSecure: Connection failed");
  }

  return result;
}

void EthernetClientSecure::stop() {
  if (impl_ptr == nullptr) {
    return;
  }

  EthernetClientSecureImpl *impl = static_cast<EthernetClientSecureImpl *>(impl_ptr);

  if (impl->ssl_client != nullptr) {
    impl->ssl_client->stop();
  }
}

bool EthernetClientSecure::connected() {
  if (impl_ptr == nullptr || !initialized) {
    return false;
  }

  EthernetClientSecureImpl *impl = static_cast<EthernetClientSecureImpl *>(impl_ptr);

  if (impl->ssl_client == nullptr) {
    return false;
  }

  return impl->ssl_client->connected();
}

void EthernetClientSecure::setTimeout(uint32_t timeout) {
  if (impl_ptr == nullptr) {
    return;
  }

  EthernetClientSecureImpl *impl = static_cast<EthernetClientSecureImpl *>(impl_ptr);

  if (impl->ssl_client != nullptr) {
    impl->ssl_client->setTimeout(timeout);
  }
}

SSLClient *EthernetClientSecure::getSSLClient() {
  if (impl_ptr == nullptr) {
    return nullptr;
  }

  EthernetClientSecureImpl *impl = static_cast<EthernetClientSecureImpl *>(impl_ptr);
  return impl->ssl_client;
}

EthernetClient *EthernetClientSecure::getEthernetClient() {
  if (impl_ptr == nullptr) {
    return nullptr;
  }

  EthernetClientSecureImpl *impl = static_cast<EthernetClientSecureImpl *>(impl_ptr);
  return impl->eth_client;
}

// Client interface compatible methods
int EthernetClientSecure::available() {
  if (impl_ptr == nullptr || !initialized) {
    return 0;
  }

  EthernetClientSecureImpl *impl = static_cast<EthernetClientSecureImpl *>(impl_ptr);
  if (impl->ssl_client == nullptr) {
    return 0;
  }
  return impl->ssl_client->available();
}

int EthernetClientSecure::read() {
  if (impl_ptr == nullptr || !initialized) {
    return -1;
  }

  EthernetClientSecureImpl *impl = static_cast<EthernetClientSecureImpl *>(impl_ptr);
  if (impl->ssl_client == nullptr) {
    return -1;
  }
  return impl->ssl_client->read();
}

int EthernetClientSecure::read(uint8_t *buf, size_t size) {
  if (impl_ptr == nullptr || !initialized) {
    return 0;
  }

  EthernetClientSecureImpl *impl = static_cast<EthernetClientSecureImpl *>(impl_ptr);
  if (impl->ssl_client == nullptr) {
    return 0;
  }
  return impl->ssl_client->read(buf, size);
}

size_t EthernetClientSecure::write(uint8_t byte) {
  if (impl_ptr == nullptr || !initialized) {
    return 0;
  }

  EthernetClientSecureImpl *impl = static_cast<EthernetClientSecureImpl *>(impl_ptr);
  if (impl->ssl_client == nullptr) {
    return 0;
  }
  return impl->ssl_client->write(byte);
}

size_t EthernetClientSecure::write(const uint8_t *buf, size_t size) {
  if (impl_ptr == nullptr || !initialized) {
    return 0;
  }

  EthernetClientSecureImpl *impl = static_cast<EthernetClientSecureImpl *>(impl_ptr);
  if (impl->ssl_client == nullptr) {
    return 0;
  }
  return impl->ssl_client->write(buf, size);
}

int EthernetClientSecure::peek() {
  if (impl_ptr == nullptr || !initialized) {
    return -1;
  }

  EthernetClientSecureImpl *impl = static_cast<EthernetClientSecureImpl *>(impl_ptr);
  if (impl->ssl_client == nullptr) {
    return -1;
  }
  return impl->ssl_client->peek();
}

void EthernetClientSecure::flush() {
  if (impl_ptr == nullptr || !initialized) {
    return;
  }

  EthernetClientSecureImpl *impl = static_cast<EthernetClientSecureImpl *>(impl_ptr);
  if (impl->ssl_client != nullptr) {
    impl->ssl_client->flush();
  }
}
