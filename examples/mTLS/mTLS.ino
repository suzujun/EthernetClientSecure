#include "certificate_der.h" // Client certificate (DER format)
#include "private_key_der.h" // Private key (DER format)
#include "trust_anchors.h"
#include <EthernetClientSecure.h>

EthernetClientSecure secureClient;

void setup() {
  // ... Ethernet initialization ...

  // Initialize with Trust Anchors
  secureClient.begin(TAs, TAs_NUM);

  // Set client certificate for mutual authentication
  secureClient.setCertificate(
      certificate_der, sizeof(certificate_der),
      private_key_der, sizeof(private_key_der));

  // Connect with mTLS
  if (secureClient.connect("api.example.com", 443)) {
    // Secure connection established with mutual authentication
  }
}

void loop() {
  // Your code here
}
