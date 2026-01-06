#include <EthernetClientSecure.h>
#include <Ethernet3.h>
#include "trust_anchors.h" // Your root CA certificates

EthernetClientSecure secureClient;

void setup()
{
    Serial.begin(115200);

    // Initialize Ethernet (example)
    Ethernet.init(CS_PIN);
    if (Ethernet.begin(mac) == 0)
    {
        Serial.println("Failed to configure Ethernet");
        return;
    }

    // Initialize secure client with Trust Anchors
    if (!secureClient.begin(trust_anchors, trust_anchors_num))
    {
        Serial.println("Failed to initialize secure client");
        return;
    }

    // Connect to server
    if (secureClient.connect("example.com", 443))
    {
        Serial.println("Connected!");

        // Send HTTP request
        secureClient.println("GET / HTTP/1.1");
        secureClient.println("Host: example.com");
        secureClient.println();

        // Read response
        while (secureClient.connected() || secureClient.available())
        {
            if (secureClient.available())
            {
                char c = secureClient.read();
                Serial.print(c);
            }
        }

        secureClient.stop();
    }
}

void loop()
{
    // Your code here
}
