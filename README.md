# NetScanner Library

The NetScanner library provides functionality for scanning IPv4 networks and managing the ARP table on ESP32 devices. It is designed to work with FreeRTOS and utilizes the ESP-IDF framework for networking capabilities.

## Features

    Send ARP requests to discover devices on the network.
    Read and manage the ARP table.
    Print the ARP table entries, including IP, MAC address, and vendor information.
    Finds IP addresses and corresponding MAC addresses.
    Searches for IP with a given MAC address.


## Installation

To use the `NetScanner` library in your PlatformIO project, place the library in the `lib` directory of your project:

## Usage

Include the `netscanner.h` header file in your main application file and create an instance of the `NetScanner` class.

### Example

```cpp
#include <Arduino.h>
#include "netscanner.h"

NetScanner netScanner;
char IP_char[] = {"192.168.0.1"};

void setup() {
    Serial.begin(115200);
    netScanner.begin();
    const char *eth_ret = netScanner.findIP(IP_char);
    if (eth_ret != nullptr) {
    Serial.println(F("IP found in ARP table"));
    }
    netScanner.end();
    delay(500); //Give the destructor some time to clean up
}

void loop() {
    // Your code here
}
```

## Methods
- void begin(): Initializes the network settings and retrieves IP information.
- void splitIp(char* interface_ip, char* from_ip): Splits the IP address into a format suitable for network scanning.
- void readArpTable(char* from_ip, int read_from, int read_to): Reads and stores ARP table entries from the specified IP range.
- void sendArp(char* from_ip): Sends ARP requests to the network.
- void printArpTable(): Prints the ARP table.
- const char* findIP(const char* IP_ToFind): Finds the MAC address for a given IP address.
- char* findIPbyMAC(const char* MAC_ToFind): Finds the IP address for a given MAC address.
- void end(): Manual destructor. It is recommended to clear the library memory before running another instance due to memory usage.

## License
This library is licensed under the MIT License. See the LICENSE file for more details.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request on GitHub.