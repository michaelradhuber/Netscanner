#define DEBUG //Enable for debugging output over Serial

#include <Arduino.h>
#include "../lib/netscanner.h"


/* ---- DEBUG SECTION ---- */

#ifdef DEBUG
  #define DEBUG_PRINT(x)  Serial.print (x)
  #define DEBUG_PRINTLN(x)  Serial.println (x)
  #define DEBUG_PRINTF(x, y)  Serial.printf (x, y)
#else
  #define DEBUG_PRINT(x)
  #define DEBUG_PRINTLN(x)
  #define DEBUG_PRINTF(x)
#endif

/* ---- END DEBUG SECTION ---- */

NetScanner scanner;
char IP_char[] = {"192.168.0.1"};
char MAC_char[] = {"a3:44:23:71:f6:e8"};

void setup() {
  #ifdef DEBUG
  Serial.begin(115200);
  #endif
  // put your setup code here, to run once:
  scanner.begin();
  const char *eth_ret = scanner.findIP(IP_char);
  if (eth_ret != nullptr) {
    DEBUG_PRINTLN(F("IP found in ARP table"));
    //Need to implement check for MAC address here (if MAC = MAC_char)
    DEBUG_PRINT(F("Comparing current MAC with stored MAC: "));
    int z = strcmp(MAC_char, eth_ret);
    DEBUG_PRINTLN((z==0) ? F("MAC address matches") : F("MAC address does not match"));
  } else {
    scanner.end();
    delay(500); //Give the destructor some time to clean up
    scanner.begin();
     //Resolve IP by MAC
     char* IPResult = scanner.findIPbyMAC(MAC_char);
     if (IPResult != nullptr) {
       DEBUG_PRINT(F("Resolved IP: "));
       DEBUG_PRINTLN(IPResult);
     }
  }
  scanner.end();
  delay(500); //Give the destructor some time to clean up
}

void loop() {
  // put your main code here, to run repeatedly:
}