#include <stdio.h>
#include <string.h>
#include <WiFi.h>
#include <ESPping.h>
#include <WiFi.h>
#include <esp_log.h>

void local_scan_setup();
void scanPorts(IPAddress host);
void afterScanOptions(IPAddress ip);
void startArpSpoofing(IPAddress target_ip, const uint8_t *target_mac); 