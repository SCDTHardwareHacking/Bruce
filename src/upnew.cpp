#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Update.h>
#include <TFT_eSPI.h>
#include "update.h"

extern TFT_eSPI tft;

const char* versionUrl = "https://kript0n007.github.io/bruce_arp_spoofing/version.txt";
const char* firmwareUrl = "https://kript0n007.github.io/bruce_arp_spoofing/firmware.bin";
const char* currentVersion = "1.4";

void checkForUpdate();
void performOTA();
void showStatusMessage(const char* message);
void showMemoryInfo();

void initializePartitionsAndCheckForUpdate() {
    // Mostrar informações de partições (ajustado para ambiente Arduino)
    Serial.println("Partição atual:");
    const esp_partition_t* running = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_OTA_0, NULL);
    if (running != NULL) {
        Serial.printf("Label: %s, Address: 0x%X, Size: 0x%X\n", running->label, running->address, running->size);
    }

    // Mostrar todas as partições OTA
    Serial.println("\nPartições OTA:");
    esp_partition_iterator_t partition_iter = esp_partition_find(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_OTA_MIN, NULL);
    while (partition_iter != NULL) {
        const esp_partition_t* partition = esp_partition_get(partition_iter);
        Serial.printf("Label: %s, Address: 0x%X, Size: 0x%X\n", partition->label, partition->address, partition->size);
        partition_iter = esp_partition_next(partition_iter);
    }
    esp_partition_iterator_release(partition_iter);

    // Mostrar memória disponível
    showMemoryInfo();

    // Verificar se há atualizações
    checkForUpdate();
}

void checkForUpdate() {
    WiFiClientSecure client;
    HTTPClient http;

    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setTextSize(2);
    tft.setCursor(10, 10);
    tft.println("Checking for updates...");
    tft.setTextSize(1);

    showStatusMessage("Checking for firmware version...");
    client.setInsecure();
    http.begin(client, versionUrl);
    int httpCode = http.GET();

    if (httpCode == HTTP_CODE_OK) {
        String newVersion = http.getString();
        newVersion.trim();

        Serial.printf("Current version: %s\n", currentVersion);
        Serial.printf("New version: %s\n", newVersion.c_str());

        if (newVersion != currentVersion) {
            char buffer[50];
            sprintf(buffer, "New version available: %s", newVersion.c_str());
            showStatusMessage(buffer);
            performOTA();
        } else {
            showStatusMessage("Firmware is up to date.");
        }
    } else {
        char buffer[50];
        sprintf(buffer, "HTTP error code: %d", httpCode);
        showStatusMessage("HTTP request failed.");
        showStatusMessage(http.errorToString(httpCode).c_str());
        showStatusMessage(buffer);
    }
    http.end();
}

void performOTA() {
    WiFiClientSecure client;
    HTTPClient http;

    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setTextSize(2);
    tft.setCursor(10, 10);
    tft.println("Performing OTA...");
    tft.setTextSize(1);

    showStatusMessage("Checking for firmware update...");
    client.setInsecure();
    http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
    http.begin(client, firmwareUrl);
    int httpCode = http.GET();

    if (httpCode == HTTP_CODE_OK) {
        int contentLength = http.getSize();
        Serial.printf("Content length: %d\n", contentLength);

        if (contentLength > 0) {
            bool canBegin = Update.begin(contentLength);
            Serial.printf("Can begin update: %s\n", canBegin ? "Yes" : "No");

            if (canBegin) {
                showStatusMessage("Begin OTA update...");
                WiFiClient * stream = http.getStreamPtr();
                size_t written = 0;
                uint8_t buff[128] = { 0 }; // Diminuir o tamanho do buffer para 128 bytes
                int retryCount = 0;
                const int maxRetries = 5; // número máximo de tentativas

                while (written < contentLength) {
                    size_t len = stream->available();
                    if (len) {
                        int c = stream->readBytes(buff, ((len > sizeof(buff)) ? sizeof(buff) : len));
                        written += Update.write(buff, c);
                        Serial.printf("Written bytes: %d\n", written);
                        retryCount = 0; // Resetar contador de tentativas após sucesso
                    } else {
                        delay(50); // Atraso para evitar travamentos
                        retryCount++;
                        if (retryCount > maxRetries) {
                            showStatusMessage("Error: Too many retries.");
                            Update.abort();
                            return;
                        }
                    }
                    // Verificação de memória disponível
                    showMemoryInfo();
                    size_t freeHeap = ESP.getFreeHeap();
                    if (freeHeap < 10000) { // Se a memória livre for menor que 10KB, abortar
                        showStatusMessage("Error: Not enough memory.");
                        Update.abort();
                        return;
                    }
                }

                if (written == contentLength) {
                    showStatusMessage("OTA update completed!");
                    if (Update.end()) {
                        showStatusMessage("Update successfully applied, restarting...");
                        delay(2000);
                        ESP.restart();
                    } else {
                        showStatusMessage("Update failed.");
                        showStatusMessage(Update.errorString());
                        // Serial.printf("Update failed: %s\n", Update.errorString().c_str());
                    }
                } else {
                    char buffer[50];
                    sprintf(buffer, "Written only: %d/%d. Retry?", written, contentLength);
                    showStatusMessage(buffer);
                    Serial.printf("Written only: %d/%d. Retry?\n", written, contentLength);
                }
            } else {
                showStatusMessage("Not enough space to begin OTA update");
            }
        } else {
            showStatusMessage("Content length is 0. Aborting update.");
        }
    } else {
        char buffer[50];
        sprintf(buffer, "HTTP error code: %d", httpCode);
        showStatusMessage("HTTP request failed.");
        showStatusMessage(http.errorToString(httpCode).c_str());
        showStatusMessage(buffer);
    }
    http.end();
}

void showStatusMessage(const char* message) {
    tft.println(message);
    Serial.println(message);
}

void showMemoryInfo() {
    size_t freeHeap = ESP.getFreeHeap();
    size_t totalHeap = ESP.getHeapSize();
    size_t totalPsram = ESP.getPsramSize();
    size_t freePsram = ESP.getFreePsram();

    Serial.printf("Free heap: %d bytes\n", freeHeap);
    Serial.printf("Total heap: %d bytes\n", totalHeap);
    Serial.printf("Total PSRAM: %d bytes\n", totalPsram);
    Serial.printf("Free PSRAM: %d bytes\n", freePsram);

    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setTextSize(2);
    tft.setCursor(10, 10);
    tft.println("Memory Info:");
    tft.setTextSize(1);
    tft.printf("Free heap: %d bytes\n", freeHeap);
    tft.printf("Total heap: %d bytes\n", totalHeap);
    tft.printf("Total PSRAM: %d bytes\n", totalPsram);
    tft.printf("Free PSRAM: %d bytes\n", freePsram);
}
