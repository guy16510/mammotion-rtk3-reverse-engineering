#include <Arduino.h>
#include <LittleFS.h>
#include <WebServer.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mbedtls/x509_crt.h"

#if __has_include("secrets.h")
#include "secrets.h"
#else
#define RTK3_IP ""
#endif

namespace {

constexpr uint16_t kTlsPort = 8883;
constexpr uint32_t kAutoStartAfterMs = 12000U;
constexpr uint32_t kConnectTimeoutMs = 6000U;
constexpr uint32_t kHandshakeTimeoutSeconds = 8U;
constexpr const char* kEvidencePath = "/rtk3-tls-evidence.json";

WebServer tlsServer(81);
SemaphoreHandle_t tlsMutex = nullptr;
TaskHandle_t tlsTask = nullptr;
bool tlsServerStarted = false;
bool autoProbeStarted = false;
bool tlsProbeActive = false;
String tlsEvidence = "{\"state\":\"not-run\"}";

String jsonEscape(const String& value) {
  String out;
  out.reserve(value.length() + 24);
  for (size_t i = 0; i < value.length(); ++i) {
    const char c = value[i];
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '"': out += "\\\""; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<uint8_t>(c) >= 0x20) out += c;
        break;
    }
  }
  return out;
}

String fingerprintText(const uint8_t fingerprint[32]) {
  String value;
  value.reserve(95);
  char byteText[4];
  for (size_t i = 0; i < 32; ++i) {
    if (i) value += ':';
    snprintf(byteText, sizeof(byteText), "%02X", fingerprint[i]);
    value += byteText;
  }
  return value;
}

String x509Name(const mbedtls_x509_name& name) {
  char buffer[512]{};
  const int written = mbedtls_x509_dn_gets(buffer, sizeof(buffer), &name);
  return written > 0 ? String(buffer) : String();
}

String x509Time(const mbedtls_x509_time& value) {
  char buffer[32]{};
  snprintf(buffer, sizeof(buffer), "%04d-%02d-%02dT%02d:%02d:%02dZ",
           value.year, value.mon, value.day, value.hour, value.min, value.sec);
  return String(buffer);
}

class InspectableSecureClient : public WiFiClientSecure {
 public:
  const char* negotiatedVersion() const {
    return mbedtls_ssl_get_version(&sslclient->ssl_ctx);
  }

  const char* negotiatedCipher() const {
    return mbedtls_ssl_get_ciphersuite(&sslclient->ssl_ctx);
  }

  const char* negotiatedAlpn() const {
    return mbedtls_ssl_get_alpn_protocol(&sslclient->ssl_ctx);
  }
};

struct TlsAttempt {
  String label;
  bool connected = false;
  uint32_t handshakeMs = 0;
  int errorCode = 0;
  String errorText;
  String tlsVersion;
  String cipherSuite;
  String alpn;
  String certificateSubject;
  String certificateIssuer;
  String certificateSerial;
  String certificateNotBefore;
  String certificateNotAfter;
  String certificateInfo;
  String certificateSha256;
  String clientCertificateAssessment;
};

String serialNumberText(const mbedtls_x509_buf& serial) {
  String value;
  value.reserve(serial.len * 3U);
  char byteText[4];
  for (size_t i = 0; i < serial.len; ++i) {
    if (i) value += ':';
    snprintf(byteText, sizeof(byteText), "%02X", serial.p[i]);
    value += byteText;
  }
  return value;
}

TlsAttempt runTlsAttempt(const IPAddress& address, bool sendIpAsSni,
                         bool advertiseMqttAlpn) {
  TlsAttempt result;
  result.label = sendIpAsSni ? "ip-sni" : "no-sni";
  if (advertiseMqttAlpn) result.label += "-mqtt-alpn";

  InspectableSecureClient client;
  client.setInsecure();
  client.setHandshakeTimeout(kHandshakeTimeoutSeconds);
  client.setTimeout(kHandshakeTimeoutSeconds);

  const char* mqttAlpn[] = {"mqtt", nullptr};
  if (advertiseMqttAlpn) client.setAlpnProtocols(mqttAlpn);

  const uint32_t started = millis();
  if (sendIpAsSni) {
    result.connected = client.connect(address, kTlsPort, RTK3_IP, nullptr,
                                      nullptr, nullptr) == 1;
  } else {
    result.connected = client.connect(address, kTlsPort, kConnectTimeoutMs) == 1;
  }
  result.handshakeMs = millis() - started;

  if (!result.connected) {
    char errorBuffer[192]{};
    result.errorCode = client.lastError(errorBuffer, sizeof(errorBuffer));
    result.errorText = errorBuffer;
    result.clientCertificateAssessment =
        "unknown-handshake-failed; inspect TLS error for client-auth clues";
    client.stop();
    return result;
  }

  const char* version = client.negotiatedVersion();
  const char* cipher = client.negotiatedCipher();
  const char* alpn = client.negotiatedAlpn();
  result.tlsVersion = version ? version : "";
  result.cipherSuite = cipher ? cipher : "";
  result.alpn = alpn ? alpn : "";
  result.clientCertificateAssessment =
      "not-required-for-this-successful-anonymous-handshake";

  const mbedtls_x509_crt* certificate = client.getPeerCertificate();
  if (certificate) {
    result.certificateSubject = x509Name(certificate->subject);
    result.certificateIssuer = x509Name(certificate->issuer);
    result.certificateSerial = serialNumberText(certificate->serial);
    result.certificateNotBefore = x509Time(certificate->valid_from);
    result.certificateNotAfter = x509Time(certificate->valid_to);

    char infoBuffer[2048]{};
    const int infoLength = mbedtls_x509_crt_info(
        infoBuffer, sizeof(infoBuffer), "", certificate);
    if (infoLength > 0) result.certificateInfo = infoBuffer;

    uint8_t fingerprint[32]{};
    if (client.getFingerprintSHA256(fingerprint)) {
      result.certificateSha256 = fingerprintText(fingerprint);
    }
  }

  client.stop();
  return result;
}

String attemptJson(const TlsAttempt& result) {
  String json;
  json.reserve(1024 + result.certificateInfo.length());
  json += "{\"label\":\"" + jsonEscape(result.label) + "\"";
  json += ",\"connected\":" + String(result.connected ? "true" : "false");
  json += ",\"handshakeMs\":" + String(result.handshakeMs);
  json += ",\"errorCode\":" + String(result.errorCode);
  json += ",\"errorText\":\"" + jsonEscape(result.errorText) + "\"";
  json += ",\"tlsVersion\":\"" + jsonEscape(result.tlsVersion) + "\"";
  json += ",\"cipherSuite\":\"" + jsonEscape(result.cipherSuite) + "\"";
  json += ",\"alpn\":\"" + jsonEscape(result.alpn) + "\"";
  json += ",\"certificateSubject\":\"" +
          jsonEscape(result.certificateSubject) + "\"";
  json += ",\"certificateIssuer\":\"" +
          jsonEscape(result.certificateIssuer) + "\"";
  json += ",\"certificateSerial\":\"" +
          jsonEscape(result.certificateSerial) + "\"";
  json += ",\"certificateNotBefore\":\"" +
          jsonEscape(result.certificateNotBefore) + "\"";
  json += ",\"certificateNotAfter\":\"" +
          jsonEscape(result.certificateNotAfter) + "\"";
  json += ",\"certificateSha256\":\"" +
          jsonEscape(result.certificateSha256) + "\"";
  json += ",\"clientCertificateAssessment\":\"" +
          jsonEscape(result.clientCertificateAssessment) + "\"";
  json += ",\"certificateInfo\":\"" +
          jsonEscape(result.certificateInfo) + "\"}";
  return json;
}

void saveEvidence(const String& json) {
  File file = LittleFS.open(kEvidencePath, FILE_WRITE);
  if (!file) {
    Serial.println("[tls-evidence] unable to write evidence file");
    return;
  }
  file.print(json);
  file.close();
}

void tlsProbeTask(void*) {
  IPAddress address;
  String finalJson;
  if (!address.fromString(RTK3_IP)) {
    finalJson = "{\"state\":\"error\",\"error\":\"invalid RTK3_IP\"}";
  } else {
    const uint32_t started = millis();
    const TlsAttempt noSni = runTlsAttempt(address, false, false);
    const TlsAttempt ipSniMqtt = runTlsAttempt(address, true, true);

    finalJson.reserve(2600 + noSni.certificateInfo.length() +
                      ipSniMqtt.certificateInfo.length());
    finalJson = "{\"state\":\"completed\"";
    finalJson += ",\"targetIp\":\"" + String(RTK3_IP) + "\"";
    finalJson += ",\"port\":" + String(kTlsPort);
    finalJson += ",\"durationMs\":" + String(millis() - started);
    finalJson += ",\"attempts\":[" + attemptJson(noSni) + "," +
                 attemptJson(ipSniMqtt) + "]}";
  }

  xSemaphoreTake(tlsMutex, portMAX_DELAY);
  tlsEvidence = finalJson;
  tlsProbeActive = false;
  xSemaphoreGive(tlsMutex);
  saveEvidence(finalJson);

  Serial.println("[tls-evidence] probe complete");
  Serial.println(finalJson);
  tlsTask = nullptr;
  vTaskDelete(nullptr);
}

bool startTlsProbe() {
  if (WiFi.status() != WL_CONNECTED || !tlsMutex) return false;

  xSemaphoreTake(tlsMutex, portMAX_DELAY);
  if (tlsProbeActive) {
    xSemaphoreGive(tlsMutex);
    return false;
  }
  tlsProbeActive = true;
  tlsEvidence = "{\"state\":\"running\"}";
  xSemaphoreGive(tlsMutex);

  LittleFS.remove(kEvidencePath);
  const BaseType_t created =
      xTaskCreate(tlsProbeTask, "tls-evidence", 16384, nullptr, 1, &tlsTask);
  if (created != pdPASS) {
    xSemaphoreTake(tlsMutex, portMAX_DELAY);
    tlsProbeActive = false;
    tlsEvidence =
        "{\"state\":\"error\",\"error\":\"task creation failed\"}";
    xSemaphoreGive(tlsMutex);
    return false;
  }
  return true;
}

String currentEvidence() {
  if (!tlsMutex) return "{\"state\":\"initializing\"}";
  xSemaphoreTake(tlsMutex, portMAX_DELAY);
  const String copy = tlsEvidence;
  const bool active = tlsProbeActive;
  xSemaphoreGive(tlsMutex);

  if (!active && LittleFS.exists(kEvidencePath)) {
    File file = LittleFS.open(kEvidencePath, FILE_READ);
    if (file) {
      const String persisted = file.readString();
      file.close();
      if (!persisted.isEmpty()) return persisted;
    }
  }
  return copy;
}

void initializeTlsEvidenceServer() {
  tlsMutex = xSemaphoreCreateMutex();
  if (!tlsMutex) {
    Serial.println("[tls-evidence] mutex allocation failed");
    return;
  }

  tlsServer.on("/", HTTP_GET, [] {
    tlsServer.sendHeader("Cache-Control", "no-store");
    tlsServer.send(200, "application/json", currentEvidence());
  });
  tlsServer.on("/healthz", HTTP_GET, [] {
    tlsServer.send(200, "application/json", "{\"ok\":true}");
  });
  tlsServer.on("/probe", HTTP_POST, [] {
    const bool started = startTlsProbe();
    tlsServer.send(started ? 202 : 409, "application/json",
                   started ? "{\"state\":\"started\"}"
                           : "{\"error\":\"probe active or Wi-Fi disconnected\"}");
  });
  tlsServer.onNotFound([] {
    tlsServer.send(404, "application/json", "{\"error\":\"not found\"}");
  });
  tlsServer.begin();
  tlsServerStarted = true;
  Serial.printf("[tls-evidence] endpoint http://%s:81/\n",
                WiFi.localIP().toString().c_str());
}

}  // namespace

void serialEventRun(void) {
  if (!tlsServerStarted && WiFi.status() == WL_CONNECTED && millis() > 3000U) {
    initializeTlsEvidenceServer();
  }

  if (tlsServerStarted) tlsServer.handleClient();

  if (!autoProbeStarted && tlsServerStarted &&
      millis() >= kAutoStartAfterMs) {
    autoProbeStarted = true;
    startTlsProbe();
  }
}
