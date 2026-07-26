#include <Arduino.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <WebServer.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiClientSecure.h>

#include <errno.h>
#include <string.h>

#include "TlsDiagnostics.h"
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
constexpr uint32_t kFallbackAutoStartAfterMs = 45000U;
constexpr uint32_t kTcpConnectTimeoutMs = 1500U;
constexpr uint32_t kTlsConnectTimeoutMs = 6000U;
constexpr uint8_t kMaximumTcpAttempts = 3U;
constexpr uint32_t kTcpRetryDelayMs = 250U;
constexpr uint32_t kTcpSettleDelayMs = 750U;
constexpr uint32_t kTlsAttemptDelayMs = 500U;
constexpr uint32_t kHandshakeTimeoutSeconds = 8U;
constexpr const char* kEvidencePath = "/rtk3-tls-evidence.json";
constexpr const char* kEvidenceTempPath = "/rtk3-tls-evidence.tmp";
constexpr const char* kMainProbeEvidencePath = "/rtk3-probe.json";

WebServer tlsServer(81);
SemaphoreHandle_t tlsMutex = nullptr;
TaskHandle_t tlsTask = nullptr;
bool tlsServerStarted = false;
bool autoProbeStarted = false;
bool tlsProbeActive = false;
String tlsProbeTrigger = "not-started";
String tlsEvidence = "{\"state\":\"not-run\"}";

String jsonEscape(const String& value) {
  String out;
  out.reserve(value.length() + 24);
  for (size_t i = 0; i < value.length(); ++i) {
    const char c = value[i];
    switch (c) {
      case '\\':
        out += "\\\\";
        break;
      case '"':
        out += "\\\"";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
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

uint32_t ipv4Value(const IPAddress& address) {
  return TlsDiagnostics::ipv4Value(address[0], address[1], address[2],
                                   address[3]);
}

bool isAllowedTarget(const IPAddress& address) {
  return TlsDiagnostics::isAllowedPrivateIpv4(
      address[0], address[1], address[2], address[3]);
}

struct TargetSelection {
  String ip;
  String source;
};

TargetSelection loadTargetSelection() {
  TargetSelection selection;
  selection.ip = RTK3_IP;
  selection.source = "compile-time";

  Preferences preferences;
  if (preferences.begin("rtk3-probe", true)) {
    const String savedIp = preferences.getString("target_ip", "");
    preferences.end();
    if (!savedIp.isEmpty()) {
      selection.ip = savedIp;
      selection.source = "nvs";
    }
  }

  selection.ip.trim();
  return selection;
}

struct NetworkSnapshot {
  String ssid;
  String bssid;
  String localIp;
  String subnetMask;
  String gatewayIp;
  String dnsIp;
  int32_t rssi = 0;
  int32_t channel = 0;
  bool targetOnLocalSubnet = false;
};

NetworkSnapshot captureNetworkSnapshot(const IPAddress& target) {
  NetworkSnapshot snapshot;
  const IPAddress local = WiFi.localIP();
  const IPAddress mask = WiFi.subnetMask();

  snapshot.ssid = WiFi.SSID();
  snapshot.bssid = WiFi.BSSIDstr();
  snapshot.localIp = local.toString();
  snapshot.subnetMask = mask.toString();
  snapshot.gatewayIp = WiFi.gatewayIP().toString();
  snapshot.dnsIp = WiFi.dnsIP().toString();
  snapshot.rssi = WiFi.RSSI();
  snapshot.channel = WiFi.channel();
  snapshot.targetOnLocalSubnet = TlsDiagnostics::sameSubnet(
      ipv4Value(local), ipv4Value(target), ipv4Value(mask));
  return snapshot;
}

String networkJson(const NetworkSnapshot& snapshot) {
  String json;
  json.reserve(360);
  json += "{\"ssid\":\"" + jsonEscape(snapshot.ssid) + "\"";
  json += ",\"bssid\":\"" + jsonEscape(snapshot.bssid) + "\"";
  json += ",\"localIp\":\"" + jsonEscape(snapshot.localIp) + "\"";
  json += ",\"subnetMask\":\"" + jsonEscape(snapshot.subnetMask) + "\"";
  json += ",\"gatewayIp\":\"" + jsonEscape(snapshot.gatewayIp) + "\"";
  json += ",\"dnsIp\":\"" + jsonEscape(snapshot.dnsIp) + "\"";
  json += ",\"rssi\":" + String(snapshot.rssi);
  json += ",\"channel\":" + String(snapshot.channel);
  json += ",\"targetOnLocalSubnet\":" +
          String(snapshot.targetOnLocalSubnet ? "true" : "false") + "}";
  return json;
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

struct TcpAttempt {
  uint8_t attempt = 0;
  bool connected = false;
  uint32_t connectMs = 0;
  int errorCode = 0;
  String errorText;
  String outcome;
};

TcpAttempt runTcpAttempt(const IPAddress& address, uint8_t attemptNumber) {
  TcpAttempt result;
  result.attempt = attemptNumber;

  WiFiClient client;
  errno = 0;
  const uint32_t started = millis();
  result.connected =
      client.connect(address, kTlsPort, kTcpConnectTimeoutMs) == 1;
  result.connectMs = millis() - started;
  result.errorCode = result.connected ? 0 : errno;
  result.outcome =
      result.connected
          ? "tcp-connected"
          : TlsDiagnostics::classifyTcpFailure(result.errorCode);
  if (!result.connected && result.errorCode != 0) {
    result.errorText = strerror(result.errorCode);
  }
  client.stop();
  return result;
}

String tcpAttemptJson(const TcpAttempt& result) {
  String json;
  json.reserve(220 + result.errorText.length());
  json += "{\"attempt\":" + String(result.attempt);
  json += ",\"connected\":" + String(result.connected ? "true" : "false");
  json += ",\"connectMs\":" + String(result.connectMs);
  json += ",\"errorCode\":" + String(result.errorCode);
  json += ",\"errorText\":\"" + jsonEscape(result.errorText) + "\"";
  json += ",\"outcome\":\"" + jsonEscape(result.outcome) + "\"}";
  return json;
}

String tcpDiagnosis(const TcpAttempt* attempts, uint8_t attemptsMade,
                    bool tcpReachable, bool targetOnLocalSubnet) {
  if (tcpReachable) {
    return "TCP 8883 accepted a connection; remaining TCP retries were skipped and TLS probing was allowed after a settle delay";
  }

  for (uint8_t i = 0; i < attemptsMade; ++i) {
    if (attempts[i].errorCode == ECONNREFUSED) {
      return "The target actively refused TCP 8883; the host may be reachable but the service is closed or rejecting connections";
    }
  }

  if (targetOnLocalSubnet) {
    return "TCP 8883 was unreachable on the local subnet; verify the RTK3 IP and power state, then check Wi-Fi client isolation, VLAN rules, or a device firewall";
  }

  return "TCP 8883 was unreachable across subnets; verify routing, VLAN rules, and firewall policy before interpreting TLS behavior";
}

struct TlsAttempt {
  String label;
  bool tlsConnected = false;
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

TlsAttempt runTlsAttempt(const IPAddress& address, const String& targetIp,
                         bool sendIpAsSni, bool advertiseMqttAlpn) {
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
    result.tlsConnected =
        client.connect(address, kTlsPort, targetIp.c_str(), nullptr, nullptr,
                       nullptr) == 1;
  } else {
    result.tlsConnected =
        client.connect(address, kTlsPort, kTlsConnectTimeoutMs) == 1;
  }
  result.handshakeMs = millis() - started;

  if (!result.tlsConnected) {
    char errorBuffer[192]{};
    result.errorCode = client.lastError(errorBuffer, sizeof(errorBuffer));
    result.errorText = errorBuffer;
    result.clientCertificateAssessment =
        "TLS handshake failed after an independent TCP preflight succeeded; client-certificate requirements remain unknown";
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
      "A client certificate was not required to complete this TLS handshake; application authentication remains unknown";

  const mbedtls_x509_crt* certificate = client.getPeerCertificate();
  if (certificate) {
    result.certificateSubject = x509Name(certificate->subject);
    result.certificateIssuer = x509Name(certificate->issuer);
    result.certificateSerial = serialNumberText(certificate->serial);
    result.certificateNotBefore = x509Time(certificate->valid_from);
    result.certificateNotAfter = x509Time(certificate->valid_to);

    char infoBuffer[2048]{};
    const int infoLength =
        mbedtls_x509_crt_info(infoBuffer, sizeof(infoBuffer), "", certificate);
    if (infoLength > 0) result.certificateInfo = infoBuffer;

    uint8_t fingerprint[32]{};
    if (client.getFingerprintSHA256(fingerprint)) {
      result.certificateSha256 = fingerprintText(fingerprint);
    }
  }

  client.stop();
  return result;
}

String tlsAttemptJson(const TlsAttempt& result) {
  String json;
  json.reserve(1100 + result.certificateInfo.length());
  json += "{\"label\":\"" + jsonEscape(result.label) + "\"";
  json += ",\"tlsConnected\":" +
          String(result.tlsConnected ? "true" : "false");
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

bool saveEvidence(const String& json) {
  LittleFS.remove(kEvidenceTempPath);
  File file = LittleFS.open(kEvidenceTempPath, FILE_WRITE);
  if (!file) {
    Serial.println("[tls-evidence] unable to create temporary evidence file");
    return false;
  }

  const size_t written = file.print(json);
  file.flush();
  file.close();
  if (written != json.length()) {
    LittleFS.remove(kEvidenceTempPath);
    Serial.printf("[tls-evidence] short evidence write: %u of %u bytes\n",
                  static_cast<unsigned>(written),
                  static_cast<unsigned>(json.length()));
    return false;
  }

  LittleFS.remove(kEvidencePath);
  if (!LittleFS.rename(kEvidenceTempPath, kEvidencePath)) {
    LittleFS.remove(kEvidenceTempPath);
    Serial.println("[tls-evidence] unable to atomically publish evidence file");
    return false;
  }
  return true;
}

String errorJson(const String& error, const TargetSelection& target,
                 const String& trigger) {
  String json = "{\"schemaVersion\":2,\"state\":\"error\"";
  json += ",\"error\":\"" + jsonEscape(error) + "\"";
  json += ",\"targetIp\":\"" + jsonEscape(target.ip) + "\"";
  json += ",\"targetSource\":\"" + jsonEscape(target.source) + "\"";
  json += ",\"trigger\":\"" + jsonEscape(trigger) + "\"}";
  return json;
}

void tlsProbeTask(void*) {
  const TargetSelection target = loadTargetSelection();
  String trigger;
  xSemaphoreTake(tlsMutex, portMAX_DELAY);
  trigger = tlsProbeTrigger;
  xSemaphoreGive(tlsMutex);

  IPAddress address;
  String finalJson;
  if (!address.fromString(target.ip)) {
    finalJson = errorJson("invalid RTK3 target IP", target, trigger);
  } else if (!isAllowedTarget(address)) {
    finalJson =
        errorJson("RTK3 target must be a private IPv4 address", target, trigger);
  } else {
    const uint32_t started = millis();
    const NetworkSnapshot network = captureNetworkSnapshot(address);
    TcpAttempt tcpAttempts[kMaximumTcpAttempts];
    uint8_t tcpAttemptsMade = 0;
    bool tcpReachable = false;

    do {
      tcpAttempts[tcpAttemptsMade] =
          runTcpAttempt(address, tcpAttemptsMade + 1U);
      tcpReachable = tcpAttempts[tcpAttemptsMade].connected;
      ++tcpAttemptsMade;

      if (TlsDiagnostics::shouldRetryTcp(
              tcpReachable, tcpAttemptsMade, kMaximumTcpAttempts)) {
        vTaskDelay(pdMS_TO_TICKS(kTcpRetryDelayMs));
      }
    } while (TlsDiagnostics::shouldRetryTcp(
        tcpReachable, tcpAttemptsMade, kMaximumTcpAttempts));

    TlsAttempt noSni;
    TlsAttempt ipSniMqtt;
    if (tcpReachable) {
      vTaskDelay(pdMS_TO_TICKS(kTcpSettleDelayMs));
      noSni = runTlsAttempt(address, target.ip, false, false);
      vTaskDelay(pdMS_TO_TICKS(kTlsAttemptDelayMs));
      ipSniMqtt = runTlsAttempt(address, target.ip, true, true);
    }

    finalJson.reserve(4400 + noSni.certificateInfo.length() +
                      ipSniMqtt.certificateInfo.length());
    finalJson = "{\"schemaVersion\":2,\"state\":\"completed\"";
    finalJson += ",\"targetIp\":\"" + jsonEscape(target.ip) + "\"";
    finalJson += ",\"targetSource\":\"" + jsonEscape(target.source) + "\"";
    finalJson += ",\"port\":" + String(kTlsPort);
    finalJson += ",\"trigger\":\"" + jsonEscape(trigger) + "\"";
    finalJson += ",\"durationMs\":" + String(millis() - started);
    finalJson += ",\"network\":" + networkJson(network);
    finalJson += ",\"tcpReachable\":" +
                 String(tcpReachable ? "true" : "false");
    finalJson += ",\"tcpAttemptsPlanned\":" +
                 String(kMaximumTcpAttempts);
    finalJson += ",\"tcpAttemptsMade\":" + String(tcpAttemptsMade);
    finalJson += ",\"tcpStoppedAfterSuccess\":" +
                 String(tcpReachable && tcpAttemptsMade < kMaximumTcpAttempts
                            ? "true"
                            : "false");
    finalJson += ",\"tcpAttempts\":[";
    for (uint8_t i = 0; i < tcpAttemptsMade; ++i) {
      if (i) finalJson += ',';
      finalJson += tcpAttemptJson(tcpAttempts[i]);
    }
    finalJson += "]";
    finalJson += ",\"tlsAttempted\":" +
                 String(tcpReachable ? "true" : "false");
    finalJson += ",\"diagnosis\":\"" +
                 jsonEscape(tcpDiagnosis(tcpAttempts, tcpAttemptsMade,
                                         tcpReachable,
                                         network.targetOnLocalSubnet)) +
                 "\"";
    finalJson += ",\"attempts\":[";
    if (tcpReachable) {
      finalJson += tlsAttemptJson(noSni) + "," + tlsAttemptJson(ipSniMqtt);
    }
    finalJson += "]}";
  }

  xSemaphoreTake(tlsMutex, portMAX_DELAY);
  tlsEvidence = finalJson;
  tlsProbeActive = false;
  tlsTask = nullptr;
  xSemaphoreGive(tlsMutex);

  const bool persisted = saveEvidence(finalJson);
  Serial.printf("[tls-evidence] probe complete, persisted=%s\n",
                persisted ? "true" : "false");
  Serial.println(finalJson);
  vTaskDelete(nullptr);
}

bool startTlsProbe(const char* trigger) {
  if (WiFi.status() != WL_CONNECTED || !tlsMutex) return false;

  xSemaphoreTake(tlsMutex, portMAX_DELAY);
  if (tlsProbeActive) {
    xSemaphoreGive(tlsMutex);
    return false;
  }
  tlsProbeActive = true;
  tlsProbeTrigger = trigger ? trigger : "unknown";
  tlsEvidence = "{\"schemaVersion\":2,\"state\":\"running\"}";
  xSemaphoreGive(tlsMutex);

  LittleFS.remove(kEvidencePath);
  LittleFS.remove(kEvidenceTempPath);
  const BaseType_t created =
      xTaskCreate(tlsProbeTask, "tls-evidence", 18432, nullptr, 1, &tlsTask);
  if (created != pdPASS) {
    xSemaphoreTake(tlsMutex, portMAX_DELAY);
    tlsProbeActive = false;
    tlsTask = nullptr;
    tlsEvidence =
        "{\"schemaVersion\":2,\"state\":\"error\",\"error\":\"task creation failed\"}";
    xSemaphoreGive(tlsMutex);
    return false;
  }
  return true;
}

String currentEvidence() {
  if (!tlsMutex) return "{\"schemaVersion\":2,\"state\":\"initializing\"}";

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
    tlsServer.sendHeader("Cache-Control", "no-store");
    tlsServer.send(200, "application/json",
                   WiFi.status() == WL_CONNECTED
                       ? "{\"ok\":true,\"wifiConnected\":true}"
                       : "{\"ok\":false,\"wifiConnected\":false}");
  });
  tlsServer.on("/probe", HTTP_POST, [] {
    const bool mainProbeMayBeActive =
        !LittleFS.exists(kMainProbeEvidencePath) &&
        millis() < kFallbackAutoStartAfterMs;
    if (mainProbeMayBeActive) {
      tlsServer.send(
          409, "application/json",
          "{\"error\":\"main port probe may still be active; retry after it completes\"}");
      return;
    }

    const bool started = startTlsProbe("manual-http");
    tlsServer.send(started ? 202 : 409, "application/json",
                   started ? "{\"schemaVersion\":2,\"state\":\"started\"}"
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

  if (!autoProbeStarted && tlsServerStarted) {
    const bool mainProbeFinished = LittleFS.exists(kMainProbeEvidencePath);
    const bool fallbackDelayElapsed = millis() >= kFallbackAutoStartAfterMs;
    if (mainProbeFinished || fallbackDelayElapsed) {
      const bool started =
          startTlsProbe(mainProbeFinished ? "main-probe-complete"
                                          : "fallback-delay-elapsed");
      if (started) autoProbeStarted = true;
    }
  }
}
