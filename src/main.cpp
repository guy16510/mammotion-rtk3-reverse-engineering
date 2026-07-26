#include <Arduino.h>
#include <ESPmDNS.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <WebServer.h>
#include <WiFi.h>

#include <algorithm>
#include <vector>

#include "config.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "ping/ping_sock.h"

#if __has_include("secrets.h")
#include "secrets.h"
#else
#define WIFI_SSID ""
#define WIFI_PASSWORD ""
#define RTK3_IP ""
#define RTK3_LORA_ID ""
#endif

namespace {

WebServer server(80);
Preferences preferences;
SemaphoreHandle_t probeMutex = nullptr;
TaskHandle_t probeTaskHandle = nullptr;
uint32_t restartAtMs = 0;

struct TargetConfig {
  String ip;
  String loraId;
  String ports;
};

struct PingContext {
  SemaphoreHandle_t done = nullptr;
  bool success = false;
  uint32_t rttMs = 0;
};

struct PortResult {
  uint16_t port = 0;
  bool open = false;
  uint32_t connectMs = 0;
  uint32_t receivedBytes = 0;
  bool loraMatch = false;
  String evidence;
};

struct ProbeState {
  bool active = false;
  bool completed = false;
  bool cancelled = false;
  volatile bool cancelRequested = false;
  uint16_t progress = 0;
  uint16_t total = 0;
  uint32_t startedMs = 0;
  uint32_t durationMs = 0;
  String error;
  TargetConfig target;
  bool ping = false;
  uint32_t rttMs = 0;
  bool loraObserved = false;
  std::vector<PortResult> ports;
} probe;

String jsonEscape(const String& value) {
  String out;
  out.reserve(value.length() + 16);
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

void setLed(bool on) {
  if (STATUS_LED_PIN >= 0) digitalWrite(STATUS_LED_PIN, on ? HIGH : LOW);
}

bool isPrivateAddress(const IPAddress& ip) {
  const uint8_t a = ip[0];
  const uint8_t b = ip[1];
  return a == 10 || (a == 172 && b >= 16 && b <= 31) ||
         (a == 192 && b == 168) || a == 127;
}

String defaultPortsString() {
  String value;
  for (size_t i = 0; i < DEFAULT_TARGET_PORT_COUNT; ++i) {
    if (i) value += ',';
    value += String(DEFAULT_TARGET_PORTS[i]);
  }
  return value;
}

std::vector<uint16_t> parsePorts(const String& input) {
  std::vector<uint16_t> ports;
  int start = 0;
  while (start < static_cast<int>(input.length()) &&
         ports.size() < MAX_PROBE_PORTS) {
    int comma = input.indexOf(',', start);
    if (comma < 0) comma = input.length();
    const long value = input.substring(start, comma).toInt();
    if (value >= 1 && value <= 65535 &&
        std::find(ports.begin(), ports.end(), static_cast<uint16_t>(value)) ==
            ports.end()) {
      ports.push_back(static_cast<uint16_t>(value));
    }
    start = comma + 1;
  }
  return ports;
}

String normalizePorts(const std::vector<uint16_t>& ports) {
  String value;
  for (size_t i = 0; i < ports.size(); ++i) {
    if (i) value += ',';
    value += String(ports[i]);
  }
  return value;
}

bool validLoraId(const String& value) {
  if (value.isEmpty() || value.length() > 64) return false;
  for (size_t i = 0; i < value.length(); ++i) {
    const char c = value[i];
    if (!(isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' ||
          c == ':' || c == '.')) {
      return false;
    }
  }
  return true;
}

TargetConfig loadTargetConfig() {
  TargetConfig config;
  config.ip = RTK3_IP;
  config.loraId = RTK3_LORA_ID;
  config.ports = defaultPortsString();

  preferences.begin("rtk3-probe", true);
  const String savedIp = preferences.getString("target_ip", "");
  const String savedLoraId = preferences.getString("lora_id", "");
  const String savedPorts = preferences.getString("ports", "");
  preferences.end();

  if (!savedIp.isEmpty()) config.ip = savedIp;
  if (!savedLoraId.isEmpty()) config.loraId = savedLoraId;
  if (!savedPorts.isEmpty()) config.ports = savedPorts;
  return config;
}

bool validateTargetConfig(const TargetConfig& config, IPAddress& address,
                          std::vector<uint16_t>& ports, String& error) {
  if (!address.fromString(config.ip) || !isPrivateAddress(address)) {
    error = "RTK3 IP must be a private IPv4 address";
    return false;
  }
  if (!validLoraId(config.loraId)) {
    error = "LoRa ID must be 1 to 64 letters, numbers, dots, colons, dashes, or underscores";
    return false;
  }
  ports = parsePorts(config.ports);
  if (ports.empty()) {
    error = "at least one valid TCP port is required";
    return false;
  }
  return true;
}

void onPingSuccess(esp_ping_handle_t handle, void* args) {
  auto* context = static_cast<PingContext*>(args);
  context->success = true;
  esp_ping_get_profile(handle, ESP_PING_PROF_TIMEGAP, &context->rttMs,
                       sizeof(context->rttMs));
}

void onPingTimeout(esp_ping_handle_t, void*) {}

void onPingEnd(esp_ping_handle_t, void* args) {
  auto* context = static_cast<PingContext*>(args);
  xSemaphoreGive(context->done);
}

bool pingOnce(const IPAddress& target, uint32_t timeoutMs, uint32_t& rttMs) {
  PingContext context;
  context.done = xSemaphoreCreateBinary();
  if (!context.done) return false;

  ip_addr_t address;
  const String targetText = target.toString();
  if (!ipaddr_aton(targetText.c_str(), &address)) {
    vSemaphoreDelete(context.done);
    return false;
  }

  esp_ping_config_t config = ESP_PING_DEFAULT_CONFIG();
  config.target_addr = address;
  config.count = 1;
  config.interval_ms = 10;
  config.timeout_ms = timeoutMs;
  config.data_size = 16;

  esp_ping_callbacks_t callbacks{};
  callbacks.cb_args = &context;
  callbacks.on_ping_success = onPingSuccess;
  callbacks.on_ping_timeout = onPingTimeout;
  callbacks.on_ping_end = onPingEnd;

  esp_ping_handle_t handle = nullptr;
  if (esp_ping_new_session(&config, &callbacks, &handle) != ESP_OK) {
    vSemaphoreDelete(context.done);
    return false;
  }

  const bool started = esp_ping_start(handle) == ESP_OK;
  if (started) xSemaphoreTake(context.done, pdMS_TO_TICKS(timeoutMs + 500U));
  esp_ping_stop(handle);
  esp_ping_delete_session(handle);
  vSemaphoreDelete(context.done);
  rttMs = context.rttMs;
  return started && context.success;
}

bool isPlainHttpPort(uint16_t port) {
  return port == 80 || port == 5000 || port == 8000 || port == 8080;
}

String evidenceText(const std::vector<uint8_t>& bytes) {
  String out;
  out.reserve(bytes.size() * 2U);
  char encoded[5];
  for (const uint8_t byte : bytes) {
    if ((byte >= 32 && byte <= 126) || byte == '\r' || byte == '\n' ||
        byte == '\t') {
      out += static_cast<char>(byte);
    } else {
      snprintf(encoded, sizeof(encoded), "\\x%02X", byte);
      out += encoded;
    }
  }
  return out;
}

bool containsCaseInsensitive(const String& haystack, const String& needle) {
  if (needle.isEmpty()) return false;
  String lowerHaystack = haystack;
  String lowerNeedle = needle;
  lowerHaystack.toLowerCase();
  lowerNeedle.toLowerCase();
  return lowerHaystack.indexOf(lowerNeedle) >= 0;
}

PortResult probePort(const IPAddress& target, const String& loraId,
                     uint16_t port) {
  PortResult result;
  result.port = port;

  WiFiClient client;
  const uint32_t started = millis();
  result.open = client.connect(target, port, TARGET_TCP_TIMEOUT_MS);
  result.connectMs = millis() - started;
  if (!result.open) {
    client.stop();
    return result;
  }

  if (isPlainHttpPort(port)) {
    client.print("GET / HTTP/1.1\r\nHost: ");
    client.print(target.toString());
    client.print("\r\nUser-Agent: RTK3-ESP32-Probe/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n");
  }

  std::vector<uint8_t> received;
  received.reserve(MAX_BANNER_BYTES);
  const uint32_t deadline = millis() + TARGET_BANNER_WAIT_MS;
  while (static_cast<int32_t>(deadline - millis()) > 0 &&
         received.size() < MAX_BANNER_BYTES) {
    while (client.available() > 0 && received.size() < MAX_BANNER_BYTES) {
      const int value = client.read();
      if (value < 0) break;
      received.push_back(static_cast<uint8_t>(value));
    }
    if (!client.connected() && client.available() == 0) break;
    vTaskDelay(pdMS_TO_TICKS(10));
  }
  client.stop();

  result.receivedBytes = received.size();
  result.evidence = evidenceText(received);
  result.loraMatch = containsCaseInsensitive(result.evidence, loraId);
  return result;
}

String portResultJson(const PortResult& result) {
  String json;
  json.reserve(220 + result.evidence.length());
  json += "{\"port\":" + String(result.port);
  json += ",\"open\":" + String(result.open ? "true" : "false");
  json += ",\"connectMs\":" + String(result.connectMs);
  json += ",\"receivedBytes\":" + String(result.receivedBytes);
  json += ",\"loraMatch\":" + String(result.loraMatch ? "true" : "false");
  json += ",\"evidence\":\"" + jsonEscape(result.evidence) + "\"}";
  return json;
}

String probeResultsJsonUnlocked() {
  String json;
  json.reserve(1024 + probe.ports.size() * 320);
  json += "{\"active\":" + String(probe.active ? "true" : "false");
  json += ",\"completed\":" + String(probe.completed ? "true" : "false");
  json += ",\"cancelled\":" + String(probe.cancelled ? "true" : "false");
  json += ",\"targetIp\":\"" + jsonEscape(probe.target.ip) + "\"";
  json += ",\"loraId\":\"" + jsonEscape(probe.target.loraId) + "\"";
  json += ",\"ping\":" + String(probe.ping ? "true" : "false");
  json += ",\"rttMs\":" + String(probe.rttMs);
  json += ",\"loraObserved\":" + String(probe.loraObserved ? "true" : "false");
  json += ",\"durationMs\":" + String(probe.durationMs);
  json += ",\"error\":\"" + jsonEscape(probe.error) + "\"";
  json += ",\"ports\":[";
  for (size_t i = 0; i < probe.ports.size(); ++i) {
    if (i) json += ',';
    json += portResultJson(probe.ports[i]);
  }
  json += "]}";
  return json;
}

String probeResultsJson() {
  if (!probeMutex) return "{\"error\":\"probe not initialized\"}";
  xSemaphoreTake(probeMutex, portMAX_DELAY);
  String json = probeResultsJsonUnlocked();
  xSemaphoreGive(probeMutex);
  return json;
}

String probeStatusJson() {
  if (!probeMutex) return "{\"error\":\"probe not initialized\"}";
  xSemaphoreTake(probeMutex, portMAX_DELAY);
  String json = "{\"active\":" + String(probe.active ? "true" : "false");
  json += ",\"completed\":" + String(probe.completed ? "true" : "false");
  json += ",\"cancelled\":" + String(probe.cancelled ? "true" : "false");
  json += ",\"progress\":" + String(probe.progress);
  json += ",\"total\":" + String(probe.total);
  json += ",\"targetIp\":\"" + jsonEscape(probe.target.ip) + "\"";
  json += ",\"error\":\"" + jsonEscape(probe.error) + "\"}";
  xSemaphoreGive(probeMutex);
  return json;
}

void persistProbeResults() {
  File file = LittleFS.open("/rtk3-probe.json", FILE_WRITE);
  if (!file) return;
  file.print(probeResultsJson());
  file.close();
}

void targetProbeTask(void*) {
  TargetConfig target;
  xSemaphoreTake(probeMutex, portMAX_DELAY);
  target = probe.target;
  xSemaphoreGive(probeMutex);

  IPAddress address;
  std::vector<uint16_t> ports;
  String validationError;
  if (!validateTargetConfig(target, address, ports, validationError)) {
    xSemaphoreTake(probeMutex, portMAX_DELAY);
    probe.active = false;
    probe.error = validationError;
    xSemaphoreGive(probeMutex);
    setLed(false);
    probeTaskHandle = nullptr;
    vTaskDelete(nullptr);
    return;
  }

  uint32_t rttMs = 0;
  const bool ping = pingOnce(address, TARGET_PING_TIMEOUT_MS, rttMs);
  xSemaphoreTake(probeMutex, portMAX_DELAY);
  probe.ping = ping;
  probe.rttMs = rttMs;
  xSemaphoreGive(probeMutex);

  for (const uint16_t port : ports) {
    xSemaphoreTake(probeMutex, portMAX_DELAY);
    const bool cancel = probe.cancelRequested;
    xSemaphoreGive(probeMutex);
    if (cancel) break;

    PortResult result = probePort(address, target.loraId, port);
    xSemaphoreTake(probeMutex, portMAX_DELAY);
    if (result.loraMatch) probe.loraObserved = true;
    probe.ports.push_back(result);
    ++probe.progress;
    xSemaphoreGive(probeMutex);
    vTaskDelay(1);
  }

  xSemaphoreTake(probeMutex, portMAX_DELAY);
  probe.cancelled = probe.cancelRequested;
  probe.active = false;
  probe.completed = !probe.cancelled;
  probe.durationMs = millis() - probe.startedMs;
  xSemaphoreGive(probeMutex);

  persistProbeResults();
  setLed(false);
  probeTaskHandle = nullptr;
  vTaskDelete(nullptr);
}

bool startTargetProbe() {
  if (WiFi.status() != WL_CONNECTED || !probeMutex) return false;

  const TargetConfig target = loadTargetConfig();
  IPAddress address;
  std::vector<uint16_t> ports;
  String validationError;
  if (!validateTargetConfig(target, address, ports, validationError)) {
    xSemaphoreTake(probeMutex, portMAX_DELAY);
    probe.error = validationError;
    xSemaphoreGive(probeMutex);
    return false;
  }

  xSemaphoreTake(probeMutex, portMAX_DELAY);
  if (probe.active) {
    xSemaphoreGive(probeMutex);
    return false;
  }
  probe = ProbeState{};
  probe.active = true;
  probe.target = target;
  probe.total = ports.size();
  probe.startedMs = millis();
  xSemaphoreGive(probeMutex);

  LittleFS.remove("/rtk3-probe.json");
  setLed(true);
  const BaseType_t created =
      xTaskCreate(targetProbeTask, "rtk3-probe", 10240, nullptr, 1,
                  &probeTaskHandle);
  if (created != pdPASS) {
    xSemaphoreTake(probeMutex, portMAX_DELAY);
    probe.active = false;
    probe.error = "failed to create target probe task";
    xSemaphoreGive(probeMutex);
    setLed(false);
    return false;
  }
  return true;
}

void stopTargetProbe() {
  if (!probeMutex) return;
  xSemaphoreTake(probeMutex, portMAX_DELAY);
  probe.cancelRequested = true;
  xSemaphoreGive(probeMutex);
}

String targetConfigJson() {
  const TargetConfig target = loadTargetConfig();
  String json = "{\"targetIp\":\"" + jsonEscape(target.ip) + "\"";
  json += ",\"loraId\":\"" + jsonEscape(target.loraId) + "\"";
  json += ",\"ports\":\"" + jsonEscape(target.ports) + "\"}";
  return json;
}

String statusJson() {
  const TargetConfig target = loadTargetConfig();
  IPAddress address;
  std::vector<uint16_t> ports;
  String error;
  const bool configured = validateTargetConfig(target, address, ports, error);

  String json = "{\"ok\":true";
  json += ",\"hostname\":\"" + String(DEVICE_HOSTNAME) + "\"";
  json += ",\"stationConnected\":" +
          String(WiFi.status() == WL_CONNECTED ? "true" : "false");
  json += ",\"stationSsid\":\"" + jsonEscape(WiFi.SSID()) + "\"";
  json += ",\"stationIp\":\"" + WiFi.localIP().toString() + "\"";
  json += ",\"apIp\":\"" + WiFi.softAPIP().toString() + "\"";
  json += ",\"targetConfigured\":" + String(configured ? "true" : "false");
  json += ",\"targetIp\":\"" + jsonEscape(target.ip) + "\"";
  json += ",\"loraId\":\"" + jsonEscape(target.loraId) + "\"";
  json += ",\"freeHeap\":" + String(ESP.getFreeHeap());
  json += ",\"probe\":" + probeStatusJson();
  json += '}';
  return json;
}

void sendJson(int status, const String& body) {
  server.sendHeader("Cache-Control", "no-store");
  server.send(status, "application/json", body);
}

void handleTargetConfigure() {
  if (probe.active) {
    sendJson(409, "{\"error\":\"stop the active probe before changing the target\"}");
    return;
  }

  TargetConfig target;
  target.ip = server.arg("ip");
  target.loraId = server.arg("loraId");
  target.ports = server.arg("ports");
  target.ip.trim();
  target.loraId.trim();
  target.ports.trim();

  IPAddress address;
  std::vector<uint16_t> ports;
  String error;
  if (!validateTargetConfig(target, address, ports, error)) {
    sendJson(400, "{\"error\":\"" + jsonEscape(error) + "\"}");
    return;
  }

  target.ports = normalizePorts(ports);
  preferences.begin("rtk3-probe", false);
  preferences.putString("target_ip", target.ip);
  preferences.putString("lora_id", target.loraId);
  preferences.putString("ports", target.ports);
  preferences.end();
  sendJson(200, targetConfigJson());
}

void handleTargetClear() {
  if (probe.active) {
    sendJson(409, "{\"error\":\"stop the active probe before clearing the target\"}");
    return;
  }
  preferences.begin("rtk3-probe", false);
  preferences.remove("target_ip");
  preferences.remove("lora_id");
  preferences.remove("ports");
  preferences.end();
  LittleFS.remove("/rtk3-probe.json");
  sendJson(200, targetConfigJson());
}

void handleWifiScan() {
  const int count = WiFi.scanNetworks(false, true, false, 250);
  String json = "[";
  for (int i = 0; i < count; ++i) {
    if (i) json += ',';
    json += "{\"ssid\":\"" + jsonEscape(WiFi.SSID(i)) + "\"";
    json += ",\"bssid\":\"" + WiFi.BSSIDstr(i) + "\"";
    json += ",\"rssi\":" + String(WiFi.RSSI(i));
    json += ",\"channel\":" + String(WiFi.channel(i)) + '}';
  }
  json += ']';
  WiFi.scanDelete();
  sendJson(200, json);
}

void handleWifiConfigure() {
  const String ssid = server.arg("ssid");
  const String password = server.arg("password");
  if (ssid.isEmpty() || ssid.length() > 32 || password.length() > 64) {
    sendJson(400, "{\"error\":\"invalid Wi-Fi credentials\"}");
    return;
  }
  preferences.begin("rtk3-probe", false);
  preferences.putString("ssid", ssid);
  preferences.putString("password", password);
  preferences.end();
  restartAtMs = millis() + 1200U;
  sendJson(202, "{\"ok\":true,\"restarting\":true}");
}

void handleWifiClear() {
  preferences.begin("rtk3-probe", false);
  preferences.remove("ssid");
  preferences.remove("password");
  preferences.end();
  restartAtMs = millis() + 1200U;
  sendJson(202, "{\"ok\":true,\"restarting\":true}");
}

const char INDEX_HTML[] PROGMEM = R"HTML(
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RTK3 Direct Probe</title><style>
body{font-family:system-ui;margin:2rem;max-width:1000px;background:#111;color:#eee}button,input{font:inherit;padding:.65rem;margin:.25rem}button{cursor:pointer}input{min-width:220px}pre{background:#222;padding:1rem;overflow:auto;white-space:pre-wrap}.row{display:flex;gap:.5rem;flex-wrap:wrap}.card{border:1px solid #444;padding:1rem;margin:1rem 0;border-radius:.5rem}.primary{font-weight:700;padding:.9rem 1.2rem}code{color:#9df}
</style></head><body><h1>RTK3 ESP32-S3 Direct Probe</h1>
<div class="card"><h2>Known RTK3</h2><p>Save the RTK3 IP and LoRa ID once. The ESP32 probes only that device.</p><form id="target"><div><input name="ip" id="targetIp" placeholder="RTK3 IP, for example 192.168.1.123" required></div><div><input name="loraId" id="loraId" placeholder="LoRa ID" required></div><div><input name="ports" id="targetPorts" placeholder="TCP ports" required></div><button>Save target</button></form><div class="row"><button class="primary" onclick="post('/api/probe/start')">Probe RTK3 now</button><button onclick="post('/api/probe/stop')">Stop</button><button onclick="getOut('/api/probe/results')">Show results</button><button onclick="post('/api/config/clear')">Clear target</button></div></div>
<div class="card"><h2>Connect this ESP32 to Wi-Fi</h2><form id="wifi"><input name="ssid" placeholder="Wi-Fi SSID" required><input name="password" type="password" placeholder="Wi-Fi password"><button>Save and restart</button></form><button onclick="post('/api/wifi/clear')">Clear saved Wi-Fi</button><button onclick="post('/api/wifi/scan')">List nearby Wi-Fi</button></div>
<div class="card"><h2>What the probe checks</h2><p>ICMP reachability, direct TCP connectivity, connection timing, plaintext service banners, an HTTP root request on common web ports, and whether any returned evidence contains the configured LoRa ID.</p></div>
<h2>Status</h2><pre id="status">Loading...</pre><h2>Output</h2><pre id="out">No output yet.</pre><script>
const statusEl=document.getElementById('status'),out=document.getElementById('out');
async function parse(r){const t=await r.text();try{return JSON.stringify(JSON.parse(t),null,2)}catch{return t}}
async function getOut(u){out.textContent=await parse(await fetch(u))}
async function post(u){out.textContent=await parse(await fetch(u,{method:'POST'}))}
async function loadConfig(){const c=await (await fetch('/api/config')).json();targetIp.value=c.targetIp||'';loraId.value=c.loraId||'';targetPorts.value=c.ports||''}
document.getElementById('target').addEventListener('submit',async e=>{e.preventDefault();out.textContent=await parse(await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(new FormData(e.target))}));loadConfig()});
document.getElementById('wifi').addEventListener('submit',async e=>{e.preventDefault();out.textContent=await parse(await fetch('/api/wifi/configure',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(new FormData(e.target))}))});
setInterval(async()=>{statusEl.textContent=await parse(await fetch('/api/status'))},2000);loadConfig();fetch('/api/status').then(parse).then(t=>statusEl.textContent=t);
</script></body></html>)HTML";

void configureRoutes() {
  server.on("/", HTTP_GET,
            [] { server.send_P(200, "text/html", INDEX_HTML); });
  server.on("/healthz", HTTP_GET,
            [] { sendJson(200, "{\"ok\":true}"); });
  server.on("/api/status", HTTP_GET,
            [] { sendJson(200, statusJson()); });
  server.on("/api/config", HTTP_GET,
            [] { sendJson(200, targetConfigJson()); });
  server.on("/api/config", HTTP_POST, handleTargetConfigure);
  server.on("/api/config/clear", HTTP_POST, handleTargetClear);
  server.on("/api/probe/start", HTTP_POST, [] {
    if (!startTargetProbe()) {
      sendJson(409, "{\"error\":\"probe already active, Wi-Fi is disconnected, or target configuration is invalid\"}");
      return;
    }
    sendJson(202, probeStatusJson());
  });
  server.on("/api/probe/stop", HTTP_POST, [] {
    stopTargetProbe();
    sendJson(202, probeStatusJson());
  });
  server.on("/api/probe/status", HTTP_GET,
            [] { sendJson(200, probeStatusJson()); });
  server.on("/api/probe/results", HTTP_GET, [] {
    if (LittleFS.exists("/rtk3-probe.json") && !probe.active) {
      File file = LittleFS.open("/rtk3-probe.json", FILE_READ);
      server.streamFile(file, "application/json");
      file.close();
      return;
    }
    sendJson(200, probeResultsJson());
  });
  server.on("/api/wifi/scan", HTTP_POST, handleWifiScan);
  server.on("/api/wifi/configure", HTTP_POST, handleWifiConfigure);
  server.on("/api/wifi/clear", HTTP_POST, handleWifiClear);
  server.onNotFound([] { sendJson(404, "{\"error\":\"not found\"}"); });
}

void connectWifi() {
  WiFi.mode(WIFI_AP_STA);
  WiFi.setHostname(DEVICE_HOSTNAME);
  WiFi.softAP(AP_SSID, AP_PASSWORD);
  Serial.printf("[wifi] fallback AP %s at %s\n", AP_SSID,
                WiFi.softAPIP().toString().c_str());

  String ssid = WIFI_SSID;
  String password = WIFI_PASSWORD;
  preferences.begin("rtk3-probe", true);
  const String savedSsid = preferences.getString("ssid", "");
  const String savedPassword = preferences.getString("password", "");
  preferences.end();
  if (!savedSsid.isEmpty()) {
    ssid = savedSsid;
    password = savedPassword;
  }
  if (ssid.isEmpty()) return;

  Serial.printf("[wifi] connecting to %s\n", ssid.c_str());
  WiFi.begin(ssid.c_str(), password.c_str());
  const uint32_t deadline = millis() + 20000U;
  while (WiFi.status() != WL_CONNECTED &&
         static_cast<int32_t>(deadline - millis()) > 0) {
    delay(250);
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("[wifi] station connected at %s\n",
                  WiFi.localIP().toString().c_str());
  } else {
    Serial.println("[wifi] station connection failed, configure through fallback AP");
  }
}

}  // namespace

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\nRTK3 ESP32-S3 direct target probe starting");

  if (STATUS_LED_PIN >= 0) {
    pinMode(STATUS_LED_PIN, OUTPUT);
    setLed(false);
  }
  if (!LittleFS.begin(true)) Serial.println("[fatal] LittleFS mount failed");
  probeMutex = xSemaphoreCreateMutex();
  if (!probeMutex) Serial.println("[fatal] probe mutex allocation failed");

  connectWifi();
  configureRoutes();
  server.begin();
  Serial.println("[http] server ready");

  if (WiFi.status() == WL_CONNECTED && MDNS.begin(DEVICE_HOSTNAME)) {
    MDNS.addService("http", "tcp", 80);
    Serial.printf("[mdns] http://%s.local/\n", DEVICE_HOSTNAME);
  }

  if (AUTO_TARGET_PROBE_ON_BOOT && WiFi.status() == WL_CONNECTED) {
    delay(500);
    startTargetProbe();
  }
}

void loop() {
  server.handleClient();
  if (restartAtMs && static_cast<int32_t>(millis() - restartAtMs) >= 0) {
    ESP.restart();
  }
  delay(1);
}
