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
#endif

namespace {

WebServer server(80);
Preferences preferences;
SemaphoreHandle_t scanMutex = nullptr;
TaskHandle_t scanTaskHandle = nullptr;
uint32_t restartAtMs = 0;

struct HostResult {
  IPAddress ip;
  bool ping = false;
  uint32_t rttMs = 0;
  bool gateway = false;
  bool newSinceLastScan = false;
  int score = 0;
  String classification;
  std::vector<uint16_t> openPorts;
};

struct LanScanState {
  bool active = false;
  bool completed = false;
  bool cancelled = false;
  bool cappedToLocal24 = false;
  volatile bool cancelRequested = false;
  uint16_t progress = 0;
  uint16_t total = 0;
  IPAddress currentIp;
  IPAddress localIp;
  IPAddress gateway;
  IPAddress subnetMask;
  String error;
  std::vector<HostResult> hosts;
  std::vector<IPAddress> previousIps;
  std::vector<IPAddress> missingSinceLastScan;
} lanScan;

struct PingContext {
  SemaphoreHandle_t done = nullptr;
  bool success = false;
  uint32_t rttMs = 0;
};

String jsonEscape(const String& value) {
  String out;
  out.reserve(value.length() + 8);
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

uint32_t ipToUint(const IPAddress& ip) {
  return (static_cast<uint32_t>(ip[0]) << 24U) |
         (static_cast<uint32_t>(ip[1]) << 16U) |
         (static_cast<uint32_t>(ip[2]) << 8U) |
         static_cast<uint32_t>(ip[3]);
}

IPAddress uintToIp(uint32_t value) {
  return IPAddress((value >> 24U) & 0xffU, (value >> 16U) & 0xffU,
                   (value >> 8U) & 0xffU, value & 0xffU);
}

bool sameIp(const IPAddress& a, const IPAddress& b) {
  return ipToUint(a) == ipToUint(b);
}

bool isPrivateAddress(const IPAddress& ip) {
  const uint8_t a = ip[0];
  const uint8_t b = ip[1];
  return a == 10 || (a == 172 && b >= 16 && b <= 31) ||
         (a == 192 && b == 168) || a == 127;
}

bool containsIp(const std::vector<IPAddress>& values, const IPAddress& value) {
  return std::any_of(values.begin(), values.end(), [&](const IPAddress& item) {
    return sameIp(item, value);
  });
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

  bool started = esp_ping_start(handle) == ESP_OK;
  if (started) {
    xSemaphoreTake(context.done, pdMS_TO_TICKS(timeoutMs + 500U));
  }
  esp_ping_stop(handle);
  esp_ping_delete_session(handle);
  vSemaphoreDelete(context.done);
  rttMs = context.rttMs;
  return started && context.success;
}

bool portOpen(const IPAddress& target, uint16_t port, uint32_t timeoutMs) {
  WiFiClient client;
  const bool open = client.connect(target, port, timeoutMs);
  client.stop();
  return open;
}

int scoreHost(const HostResult& host) {
  if (host.gateway) return -100;
  int score = host.ping ? 5 : 0;
  for (const uint16_t port : host.openPorts) {
    if (port >= 50001 && port <= 50003) score += 70;
    else if (port == 1883 || port == 8883) score += 35;
    else if (port == 80 || port == 443 || port == 8080 || port == 8443) score += 12;
    else score += 5;
  }
  return score;
}

String classifyHost(const HostResult& host) {
  if (host.gateway) return "router";
  if (host.score >= 70) return "strong-mammotion-candidate";
  if (host.score >= 30) return "possible-iot-candidate";
  if (!host.openPorts.empty()) return "network-service";
  return "reachable-device";
}

String portsJson(const std::vector<uint16_t>& ports) {
  String json = "[";
  for (size_t i = 0; i < ports.size(); ++i) {
    if (i) json += ',';
    json += String(ports[i]);
  }
  json += ']';
  return json;
}

String hostJson(const HostResult& host) {
  String json;
  json.reserve(260);
  json += "{\"ip\":\"" + host.ip.toString() + "\"";
  json += ",\"ping\":" + String(host.ping ? "true" : "false");
  json += ",\"rttMs\":" + String(host.rttMs);
  json += ",\"gateway\":" + String(host.gateway ? "true" : "false");
  json += ",\"newSinceLastScan\":" + String(host.newSinceLastScan ? "true" : "false");
  json += ",\"score\":" + String(host.score);
  json += ",\"classification\":\"" + jsonEscape(host.classification) + "\"";
  json += ",\"openPorts\":" + portsJson(host.openPorts);
  json += '}';
  return json;
}

String lanResultsJsonUnlocked() {
  String json;
  json.reserve(1024 + lanScan.hosts.size() * 220);
  json += "{\"completed\":" + String(lanScan.completed ? "true" : "false");
  json += ",\"cancelled\":" + String(lanScan.cancelled ? "true" : "false");
  json += ",\"localIp\":\"" + lanScan.localIp.toString() + "\"";
  json += ",\"gateway\":\"" + lanScan.gateway.toString() + "\"";
  json += ",\"subnetMask\":\"" + lanScan.subnetMask.toString() + "\"";
  json += ",\"cappedToLocal24\":" + String(lanScan.cappedToLocal24 ? "true" : "false");
  json += ",\"hosts\":[";
  for (size_t i = 0; i < lanScan.hosts.size(); ++i) {
    if (i) json += ',';
    json += hostJson(lanScan.hosts[i]);
  }
  json += "],\"missingSinceLastScan\":[";
  for (size_t i = 0; i < lanScan.missingSinceLastScan.size(); ++i) {
    if (i) json += ',';
    json += "\"" + lanScan.missingSinceLastScan[i].toString() + "\"";
  }
  json += "]}";
  return json;
}

String lanResultsJson() {
  if (!scanMutex) return "{\"error\":\"scanner not initialized\"}";
  xSemaphoreTake(scanMutex, portMAX_DELAY);
  String json = lanResultsJsonUnlocked();
  xSemaphoreGive(scanMutex);
  return json;
}

String lanStatusJson() {
  if (!scanMutex) return "{\"error\":\"scanner not initialized\"}";
  xSemaphoreTake(scanMutex, portMAX_DELAY);
  String json = "{\"active\":" + String(lanScan.active ? "true" : "false");
  json += ",\"completed\":" + String(lanScan.completed ? "true" : "false");
  json += ",\"cancelled\":" + String(lanScan.cancelled ? "true" : "false");
  json += ",\"progress\":" + String(lanScan.progress);
  json += ",\"total\":" + String(lanScan.total);
  json += ",\"currentIp\":\"" + lanScan.currentIp.toString() + "\"";
  json += ",\"found\":" + String(lanScan.hosts.size());
  json += ",\"error\":\"" + jsonEscape(lanScan.error) + "\"}";
  xSemaphoreGive(scanMutex);
  return json;
}

void persistLanResults() {
  const String json = lanResultsJson();
  File file = LittleFS.open("/lan-scan.json", FILE_WRITE);
  if (!file) return;
  file.print(json);
  file.close();
}

void lanScanTask(void*) {
  uint32_t localValue;
  uint32_t networkValue;
  uint32_t broadcastValue;
  std::vector<IPAddress> previous;

  xSemaphoreTake(scanMutex, portMAX_DELAY);
  localValue = ipToUint(lanScan.localIp);
  const uint32_t maskValue = ipToUint(lanScan.subnetMask);
  networkValue = localValue & maskValue;
  broadcastValue = networkValue | ~maskValue;
  uint32_t hostCount = broadcastValue > networkValue + 1U
                           ? broadcastValue - networkValue - 1U
                           : 0U;
  if (hostCount == 0U || hostCount > MAX_LAN_SCAN_HOSTS) {
    networkValue = localValue & 0xffffff00U;
    broadcastValue = networkValue | 0x000000ffU;
    lanScan.cappedToLocal24 = true;
  }
  previous = lanScan.previousIps;
  lanScan.total = static_cast<uint16_t>(broadcastValue - networkValue - 2U);
  xSemaphoreGive(scanMutex);

  for (uint32_t value = networkValue + 1U; value < broadcastValue; ++value) {
    if (value == localValue) continue;

    xSemaphoreTake(scanMutex, portMAX_DELAY);
    const bool cancel = lanScan.cancelRequested;
    lanScan.currentIp = uintToIp(value);
    xSemaphoreGive(scanMutex);
    if (cancel) break;

    const IPAddress target = uintToIp(value);
    uint32_t rttMs = 0;
    HostResult result;
    result.ip = target;
    result.gateway = sameIp(target, WiFi.gatewayIP());
    result.ping = pingOnce(target, LAN_PING_TIMEOUT_MS, rttMs);
    result.rttMs = rttMs;

    const uint16_t* ports = result.ping ? LAN_CANDIDATE_PORTS : LAN_FALLBACK_PORTS;
    const size_t portCount = result.ping ? LAN_CANDIDATE_PORT_COUNT : LAN_FALLBACK_PORT_COUNT;
    for (size_t i = 0; i < portCount; ++i) {
      if (portOpen(target, ports[i], LAN_TCP_TIMEOUT_MS)) result.openPorts.push_back(ports[i]);
      if (lanScan.cancelRequested) break;
    }

    if (result.ping || !result.openPorts.empty()) {
      result.newSinceLastScan = !previous.empty() && !containsIp(previous, target);
      result.score = scoreHost(result);
      result.classification = classifyHost(result);
      xSemaphoreTake(scanMutex, portMAX_DELAY);
      lanScan.hosts.push_back(result);
      xSemaphoreGive(scanMutex);
    }

    xSemaphoreTake(scanMutex, portMAX_DELAY);
    ++lanScan.progress;
    xSemaphoreGive(scanMutex);
    vTaskDelay(1);
  }

  xSemaphoreTake(scanMutex, portMAX_DELAY);
  lanScan.cancelled = lanScan.cancelRequested;
  lanScan.active = false;
  lanScan.completed = !lanScan.cancelled;
  lanScan.currentIp = IPAddress();
  std::sort(lanScan.hosts.begin(), lanScan.hosts.end(), [](const HostResult& a, const HostResult& b) {
    if (a.score != b.score) return a.score > b.score;
    return ipToUint(a.ip) < ipToUint(b.ip);
  });
  lanScan.missingSinceLastScan.clear();
  for (const IPAddress& previousIp : previous) {
    const bool stillPresent = std::any_of(lanScan.hosts.begin(), lanScan.hosts.end(),
                                         [&](const HostResult& host) {
                                           return sameIp(host.ip, previousIp);
                                         });
    if (!stillPresent) lanScan.missingSinceLastScan.push_back(previousIp);
  }
  xSemaphoreGive(scanMutex);

  persistLanResults();
  setLed(false);
  scanTaskHandle = nullptr;
  vTaskDelete(nullptr);
}

bool startLanScan() {
  if (WiFi.status() != WL_CONNECTED || !scanMutex) return false;

  xSemaphoreTake(scanMutex, portMAX_DELAY);
  if (lanScan.active) {
    xSemaphoreGive(scanMutex);
    return false;
  }
  lanScan.previousIps.clear();
  for (const HostResult& host : lanScan.hosts) lanScan.previousIps.push_back(host.ip);
  lanScan.hosts.clear();
  lanScan.missingSinceLastScan.clear();
  lanScan.active = true;
  lanScan.completed = false;
  lanScan.cancelled = false;
  lanScan.cappedToLocal24 = false;
  lanScan.cancelRequested = false;
  lanScan.progress = 0;
  lanScan.total = 0;
  lanScan.currentIp = IPAddress();
  lanScan.localIp = WiFi.localIP();
  lanScan.gateway = WiFi.gatewayIP();
  lanScan.subnetMask = WiFi.subnetMask();
  lanScan.error = "";
  xSemaphoreGive(scanMutex);

  setLed(true);
  const BaseType_t created = xTaskCreate(lanScanTask, "lan-scan", 8192, nullptr, 1,
                                         &scanTaskHandle);
  if (created != pdPASS) {
    xSemaphoreTake(scanMutex, portMAX_DELAY);
    lanScan.active = false;
    lanScan.error = "failed to create scan task";
    xSemaphoreGive(scanMutex);
    setLed(false);
    return false;
  }
  return true;
}

void stopLanScan() {
  if (!scanMutex) return;
  xSemaphoreTake(scanMutex, portMAX_DELAY);
  lanScan.cancelRequested = true;
  xSemaphoreGive(scanMutex);
}

String statusJson() {
  String json = "{\"ok\":true";
  json += ",\"hostname\":\"" + String(DEVICE_HOSTNAME) + "\"";
  json += ",\"stationConnected\":" + String(WiFi.status() == WL_CONNECTED ? "true" : "false");
  json += ",\"stationSsid\":\"" + jsonEscape(WiFi.SSID()) + "\"";
  json += ",\"stationIp\":\"" + WiFi.localIP().toString() + "\"";
  json += ",\"gateway\":\"" + WiFi.gatewayIP().toString() + "\"";
  json += ",\"subnetMask\":\"" + WiFi.subnetMask().toString() + "\"";
  json += ",\"apIp\":\"" + WiFi.softAPIP().toString() + "\"";
  json += ",\"freeHeap\":" + String(ESP.getFreeHeap());
  json += ",\"scan\":" + lanStatusJson();
  json += '}';
  return json;
}

void sendJson(int status, const String& body) {
  server.sendHeader("Cache-Control", "no-store");
  server.send(status, "application/json", body);
}

std::vector<uint16_t> parsePorts(const String& input) {
  std::vector<uint16_t> ports;
  int start = 0;
  while (start < static_cast<int>(input.length()) && ports.size() < MAX_PROBE_PORTS) {
    int comma = input.indexOf(',', start);
    if (comma < 0) comma = input.length();
    const long value = input.substring(start, comma).toInt();
    if (value >= 1 && value <= 65535 &&
        std::find(ports.begin(), ports.end(), static_cast<uint16_t>(value)) == ports.end()) {
      ports.push_back(static_cast<uint16_t>(value));
    }
    start = comma + 1;
  }
  return ports;
}

void handleManualProbe() {
  IPAddress target;
  if (!server.hasArg("ip") || !target.fromString(server.arg("ip")) ||
      !isPrivateAddress(target)) {
    sendJson(400, "{\"error\":\"only private IPv4 targets are allowed\"}");
    return;
  }
  const String portArg = server.hasArg("ports")
                             ? server.arg("ports")
                             : "80,443,1883,8883,50001,50002,50003";
  const std::vector<uint16_t> ports = parsePorts(portArg);
  uint32_t rttMs = 0;
  const bool reachable = pingOnce(target, LAN_PING_TIMEOUT_MS, rttMs);
  String json = "{\"ip\":\"" + target.toString() + "\",\"ping\":" +
                String(reachable ? "true" : "false") + ",\"rttMs\":" +
                String(rttMs) + ",\"ports\":[";
  for (size_t i = 0; i < ports.size(); ++i) {
    if (i) json += ',';
    json += "{\"port\":" + String(ports[i]) + ",\"open\":" +
            String(portOpen(target, ports[i], LAN_TCP_TIMEOUT_MS) ? "true" : "false") + "}";
  }
  json += "]}";
  sendJson(200, json);
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
  preferences.clear();
  preferences.end();
  restartAtMs = millis() + 1200U;
  sendJson(202, "{\"ok\":true,\"restarting\":true}");
}

const char INDEX_HTML[] PROGMEM = R"HTML(
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RTK3 Network Probe</title><style>
body{font-family:system-ui;margin:2rem;max-width:1000px;background:#111;color:#eee}button,input{font:inherit;padding:.65rem;margin:.25rem}button{cursor:pointer}pre{background:#222;padding:1rem;overflow:auto;white-space:pre-wrap}.row{display:flex;gap:.5rem;flex-wrap:wrap}.card{border:1px solid #444;padding:1rem;margin:1rem 0;border-radius:.5rem}a{color:#8cf}.primary{font-weight:700;padding:.9rem 1.2rem}
</style></head><body><h1>RTK3 ESP32-S3 Network Probe</h1>
<div class="card"><h2>Find the RTK3 on this network</h2><p>The ESP32 scans its current subnet automatically after joining Wi-Fi. No RTK IP and no UART wiring are required.</p><div class="row"><button class="primary" onclick="post('/api/lan/scan/start')">Scan my network</button><button onclick="post('/api/lan/scan/stop')">Stop</button><button onclick="get('/api/lan/scan/results')">Show ranked results</button></div><p>For a definitive identification, scan once, power off the RTK3, scan again, and inspect <code>missingSinceLastScan</code>.</p></div>
<div class="card"><h2>Connect this ESP32 to your Wi-Fi</h2><form id="wifi"><input name="ssid" placeholder="Wi-Fi SSID" required><input name="password" type="password" placeholder="Wi-Fi password"><button>Save and restart</button></form><button onclick="post('/api/wifi/clear')">Clear saved Wi-Fi</button><button onclick="post('/api/wifi/scan')">List nearby Wi-Fi</button></div>
<div class="card"><h2>Probe one known device</h2><input id="ip" placeholder="192.168.1.123"><input id="ports" value="80,443,1883,8883,50001,50002,50003"><button onclick="post('/api/probe?ip='+encodeURIComponent(ip.value)+'&ports='+encodeURIComponent(ports.value))">Probe</button></div>
<div class="card"><h2>Important limitation</h2><p>The ESP32 can discover hosts and test local services. A normal Wi-Fi client cannot decrypt another client's WPA-protected unicast traffic, so cloud packet capture requires router-side capture or a separate monitor-mode workflow.</p></div>
<pre id="out">Loading status...</pre><script>
const out=document.getElementById('out');async function show(r){let t=await r.text();try{out.textContent=JSON.stringify(JSON.parse(t),null,2)}catch{out.textContent=t}}
async function get(u){show(await fetch(u))}async function post(u){show(await fetch(u,{method:'POST'}))}
document.getElementById('wifi').addEventListener('submit',async e=>{e.preventDefault();show(await fetch('/api/wifi/configure',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(new FormData(e.target))}))});
setInterval(()=>get('/api/status'),3000);get('/api/status');
</script></body></html>)HTML";

void configureRoutes() {
  server.on("/", HTTP_GET, [] { server.send_P(200, "text/html", INDEX_HTML); });
  server.on("/healthz", HTTP_GET, [] { sendJson(200, "{\"ok\":true}"); });
  server.on("/api/status", HTTP_GET, [] { sendJson(200, statusJson()); });
  server.on("/api/lan/scan/start", HTTP_POST, [] {
    if (!startLanScan()) {
      sendJson(409, "{\"error\":\"scan already active or Wi-Fi is not connected\"}");
      return;
    }
    sendJson(202, lanStatusJson());
  });
  server.on("/api/lan/scan/stop", HTTP_POST, [] {
    stopLanScan();
    sendJson(202, lanStatusJson());
  });
  server.on("/api/lan/scan/status", HTTP_GET, [] { sendJson(200, lanStatusJson()); });
  server.on("/api/lan/scan/results", HTTP_GET, [] {
    if (LittleFS.exists("/lan-scan.json") && !lanScan.active) {
      File file = LittleFS.open("/lan-scan.json", FILE_READ);
      server.streamFile(file, "application/json");
      file.close();
      return;
    }
    sendJson(200, lanResultsJson());
  });
  server.on("/api/probe", HTTP_POST, handleManualProbe);
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
    Serial.printf("[wifi] station connected at %s, gateway %s, mask %s\n",
                  WiFi.localIP().toString().c_str(),
                  WiFi.gatewayIP().toString().c_str(),
                  WiFi.subnetMask().toString().c_str());
  } else {
    Serial.println("[wifi] station connection failed, configure through fallback AP");
  }
}

}  // namespace

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\nRTK3 ESP32-S3 network probe starting");

  if (STATUS_LED_PIN >= 0) {
    pinMode(STATUS_LED_PIN, OUTPUT);
    setLed(false);
  }
  if (!LittleFS.begin(true)) Serial.println("[fatal] LittleFS mount failed");
  scanMutex = xSemaphoreCreateMutex();
  if (!scanMutex) Serial.println("[fatal] scan mutex allocation failed");

  connectWifi();
  configureRoutes();
  server.begin();
  Serial.println("[http] server ready");

  if (WiFi.status() == WL_CONNECTED && MDNS.begin(DEVICE_HOSTNAME)) {
    MDNS.addService("http", "tcp", 80);
    Serial.printf("[mdns] http://%s.local/\n", DEVICE_HOSTNAME);
  }

  if (AUTO_LAN_SCAN_ON_BOOT && WiFi.status() == WL_CONNECTED) {
    delay(500);
    startLanScan();
  }
}

void loop() {
  server.handleClient();
  if (restartAtMs && static_cast<int32_t>(millis() - restartAtMs) >= 0) {
    ESP.restart();
  }
  delay(1);
}
