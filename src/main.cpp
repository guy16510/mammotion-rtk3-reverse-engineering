#include <Arduino.h>
#include <LittleFS.h>
#include <NimBLEDevice.h>
#include <WebServer.h>
#include <WiFi.h>

#include <algorithm>
#include <array>
#include <vector>

#include "ProtocolAnalyzer.h"
#include "config.h"

#if __has_include("secrets.h")
#include "secrets.h"
#else
#define WIFI_SSID ""
#define WIFI_PASSWORD ""
#endif

namespace {

HardwareSerial RtkSerial(1);
WebServer server(80);
WiFiServer correctionServer(2101);
WiFiClient correctionClient;
ProtocolAnalyzer analyzer;

struct BaudResult {
  uint32_t baud = 0;
  ProtocolStats stats{};
  uint32_t storedBytes = 0;
  double printableRatio = 0;
};

struct CaptureState {
  bool active = false;
  bool completed = false;
  uint32_t secondsPerBaud = CAPTURE_SECONDS_PER_BAUD;
  size_t baudIndex = 0;
  uint32_t sampleStartedMs = 0;
  File output;
  std::array<BaudResult, RTK_BAUD_RATE_COUNT> results{};
} capture;

struct StreamState {
  bool active = false;
  uint32_t baud = 0;
  uint64_t bytesRead = 0;
  uint64_t bytesSent = 0;
  uint32_t clientsAccepted = 0;
  uint32_t startedMs = 0;
} stream;

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

String baudPath(uint32_t baud) { return "/baud-" + String(baud) + ".bin"; }

bool supportedBaud(uint32_t baud) {
  return std::find(std::begin(RTK_BAUD_RATES), std::end(RTK_BAUD_RATES), baud) !=
         std::end(RTK_BAUD_RATES);
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

void clearCaptureFiles() {
  LittleFS.remove("/summary.json");
  // Results from the superseded inbound LAN/TLS probe must never be mistaken
  // for evidence produced by a new passive UART capture.
  LittleFS.remove("/rtk3-probe.json");
  LittleFS.remove("/rtk3-tls-evidence.json");
  for (const uint32_t baud : RTK_BAUD_RATES) LittleFS.remove(baudPath(baud));
}

String typesJson(const ProtocolStats& stats) {
  String json = "[";
  for (size_t i = 0; i < stats.rtcmTypeCount; ++i) {
    if (i) json += ',';
    json += String(stats.rtcmTypes[i]);
  }
  json += ']';
  return json;
}

String resultJson(const BaudResult& result) {
  String json;
  json.reserve(240);
  json += "{\"baud\":" + String(result.baud);
  json += ",\"bytes\":" + String(static_cast<unsigned long>(result.stats.bytes));
  json += ",\"storedBytes\":" + String(result.storedBytes);
  json += ",\"rtcmFrames\":" + String(result.stats.rtcmFrames);
  json += ",\"rtcmCrcErrors\":" + String(result.stats.rtcmCrcErrors);
  json += ",\"rtcmTypes\":" + typesJson(result.stats);
  json += ",\"ubxSyncMarkers\":" + String(result.stats.ubxSyncMarkers);
  json += ",\"nmeaPrefixes\":" + String(result.stats.nmeaPrefixes);
  json += ",\"printableRatio\":" + String(result.printableRatio, 4);
  json += '}';
  return json;
}

String summaryJson() {
  String json = "{\"completed\":";
  json += capture.completed ? "true" : "false";
  json += ",\"secondsPerBaud\":" + String(capture.secondsPerBaud);
  json += ",\"samples\":[";
  for (size_t i = 0; i < RTK_BAUD_RATE_COUNT; ++i) {
    if (i) json += ',';
    json += resultJson(capture.results[i]);
  }
  json += "]}";
  return json;
}

void persistSummary() {
  File file = LittleFS.open("/summary.json", FILE_WRITE);
  if (!file) return;
  file.print(summaryJson());
  file.close();
}

void beginCurrentBaud() {
  const uint32_t baud = RTK_BAUD_RATES[capture.baudIndex];
  analyzer.reset();
  capture.results[capture.baudIndex] = BaudResult{};
  capture.results[capture.baudIndex].baud = baud;

  RtkSerial.end();
  delay(10);
  pinMode(RTK_RX_PIN, INPUT);
  RtkSerial.begin(baud, SERIAL_8N1, RTK_RX_PIN, -1);

  capture.output = LittleFS.open(baudPath(baud), FILE_WRITE);
  capture.sampleStartedMs = millis();
  Serial.printf("[capture] baud=%lu file=%s\n", static_cast<unsigned long>(baud),
                baudPath(baud).c_str());
}

void finalizeCurrentBaud() {
  if (capture.output) capture.output.close();
  BaudResult& result = capture.results[capture.baudIndex];
  result.stats = analyzer.stats();
  result.printableRatio = analyzer.printableRatio();
  Serial.printf("[capture] baud=%lu bytes=%lu rtcm=%lu ubx=%lu nmea=%lu\n",
                static_cast<unsigned long>(result.baud),
                static_cast<unsigned long>(result.stats.bytes),
                static_cast<unsigned long>(result.stats.rtcmFrames),
                static_cast<unsigned long>(result.stats.ubxSyncMarkers),
                static_cast<unsigned long>(result.stats.nmeaPrefixes));
}

void finishCapture() {
  capture.active = false;
  capture.completed = true;
  RtkSerial.end();
  persistSummary();
  setLed(false);
  Serial.println("[capture] sweep complete");
}

bool startCapture(uint32_t secondsPerBaud) {
  if (capture.active || stream.active) return false;
  clearCaptureFiles();
  capture = CaptureState{};
  capture.active = true;
  capture.secondsPerBaud = std::max<uint32_t>(1, std::min<uint32_t>(
      secondsPerBaud, MAX_CAPTURE_SECONDS_PER_BAUD));
  setLed(true);
  beginCurrentBaud();
  return true;
}

void stopCapture() {
  if (!capture.active) return;
  finalizeCurrentBaud();
  capture.active = false;
  capture.completed = false;
  RtkSerial.end();
  persistSummary();
  setLed(false);
}

void serviceCapture() {
  if (!capture.active) return;

  BaudResult& result = capture.results[capture.baudIndex];
  uint8_t buffer[256];
  while (RtkSerial.available() > 0) {
    const size_t wanted = std::min<size_t>(RtkSerial.available(), sizeof(buffer));
    const size_t received = RtkSerial.readBytes(buffer, wanted);
    if (!received) break;
    analyzer.feed(buffer, received);

    if (capture.output && result.storedBytes < MAX_CAPTURE_BYTES_PER_BAUD) {
      const size_t remaining = MAX_CAPTURE_BYTES_PER_BAUD - result.storedBytes;
      const size_t writing = std::min(received, remaining);
      result.storedBytes += capture.output.write(buffer, writing);
    }
  }

  const bool timedOut = millis() - capture.sampleStartedMs >=
                        capture.secondsPerBaud * 1000UL;
  const bool storageFull = result.storedBytes >= MAX_CAPTURE_BYTES_PER_BAUD;
  if (!timedOut && !storageFull) return;

  finalizeCurrentBaud();
  ++capture.baudIndex;
  if (capture.baudIndex >= RTK_BAUD_RATE_COUNT) {
    finishCapture();
  } else {
    beginCurrentBaud();
  }
}

void stopLiveStream() {
  if (!stream.active) return;
  RtkSerial.end();
  correctionClient.stop();
  stream.active = false;
  setLed(false);
  Serial.println("[stream] stopped");
}

bool startLiveStream(uint32_t baud) {
  if (capture.active || stream.active || !supportedBaud(baud)) return false;
  stream = StreamState{};
  stream.active = true;
  stream.baud = baud;
  stream.startedMs = millis();
  analyzer.reset();
  pinMode(RTK_RX_PIN, INPUT);
  RtkSerial.begin(baud, SERIAL_8N1, RTK_RX_PIN, -1);
  setLed(true);
  Serial.printf("[stream] receive-only TCP bridge baud=%lu port=2101\n",
                static_cast<unsigned long>(baud));
  return true;
}

void serviceLiveStream() {
  if (!stream.active) return;

  if (!correctionClient || !correctionClient.connected()) {
    correctionClient.stop();
    WiFiClient candidate = correctionServer.available();
    if (candidate) {
      correctionClient = candidate;
      correctionClient.setNoDelay(true);
      ++stream.clientsAccepted;
      Serial.printf("[stream] client connected from %s\n",
                    correctionClient.remoteIP().toString().c_str());
    }
  }

  uint8_t buffer[512];
  while (RtkSerial.available() > 0) {
    const size_t wanted = std::min<size_t>(RtkSerial.available(), sizeof(buffer));
    const size_t received = RtkSerial.readBytes(buffer, wanted);
    if (!received) break;
    stream.bytesRead += received;
    analyzer.feed(buffer, received);
    if (correctionClient && correctionClient.connected()) {
      const size_t sent = correctionClient.write(buffer, received);
      stream.bytesSent += sent;
      if (sent != received) {
        correctionClient.stop();
        Serial.println("[stream] short TCP write, client dropped");
      }
    }
  }
}

String statusJson() {
  String json = "{\"ok\":true";
  json += ",\"hostname\":\"" + jsonEscape(DEVICE_HOSTNAME) + "\"";
  json += ",\"active\":" + String(capture.active ? "true" : "false");
  json += ",\"completed\":" + String(capture.completed ? "true" : "false");
  json += ",\"baudIndex\":" + String(capture.baudIndex);
  json += ",\"baudCount\":" + String(RTK_BAUD_RATE_COUNT);
  if (capture.active && capture.baudIndex < RTK_BAUD_RATE_COUNT) {
    json += ",\"currentBaud\":" + String(RTK_BAUD_RATES[capture.baudIndex]);
    const uint32_t elapsed = (millis() - capture.sampleStartedMs) / 1000UL;
    json += ",\"sampleElapsedSeconds\":" + String(elapsed);
  }
  json += ",\"streamActive\":" + String(stream.active ? "true" : "false");
  json += ",\"streamPort\":2101";
  json += ",\"streamBaud\":" + String(stream.baud);
  json += ",\"streamClientConnected\":" +
          String(correctionClient && correctionClient.connected() ? "true" : "false");
  json += ",\"streamClientsAccepted\":" + String(stream.clientsAccepted);
  json += ",\"streamBytesRead\":" +
          String(static_cast<unsigned long long>(stream.bytesRead));
  json += ",\"streamBytesSent\":" +
          String(static_cast<unsigned long long>(stream.bytesSent));
  json += ",\"streamRtcmFrames\":" + String(analyzer.stats().rtcmFrames);
  json += ",\"streamRtcmCrcErrors\":" + String(analyzer.stats().rtcmCrcErrors);
  json += ",\"streamRtcmTypes\":" + typesJson(analyzer.stats());
  json += ",\"stationConnected\":" + String(WiFi.status() == WL_CONNECTED ? "true" : "false");
  json += ",\"stationIp\":\"" + WiFi.localIP().toString() + "\"";
  json += ",\"apIp\":\"" + WiFi.softAPIP().toString() + "\"";
  json += ",\"freeHeap\":" + String(ESP.getFreeHeap());
  json += ",\"fsUsed\":" + String(LittleFS.usedBytes());
  json += ",\"fsTotal\":" + String(LittleFS.totalBytes());
  json += '}';
  return json;
}

void sendJson(int status, const String& body) {
  server.sendHeader("Cache-Control", "no-store");
  server.send(status, "application/json", body);
}

void handleStartCapture() {
  const uint32_t seconds = server.hasArg("seconds")
                               ? static_cast<uint32_t>(server.arg("seconds").toInt())
                               : CAPTURE_SECONDS_PER_BAUD;
  if (!startCapture(seconds)) {
    sendJson(409, "{\"error\":\"capture or live stream already active\"}");
    return;
  }
  sendJson(202, statusJson());
}

void handleStartLiveStream() {
  if (!server.hasArg("baud")) {
    sendJson(400, "{\"error\":\"baud is required\"}");
    return;
  }
  const uint32_t baud = static_cast<uint32_t>(server.arg("baud").toInt());
  if (!supportedBaud(baud)) {
    sendJson(400, "{\"error\":\"unsupported baud\"}");
    return;
  }
  if (!startLiveStream(baud)) {
    sendJson(409, "{\"error\":\"capture or live stream already active\"}");
    return;
  }
  sendJson(202, statusJson());
}

void handleSummary() {
  if (LittleFS.exists("/summary.json")) {
    File file = LittleFS.open("/summary.json", FILE_READ);
    server.streamFile(file, "application/json");
    file.close();
    return;
  }
  sendJson(200, summaryJson());
}

void handleFiles() {
  String json = "[";
  bool first = true;
  File root = LittleFS.open("/");
  File file = root.openNextFile();
  while (file) {
    if (!first) json += ',';
    first = false;
    json += "{\"name\":\"" + jsonEscape(file.name()) + "\",\"size\":" +
            String(file.size()) + "}";
    file = root.openNextFile();
  }
  json += ']';
  sendJson(200, json);
}

void handleDownload() {
  if (!server.hasArg("name")) {
    sendJson(400, "{\"error\":\"name is required\"}");
    return;
  }
  String name = server.arg("name");
  if (!name.startsWith("/") || name.indexOf("..") >= 0 || !LittleFS.exists(name)) {
    sendJson(404, "{\"error\":\"file not found\"}");
    return;
  }
  File file = LittleFS.open(name, FILE_READ);
  server.sendHeader("Content-Disposition", "attachment; filename=\"" +
                                            String(file.name()).substring(1) + "\"");
  server.streamFile(file, "application/octet-stream");
  file.close();
}

void handleWifiScan() {
  const int count = WiFi.scanNetworks(false, true, false, 300);
  String json = "[";
  for (int i = 0; i < count; ++i) {
    if (i) json += ',';
    json += "{\"ssid\":\"" + jsonEscape(WiFi.SSID(i)) + "\"";
    json += ",\"bssid\":\"" + WiFi.BSSIDstr(i) + "\"";
    json += ",\"rssi\":" + String(WiFi.RSSI(i));
    json += ",\"channel\":" + String(WiFi.channel(i));
    json += ",\"encryption\":" + String(static_cast<int>(WiFi.encryptionType(i)));
    json += '}';
  }
  json += ']';
  WiFi.scanDelete();
  sendJson(200, json);
}

void handleBleScan() {
  NimBLEScan* scan = NimBLEDevice::getScan();
  scan->setActiveScan(false);
  scan->setDuplicateFilter(false);
  NimBLEScanResults results = scan->getResults(5000, false);

  String json = "[";
  for (int i = 0; i < results.getCount(); ++i) {
    const NimBLEAdvertisedDevice* device = results.getDevice(i);
    if (i) json += ',';
    json += "{\"address\":\"" + String(device->getAddress().toString().c_str()) + "\"";
    json += ",\"rssi\":" + String(device->getRSSI());
    if (device->haveName()) {
      json += ",\"name\":\"" + jsonEscape(String(device->getName().c_str())) + "\"";
    }
    json += ",\"connectable\":" + String(device->isConnectable() ? "true" : "false");
    json += '}';
  }
  json += ']';
  scan->clearResults();
  sendJson(200, json);
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

void handleProbe() {
  IPAddress target;
  if (!server.hasArg("ip") || !target.fromString(server.arg("ip")) ||
      !isPrivateAddress(target)) {
    sendJson(400, "{\"error\":\"only private IPv4 targets are allowed\"}");
    return;
  }

  const String portArg = server.hasArg("ports")
                             ? server.arg("ports")
                             : "22,53,80,443,1883,8883,8080,8443";
  const std::vector<uint16_t> ports = parsePorts(portArg);
  if (ports.empty()) {
    sendJson(400, "{\"error\":\"no valid ports\"}");
    return;
  }

  String json = "{\"ip\":\"" + target.toString() + "\",\"ports\":[";
  for (size_t i = 0; i < ports.size(); ++i) {
    WiFiClient client;
    const uint32_t started = millis();
    const bool open = client.connect(target, ports[i], TCP_CONNECT_TIMEOUT_MS);
    const uint32_t elapsed = millis() - started;
    client.stop();
    if (i) json += ',';
    json += "{\"port\":" + String(ports[i]);
    json += ",\"open\":" + String(open ? "true" : "false");
    json += ",\"elapsedMs\":" + String(elapsed) + '}';
  }
  json += "]}";
  sendJson(200, json);
}

const char INDEX_HTML[] PROGMEM = R"HTML(
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RTK3 ESP32-S3 Probe</title><style>
body{font-family:system-ui;margin:2rem;max-width:900px;background:#111;color:#eee}button,input{font:inherit;padding:.6rem;margin:.25rem}button{cursor:pointer}pre{background:#222;padding:1rem;overflow:auto;white-space:pre-wrap}.row{display:flex;gap:.5rem;flex-wrap:wrap}.card{border:1px solid #444;padding:1rem;margin:1rem 0;border-radius:.5rem}a{color:#8cf}
</style></head><body><h1>RTK3 ESP32-S3 Probe</h1>
<div class="card"><h2>Passive UART sweep</h2><div class="row"><input id="seconds" type="number" min="1" max="60" value="12"><button onclick="post('/api/capture/start?seconds='+seconds.value)">Start</button><button onclick="post('/api/capture/stop')">Stop</button><button onclick="get('/api/summary')">Summary</button><button onclick="get('/api/files')">Files</button></div></div>
<div class="card"><h2>Fixed-baud live stream</h2><div class="row"><input id="streamBaud" type="number" value="115200"><button onclick="post('/api/stream/start?baud='+streamBaud.value)">Start TCP 2101</button><button onclick="post('/api/stream/stop')">Stop</button></div><p>Choose a baud only after the passive sweep identifies a valid signal. The stream is raw and must pass through the host CRC validator before reaching a receiver.</p></div>
<div class="card"><h2>Radio discovery</h2><button onclick="post('/api/wifi/scan')">Wi-Fi scan</button><button onclick="post('/api/ble/scan')">BLE scan</button></div>
<div class="card"><h2>Bounded private-network probe</h2><input id="ip" placeholder="192.168.1.123"><input id="ports" value="80,443,1883,8883"><button onclick="post('/api/probe?ip='+encodeURIComponent(ip.value)+'&ports='+encodeURIComponent(ports.value))">Probe</button></div>
<pre id="out">Loading status...</pre><script>
const out=document.getElementById('out');async function show(r){let t=await r.text();try{out.textContent=JSON.stringify(JSON.parse(t),null,2)}catch{out.textContent=t}}
async function get(u){show(await fetch(u))}async function post(u){show(await fetch(u,{method:'POST'}))}setInterval(()=>get('/api/status'),3000);get('/api/status');
</script></body></html>)HTML";

void configureRoutes() {
  server.on("/", HTTP_GET, [] { server.send_P(200, "text/html", INDEX_HTML); });
  server.on("/healthz", HTTP_GET, [] { sendJson(200, "{\"ok\":true}"); });
  server.on("/api/status", HTTP_GET, [] { sendJson(200, statusJson()); });
  server.on("/api/capture/start", HTTP_POST, handleStartCapture);
  server.on("/api/capture/stop", HTTP_POST, [] {
    stopCapture();
    sendJson(200, statusJson());
  });
  server.on("/api/stream/start", HTTP_POST, handleStartLiveStream);
  server.on("/api/stream/stop", HTTP_POST, [] {
    stopLiveStream();
    sendJson(200, statusJson());
  });
  server.on("/api/summary", HTTP_GET, handleSummary);
  server.on("/api/files", HTTP_GET, handleFiles);
  server.on("/api/file", HTTP_GET, handleDownload);
  server.on("/api/wifi/scan", HTTP_POST, handleWifiScan);
  server.on("/api/ble/scan", HTTP_POST, handleBleScan);
  server.on("/api/probe", HTTP_POST, handleProbe);
  server.onNotFound([] { sendJson(404, "{\"error\":\"not found\"}"); });
}

void connectWifi() {
  WiFi.mode(WIFI_AP_STA);
  WiFi.setHostname(DEVICE_HOSTNAME);
  WiFi.softAP(AP_SSID, AP_PASSWORD);
  Serial.printf("[wifi] fallback AP %s at %s\n", AP_SSID,
                WiFi.softAPIP().toString().c_str());

  if (strlen(WIFI_SSID) == 0) return;
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  const uint32_t deadline = millis() + 15000;
  while (WiFi.status() != WL_CONNECTED && static_cast<int32_t>(deadline - millis()) > 0) {
    delay(250);
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("[wifi] station connected at %s\n", WiFi.localIP().toString().c_str());
  } else {
    Serial.println("[wifi] station connection failed, AP remains available");
  }
}

}  // namespace

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\nRTK3 ESP32-S3 standalone probe starting");

  if (STATUS_LED_PIN >= 0) {
    pinMode(STATUS_LED_PIN, OUTPUT);
    setLed(false);
  }

  if (!LittleFS.begin(true)) {
    Serial.println("[fatal] LittleFS mount failed");
  }

  connectWifi();
  NimBLEDevice::init(DEVICE_HOSTNAME);
  configureRoutes();
  server.begin();
  correctionServer.begin();
  correctionServer.setNoDelay(true);
  Serial.println("[http] server ready; raw correction stream port 2101 ready");
}

void loop() {
  server.handleClient();
  serviceCapture();
  serviceLiveStream();
  delay(1);
}
