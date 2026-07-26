Import("env")

import ipaddress
import json
from pathlib import Path

project_dir = Path(env["PROJECT_DIR"])
target_path = project_dir / "config" / "rtk3-target.json"
secrets_path = project_dir / "include" / "secrets.h"

if secrets_path.exists():
    print("[target-config] preserving existing ignored include/secrets.h")
else:
    target = json.loads(target_path.read_text(encoding="utf-8"))
    ip = str(ipaddress.ip_address(target["ip"]))
    lora_id = str(target["lora_id"]).strip()

    if not ipaddress.ip_address(ip).is_private:
        raise ValueError("RTK3 target IP must be private")
    if not lora_id or len(lora_id) > 64:
        raise ValueError("LoRa ID must contain 1 to 64 characters")
    if any(not (character.isalnum() or character in "-_:.") for character in lora_id):
        raise ValueError("LoRa ID contains unsupported characters")

    secrets_path.write_text(
        "#pragma once\n\n"
        "// Generated from config/rtk3-target.json. This file is gitignored.\n"
        "// Configure Wi-Fi from the fallback access point or replace these blanks locally.\n"
        '#define WIFI_SSID ""\n'
        '#define WIFI_PASSWORD ""\n'
        f'#define RTK3_IP "{ip}"\n'
        f'#define RTK3_LORA_ID "{lora_id}"\n',
        encoding="utf-8",
    )
    print(f"[target-config] generated ignored include/secrets.h for {ip}")
