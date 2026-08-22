# NTAG 424 DNA Tag Provisioning System

ESP32-S3 + PN532 NFC reader for programming and validating NXP NTAG 424 DNA secure NFC tags with unique AES-128 keys and encrypted secret storage.

## Hardware Setup

| SPI Variant | I2C Variant |
|:-----------:|:-----------:|
| ![SPI Setup](spi/749670.jpg) | ![I2C Setup](i2c/767325.jpg) |

## Variants

| Folder | Interface | Wiring |
|--------|-----------|--------|
| [spi/](spi/) | SPI (4-wire) | SCK, MOSI, MISO, SSEL — no pull-ups needed |
| [i2c/](i2c/) | I2C (2-wire) | SDA, SCL — requires 1.5KΩ pull-ups to 3.3V |

Both variants are functionally identical — same provisioning flow, same security model, same NVS database. Choose based on your wiring preference.

## Components

| Component | Description |
|-----------|-------------|
| ESP32-S3 DevKit | Microcontroller (3.3V logic, hardware AES, NVS flash storage) |
| PN532 NFC Breakout | 13.56 MHz NFC reader (ISO 14443-4 support) |
| NTAG 424 DNA tags | NXP secure NFC tags (AES-128 auth, file access control) |
| 2× 1.5KΩ resistors | I2C pull-ups (only for I2C variant) |

## Features

- **AuthenticateEV2First** — 3-pass mutual AES-128 challenge-response (ISO/IEC 9798-4)
- **CommMode.Full** — secret encrypted on the air (AES-CBC + CMAC), never in plaintext
- **Per-tag random keys** — Key 0 (admin), Key 1 (read), Key 2 (write) from hardware RNG
- **NVS database** — keys stored in ESP32 flash, survives reboots
- **Factory reset** — restore tag to all-zeros state
- **JSON export/import** — backup and restore tag records

## Quick Start

1. Pick your variant (SPI or I2C)
2. Wire per the variant's README
3. Open the `.ino` file in Arduino IDE
4. Set board to ESP32S3 Dev Module
5. Upload to ESP32-S3
6. Open Serial Monitor at 115200 baud
7. Press `P` to program a fresh tag

## Security Model

### Per-Tag Key Structure

| Key | Role | Permissions |
|-----|------|-------------|
| Key 0 (AppMasterKey) | Admin | Change any key (must know current), change file permissions |
| Key 1 (Read) | Reader | Read the secret from File 02 |
| Key 2 (Write) | Writer | Write data to File 02 |

All keys are **random** (16 bytes from ESP32 hardware RNG) and **unique per tag**.

### Encryption on the Air

File 02 is configured with **CommMode.Full** — all data is AES-128-CBC encrypted and CMAC'd during NFC communication. An RF eavesdropper capturing the entire exchange cannot extract the secret.

### Authentication Protocol

```
Reader                              Tag
  │ "Auth with Key 1"                 │
  ├──────────────────────────────────►│
  │                                   │
  │ E(Key1, RndB)     ← Challenge    │
  │◄──────────────────────────────────┤
  │                                   │
  │ E(Key1, RndA||RndB')  → Response │
  ├──────────────────────────────────►│
  │                                   │ Verifies RndB' ✓
  │ E(Key1, TI||RndA')    ← Proof   │
  │◄──────────────────────────────────┤
  │ Verifies RndA' ✓                  │
  │ MUTUAL AUTH COMPLETE              │
```

Neither the key nor the secret ever travels over the air in plaintext.

## Usage

```
Commands:
  [P] Program tag        — provision fresh tag with random keys + secret
  [V] Validate tag       — authenticate + read + verify secret
  [D] Dump/export        — print all records as JSON
  [I] Import             — manually add a tag record
  [X] Erase database     — wipe all records
  [T] Reset tag          — factory reset all keys and file settings
  [C] Tag count          — show number of stored tags
```

## Data Backup

**IMPORTANT:** If the ESP32 dies or flash is corrupted, all keys are lost permanently — you cannot recover access to programmed tags. Always export records with `D` and save the JSON somewhere secure.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "PN532 not found" | Wiring wrong | Check connections, switches, power-cycle PN532 |
| No serial output | USB CDC setting | Set USB CDC On Boot = Disabled, use UART port |
| "0x1E" INTEGRITY_ERROR | OldKey mismatch | DB key doesn't match tag; factory reset with `T` |
| "0xAE" AUTH_ERROR | Session expired | Re-tap tag |
| Re-program fails | Previous partial success | Factory reset with `T` first |

## Protocol Reference

- NXP NT4H2421Gx datasheet (NTAG 424 DNA)
- NXP AN12196 — NTAG 424 DNA features and hints
- ISO/IEC 14443-4 — Transmission protocol
- ISO/IEC 7816-4 — APDU command structure
- NIST SP 800-38B — CMAC
- ISO/IEC 9797-1 Method 2 — Padding

## License

See [LICENSE](LICENSE).
