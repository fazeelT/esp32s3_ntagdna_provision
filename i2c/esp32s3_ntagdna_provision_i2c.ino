/******************************************************************************
 * NTAG 424 DNA Tag Provisioning & Validation System
 * 
 * Hardware: ESP32-S3 + PN532 NFC Reader (I2C)
 * 
 * Modes:
 *   [P] Program  — provision a fresh tag with random keys + secret
 *   [V] Validate — verify a programmed tag is genuine
 *   [D] Dump     — export all records as JSON
 *   [I] Import   — manually add a tag record
 *   [X] Erase    — wipe the database
 *   [C] Count    — show number of stored tags
 * 
 * Wiring (I2C with 1.5K pull-ups — ESP32-S3 is 3.3V native):
 *   PN532 SDA  → GPIO 8   (+ 1.5KΩ pull-up to 3.3V)
 *   PN532 SCL  → GPIO 9   (+ 1.5KΩ pull-up to 3.3V)
 *   PN532 IRQ  → GPIO 7   (optional, active LOW when data ready)
 *   PN532 RSTO → GPIO 6   (optional, for hardware reset)
 *   PN532 3.3V → 3.3V
 *   PN532 GND  → GND
 *   PN532 switches: SEL0=ON, SEL1=OFF (I2C mode)
 ******************************************************************************/

#include <Wire.h>
#include <Preferences.h>
#include "mbedtls/aes.h"
#include "mbedtls/cmac.h"

// =============================================================================
// CONFIGURATION
// =============================================================================

// I2C pins to PN532 (GPIO 8/9 are safe I2C pins on ESP32-S3)
const uint8_t PIN_NFC_SDA = 8;
const uint8_t PIN_NFC_SCL = 9;
const uint8_t PIN_NFC_IRQ = 7;    // Optional: LOW when PN532 has data ready
const uint8_t PIN_NFC_RST = 6;    // Optional: hardware reset

// PN532 I2C address (fixed by hardware)
const uint8_t PN532_I2C_ADDR = 0x24;

// NTAG 424 DNA key slot numbers
const uint8_t KEY_SLOT_MASTER = 0x00;  // AppMasterKey — full control
const uint8_t KEY_SLOT_READ = 0x01;    // Read access to file
const uint8_t KEY_SLOT_WRITE = 0x02;   // Write access to file

// File number for the secret
const uint8_t SECRET_FILE_NUMBER = 0x02;
const uint8_t SECRET_LENGTH = 16;

// Factory default key (all zeros)
const uint8_t FACTORY_KEY[16] = { 0 };

// NVS record size: MasterKey(16) + ReadKey(16) + WriteKey(16) + Secret(16) = 64
const size_t NVS_RECORD_SIZE = 64;

// =============================================================================
// PN532 PROTOCOL CONSTANTS
// =============================================================================

const uint8_t PN532_HOST_TO_READER = 0xD4;
const uint8_t PN532_READER_TO_HOST = 0xD5;

const uint8_t PN532_GET_FIRMWARE = 0x02;
const uint8_t PN532_SAM_CONFIG = 0x14;
const uint8_t PN532_RF_CONFIG = 0x32;
const uint8_t PN532_LIST_TARGETS = 0x4A;
const uint8_t PN532_DATA_EXCHANGE = 0x40;

// =============================================================================
// NTAG 424 DNA COMMAND CODES
// =============================================================================

const uint8_t NTAG_AUTH_FIRST_PART1 = 0x71;
const uint8_t NTAG_AUTH_FIRST_PART2 = 0xAF;
const uint8_t NTAG_CHANGE_KEY = 0xC4;
const uint8_t NTAG_CHANGE_FILE_SETTINGS = 0x5F;
const uint8_t NTAG_WRITE_DATA = 0x8D;
const uint8_t NTAG_READ_DATA = 0xAD;

// =============================================================================
// GLOBAL STATE
// =============================================================================

// Authenticated session state
uint8_t sessionEncryptionKey[16];
uint8_t sessionMacKey[16];
uint8_t transactionId[4];
uint16_t commandCounter;
bool isAuthenticated = false;

// Application state
enum AppMode { MODE_IDLE,
               MODE_PROGRAM,
               MODE_VALIDATE,
               MODE_RESET };
AppMode appMode = MODE_IDLE;

// Hardware
Preferences storage;

// =============================================================================
// PN532 I2C COMMUNICATION
// =============================================================================

void nfc_initialize() {
  Wire.begin(PIN_NFC_SDA, PIN_NFC_SCL);
  Wire.setClock(100000);  // 100 kHz I2C — PN532 max is 400 kHz but 100 is safer
  Wire.setTimeOut(100);   // 100ms timeout on I2C operations (prevents hangs)

  // Configure IRQ pin (active LOW when PN532 has data ready)
  pinMode(PIN_NFC_IRQ, INPUT_PULLUP);

  // Hardware reset (toggle RSTO low then high)
  if (PIN_NFC_RST != 0xFF) {
    pinMode(PIN_NFC_RST, OUTPUT);
    digitalWrite(PIN_NFC_RST, HIGH);
    delay(10);
    digitalWrite(PIN_NFC_RST, LOW);
    delay(50);
    digitalWrite(PIN_NFC_RST, HIGH);
    delay(50);
  }

  Serial0.println("I2C initialized");
}

/**
 * Hardware reset the PN532. Call this when the chip becomes unresponsive.
 */
void nfc_reset() {
  if (PIN_NFC_RST != 0xFF) {
    digitalWrite(PIN_NFC_RST, LOW);
    delay(50);
    digitalWrite(PIN_NFC_RST, HIGH);
    delay(50);
  }
  // Re-initialize I2C bus (clears stuck SDA)
  Wire.end();
  delay(10);
  Wire.begin(PIN_NFC_SDA, PIN_NFC_SCL);
  Wire.setClock(100000);
  delay(50);
  nfc_setup();
}

bool nfc_checkReady() {
  // Check IRQ pin first (fastest if wired)
  if (digitalRead(PIN_NFC_IRQ) == LOW) return true;

  // Fallback: I2C ready-byte poll
  uint8_t n = Wire.requestFrom((uint8_t)PN532_I2C_ADDR, (uint8_t)1);
  if (n >= 1 && Wire.available()) {
    uint8_t status = Wire.read();
    return (status == 0x01);
  }
  return false;
}

bool nfc_waitUntilReady(uint16_t timeoutMs) {
  uint32_t startTime = millis();
  while (!nfc_checkReady()) {
    if (millis() - startTime > timeoutMs) return false;
    delay(5);
  }
  return true;
}

bool nfc_sendFrame(uint8_t *commandData, uint8_t commandLength) {
  uint8_t frameLength = commandLength + 1;  // +1 for TFI byte
  uint8_t lengthChecksum = ~frameLength + 1;
  uint8_t dataChecksum = PN532_HOST_TO_READER;

  for (uint8_t i = 0; i < commandLength; i++) {
    dataChecksum += commandData[i];
  }

  Wire.beginTransmission(PN532_I2C_ADDR);

  // Preamble + Start Code
  Wire.write(0x00);  // Preamble
  Wire.write(0x00);  // Start Code byte 1
  Wire.write(0xFF);  // Start Code byte 2

  // Length + LCS
  Wire.write(frameLength);
  Wire.write(lengthChecksum);

  // TFI (Host to PN532)
  Wire.write(PN532_HOST_TO_READER);

  // Command data
  for (uint8_t i = 0; i < commandLength; i++) {
    Wire.write(commandData[i]);
  }

  // DCS + Postamble
  Wire.write((uint8_t)(~dataChecksum + 1));
  Wire.write(0x00);

  uint8_t err = Wire.endTransmission();
  return (err == 0);
}

bool nfc_receiveAck() {
  if (!nfc_waitUntilReady(1000)) return false;

  // Request 7 bytes: 1 ready byte + 6 ACK bytes
  Wire.requestFrom((uint8_t)PN532_I2C_ADDR, (uint8_t)7);

  // First byte is the I2C ready flag (0x01 = ready)
  uint8_t readyByte = Wire.read();
  if (readyByte != 0x01) return false;

  uint8_t ackBuffer[6];
  for (int i = 0; i < 6; i++) {
    ackBuffer[i] = Wire.read();
  }

  const uint8_t expectedAck[] = { 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00 };
  return (memcmp(ackBuffer, expectedAck, 6) == 0);
}

int16_t nfc_receiveResponse(uint8_t *buffer, uint8_t bufferSize, uint16_t timeoutMs) {
  if (!nfc_waitUntilReady(timeoutMs)) return -1;

  // Request a large chunk — we don't know the exact length yet
  // PN532 I2C: first byte is ready flag, then preamble+frame
  uint8_t rawBuf[128 + 7];  // max frame + overhead
  uint8_t requestLen = (bufferSize + 12 > 128) ? 128 : bufferSize + 12;
  Wire.requestFrom((uint8_t)PN532_I2C_ADDR, (uint8_t)(requestLen + 1));  // +1 for ready byte

  // First byte: ready flag
  uint8_t readyByte = Wire.read();
  if (readyByte != 0x01) return -1;

  // Read preamble + start code
  uint8_t preamble = Wire.read();  // 0x00
  uint8_t startCode1 = Wire.read();
  uint8_t startCode2 = Wire.read();
  if (startCode1 != 0x00 || startCode2 != 0xFF) {
    // Flush remaining
    while (Wire.available()) Wire.read();
    return -2;
  }

  // Read length
  uint8_t payloadLength = Wire.read();
  Wire.read();  // LCS (skip)

  // Read TFI
  uint8_t tfi = Wire.read();
  if (tfi != PN532_READER_TO_HOST) {
    while (Wire.available()) Wire.read();
    return -3;
  }

  // Read data (payload minus TFI byte)
  uint8_t dataLength = payloadLength - 1;
  uint8_t bytesToRead = (dataLength > bufferSize) ? bufferSize : dataLength;

  for (uint8_t i = 0; i < bytesToRead; i++) {
    buffer[i] = Wire.read();
  }

  // Read remaining bytes + DCS + postamble
  for (uint8_t i = bytesToRead; i < dataLength; i++) {
    Wire.read();
  }
  Wire.read();  // DCS
  Wire.read();  // Postamble

  // Flush any remaining
  while (Wire.available()) Wire.read();

  return bytesToRead;
}

/**
 * Send a command to PN532 and get the response.
 * Returns true if command succeeded, with response in buffer.
 */
bool nfc_executeCommand(uint8_t *command, uint8_t commandLength,
                        uint8_t *response, uint8_t *responseLength,
                        uint16_t timeoutMs) {
  if (!nfc_sendFrame(command, commandLength)) return false;

  if (!nfc_receiveAck()) return false;

  int16_t received = nfc_receiveResponse(response, *responseLength, timeoutMs);
  if (received < 0) return false;

  *responseLength = received;
  return true;
}

// =============================================================================
// PN532 HIGH-LEVEL FUNCTIONS
// =============================================================================

bool nfc_setup() {
  // Get firmware version
  uint8_t cmd[] = { PN532_GET_FIRMWARE };
  uint8_t response[12];
  uint8_t responseLength = sizeof(response);

  if (!nfc_executeCommand(cmd, 1, response, &responseLength, 1000)) return false;
  if (responseLength < 5 || response[0] != 0x03) return false;

  static bool firstBoot = true;
  if (firstBoot) {
    Serial0.printf("PN532 firmware: %d.%d\n", response[2], response[3]);
    firstBoot = false;
  }

  // Configure SAM (Security Access Module)
  uint8_t samCmd[] = { PN532_SAM_CONFIG, 0x01, 0x14, 0x01 };
  responseLength = sizeof(response);
  nfc_executeCommand(samCmd, 4, response, &responseLength, 1000);

  // Set max retries for passive activation
  uint8_t rfCmd[] = { PN532_RF_CONFIG, 0x05, 0xFF, 0x01, 0xFF };
  responseLength = sizeof(response);
  nfc_executeCommand(rfCmd, 5, response, &responseLength, 1000);

  return true;
}

/**
 * Scan for an NFC tag. Returns true if a tag is found, with UID populated.
 */
bool nfc_findTag(uint8_t *uid, uint8_t *uidLength) {
  uint8_t cmd[] = { PN532_LIST_TARGETS, 0x01, 0x00 };  // 1 target, 106 kbps Type A
  uint8_t response[32];
  uint8_t responseLength = sizeof(response);

  // Send command — if I2C write fails, PN532 is unresponsive
  if (!nfc_sendFrame(cmd, 3)) return false;

  // Wait for ACK (short timeout)
  if (!nfc_receiveAck()) return false;

  // Wait for tag response — needs up to 2s for RF field + tag detection
  int16_t received = nfc_receiveResponse(response, sizeof(response), 2000);
  if (received < 0) return false;
  if (received < 7 || response[0] != 0x4B || response[1] == 0) return false;

  *uidLength = response[6];
  if (*uidLength > 7) *uidLength = 7;
  memcpy(uid, response + 7, *uidLength);
  return true;
}

/**
 * Send an ISO 7816-4 APDU to the tag via PN532's InDataExchange.
 */
bool nfc_sendApdu(uint8_t *apdu, uint8_t apduLength,
                  uint8_t *response, uint8_t *responseLength) {
  uint8_t command[128];
  command[0] = PN532_DATA_EXCHANGE;
  command[1] = 0x01;  // Target number
  memcpy(command + 2, apdu, apduLength);

  uint8_t rawResponse[128];
  uint8_t rawResponseLength = sizeof(rawResponse);

  if (!nfc_executeCommand(command, 2 + apduLength, rawResponse, &rawResponseLength, 3000)) {
    return false;
  }

  // Check PN532 error byte
  if (rawResponseLength < 2 || rawResponse[0] != 0x41 || rawResponse[1] != 0x00) {
    return false;
  }

  // Copy tag response (skip PN532 header)
  *responseLength = rawResponseLength - 2;
  memcpy(response, rawResponse + 2, *responseLength);
  return true;
}

/**
 * Select the NTAG 424 DNA application (DF name: D2760000850101)
 */
bool nfc_selectNtagApp() {
  uint8_t selectApdu[] = {
    0x00, 0xA4, 0x04, 0x00, 0x07,
    0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01,
    0x00
  };
  uint8_t response[32];
  uint8_t responseLength = sizeof(response);

  if (!nfc_sendApdu(selectApdu, sizeof(selectApdu), response, &responseLength)) {
    return false;
  }

  return (responseLength >= 2 && response[responseLength - 2] == 0x90 && response[responseLength - 1] == 0x00);
}

// =============================================================================
// AES CRYPTOGRAPHY (using mbedtls — built into ESP32)
// =============================================================================

void aes_encryptCbc(const uint8_t *key, uint8_t *iv,
                    const uint8_t *plaintext, uint8_t *ciphertext, size_t length) {
  mbedtls_aes_context context;
  mbedtls_aes_init(&context);
  mbedtls_aes_setkey_enc(&context, key, 128);
  mbedtls_aes_crypt_cbc(&context, MBEDTLS_AES_ENCRYPT, length, iv, plaintext, ciphertext);
  mbedtls_aes_free(&context);
}

void aes_decryptCbc(const uint8_t *key, uint8_t *iv,
                    const uint8_t *ciphertext, uint8_t *plaintext, size_t length) {
  mbedtls_aes_context context;
  mbedtls_aes_init(&context);
  mbedtls_aes_setkey_dec(&context, key, 128);
  mbedtls_aes_crypt_cbc(&context, MBEDTLS_AES_DECRYPT, length, iv, ciphertext, plaintext);
  mbedtls_aes_free(&context);
}

void aes_encryptEcb(const uint8_t *key, const uint8_t *input, uint8_t *output) {
  mbedtls_aes_context context;
  mbedtls_aes_init(&context);
  mbedtls_aes_setkey_enc(&context, key, 128);
  mbedtls_aes_crypt_ecb(&context, MBEDTLS_AES_ENCRYPT, input, output);
  mbedtls_aes_free(&context);
}

bool aes_calculateCmac(const uint8_t *key, const uint8_t *message, size_t length, uint8_t *mac) {
  const mbedtls_cipher_info_t *cipherInfo =
    mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
  return (mbedtls_cipher_cmac(cipherInfo, key, 128, message, length, mac) == 0);
}

// =============================================================================
// EV2 SECURE MESSAGING
// =============================================================================

/**
 * Calculate the IV for encrypting command data.
 * IV = AES_ECB(SessEncKey, A5 5A || TI || CmdCtr_LE16 || 00...00)
 */
void secureMessaging_calculateCommandIv(uint8_t *iv) {
  uint8_t ivInput[16] = { 0 };
  ivInput[0] = 0xA5;
  ivInput[1] = 0x5A;
  memcpy(ivInput + 2, transactionId, 4);
  ivInput[6] = commandCounter & 0xFF;
  ivInput[7] = (commandCounter >> 8) & 0xFF;
  // Bytes 8-15 remain zero

  aes_encryptEcb(sessionEncryptionKey, ivInput, iv);
}

/**
 * Calculate truncated 8-byte MAC for a command.
 * Full MAC = CMAC(SessMACKey, cmd || cmdCtr_LE16 || TI || data)
 * Truncated = bytes at odd positions (1,3,5,7,9,11,13,15)
 */
void secureMessaging_calculateMac(uint8_t commandCode,
                                  const uint8_t *data, size_t dataLength,
                                  uint8_t *truncatedMac) {
  uint8_t macInput[128];
  size_t position = 0;

  macInput[position++] = commandCode;
  macInput[position++] = commandCounter & 0xFF;
  macInput[position++] = (commandCounter >> 8) & 0xFF;
  memcpy(macInput + position, transactionId, 4);
  position += 4;

  if (data != NULL && dataLength > 0) {
    memcpy(macInput + position, data, dataLength);
    position += dataLength;
  }

  uint8_t fullMac[16];
  aes_calculateCmac(sessionMacKey, macInput, position, fullMac);

  // Truncate: take bytes at odd positions (1,3,5,7,9,11,13,15)
  for (int i = 0; i < 8; i++) {
    truncatedMac[i] = fullMac[i * 2 + 1];
  }
}

/**
 * Verify the MAC on a response from the tag.
 * Response MAC = CMAC_truncated(SessMACKey, ResponseStatus || CmdCtr_LE16 || TI || ResponseData)
 * Note: CmdCtr used here is the UPDATED counter (after the command was accepted).
 *
 * @param responseStatus  The status byte from the response (usually 0x00)
 * @param responseData    The data portion of the response (NULL if none)
 * @param responseDataLength  Length of response data
 * @param receivedMac     The 8-byte truncated MAC received from the tag
 * @return true if MAC matches
 */
bool secureMessaging_verifyResponseMac(uint8_t responseStatus,
                                       const uint8_t *responseData, size_t responseDataLength,
                                       const uint8_t *receivedMac) {
  uint8_t macInput[128];
  size_t position = 0;

  macInput[position++] = responseStatus;
  macInput[position++] = commandCounter & 0xFF;
  macInput[position++] = (commandCounter >> 8) & 0xFF;
  memcpy(macInput + position, transactionId, 4);
  position += 4;

  if (responseData != NULL && responseDataLength > 0) {
    memcpy(macInput + position, responseData, responseDataLength);
    position += responseDataLength;
  }

  uint8_t fullMac[16];
  aes_calculateCmac(sessionMacKey, macInput, position, fullMac);

  uint8_t expectedMac[8];
  for (int i = 0; i < 8; i++) {
    expectedMac[i] = fullMac[i * 2 + 1];
  }

  // Constant-time comparison
  uint8_t diff = 0;
  for (int i = 0; i < 8; i++) {
    diff |= expectedMac[i] ^ receivedMac[i];
  }

  secure_zero(macInput, sizeof(macInput));
  secure_zero(fullMac, 16);
  secure_zero(expectedMac, 8);

  return (diff == 0);
}

// =============================================================================
// NTAG 424 DNA COMMAND TRANSPORT
// =============================================================================

/**
 * Send a native NTAG 424 DNA command wrapped in ISO 7816-4 APDU.
 * Format: CLA=90, INS=cmd[0], P1=00, P2=00, Lc, Data, Le=00
 *
 * Response format: status byte + data
 * Status 0x00 = success, 0xAF = more frames, others = error
 */
bool ntag_sendCommand(uint8_t *command, uint8_t commandLength,
                      uint8_t *response, uint8_t *responseLength) {
  // Wrap native command in ISO 7816-4 APDU
  uint8_t apdu[128];
  uint8_t apduLength = 0;

  apdu[apduLength++] = 0x90;        // CLA (proprietary)
  apdu[apduLength++] = command[0];  // INS (native command code)
  apdu[apduLength++] = 0x00;        // P1
  apdu[apduLength++] = 0x00;        // P2

  if (commandLength > 1) {
    apdu[apduLength++] = commandLength - 1;  // Lc
    memcpy(apdu + apduLength, command + 1, commandLength - 1);
    apduLength += commandLength - 1;
  }

  apdu[apduLength++] = 0x00;  // Le

  // Send and receive
  uint8_t rawResponse[128];
  uint8_t rawResponseLength = sizeof(rawResponse);

  if (!nfc_sendApdu(apdu, apduLength, rawResponse, &rawResponseLength)) {
    return false;
  }

  if (rawResponseLength < 2) return false;

  // Parse SW1 SW2
  uint8_t sw1 = rawResponse[rawResponseLength - 2];
  uint8_t sw2 = rawResponse[rawResponseLength - 1];

  if (sw1 == 0x91) {
    // Native response: status = SW2, data = everything before SW
    response[0] = sw2;
    if (rawResponseLength > 2) {
      memcpy(response + 1, rawResponse, rawResponseLength - 2);
    }
    *responseLength = rawResponseLength - 1;
    return true;
  } else if (sw1 == 0x90 && sw2 == 0x00) {
    response[0] = 0x00;
    if (rawResponseLength > 2) {
      memcpy(response + 1, rawResponse, rawResponseLength - 2);
    }
    *responseLength = rawResponseLength - 1;
    return true;
  }

  response[0] = sw2;
  *responseLength = 1;
  return true;
}

// =============================================================================
// NTAG 424 DNA AUTHENTICATION (AuthenticateEV2First)
// =============================================================================

void rotateLeftByOneByte(uint8_t *data, size_t length) {
  uint8_t firstByte = data[0];
  memmove(data, data + 1, length - 1);
  data[length - 1] = firstByte;
}

/**
 * Perform EV2First authentication with the specified key slot.
 * On success, establishes session keys for secure messaging.
 */
bool ntag_authenticate(uint8_t keySlot, const uint8_t *key) {
  isAuthenticated = false;
  commandCounter = 0;

  // --- Part 1: Send auth request, receive encrypted RndB ---
  uint8_t authCommand[3] = { NTAG_AUTH_FIRST_PART1, keySlot, 0x00 };
  uint8_t response[64];
  uint8_t responseLength = sizeof(response);

  if (!ntag_sendCommand(authCommand, 3, response, &responseLength)) return false;
  if (response[0] != 0xAF || responseLength < 17) return false;

  // Decrypt RndB (AES-CBC, IV=0)
  uint8_t encryptedRndB[16];
  memcpy(encryptedRndB, response + 1, 16);

  uint8_t zeroIv[16] = { 0 };
  uint8_t rndB[16];
  aes_decryptCbc(key, zeroIv, encryptedRndB, rndB, 16);

  // --- Part 2: Generate RndA, send encrypted (RndA || RndB') ---
  uint8_t rndA[16];
  esp_fill_random(rndA, 16);

  uint8_t rndBrotated[16];
  memcpy(rndBrotated, rndB, 16);
  rotateLeftByOneByte(rndBrotated, 16);

  // Concatenate RndA || RndB'
  uint8_t challengeResponse[32];
  memcpy(challengeResponse, rndA, 16);
  memcpy(challengeResponse + 16, rndBrotated, 16);

  // Encrypt with IV=0
  uint8_t encryptIv[16] = { 0 };
  uint8_t encryptedChallenge[32];
  aes_encryptCbc(key, encryptIv, challengeResponse, encryptedChallenge, 32);

  // Send Part 2
  uint8_t part2Command[33];
  part2Command[0] = NTAG_AUTH_FIRST_PART2;
  memcpy(part2Command + 1, encryptedChallenge, 32);

  responseLength = sizeof(response);
  if (!ntag_sendCommand(part2Command, 33, response, &responseLength)) return false;
  if (response[0] != 0x00) return false;

  // --- Verify: Decrypt response and check RndA' ---
  uint8_t decryptIv[16] = { 0 };
  uint8_t decryptedResponse[32];
  aes_decryptCbc(key, decryptIv, response + 1, decryptedResponse, 32);

  // Response = TI(4) || RndA'(16) || PDcap2(6) || PCDcap2(6)
  uint8_t expectedRndA[16];
  memcpy(expectedRndA, rndA, 16);
  rotateLeftByOneByte(expectedRndA, 16);

  if (memcmp(decryptedResponse + 4, expectedRndA, 16) != 0) {
    return false;  // Tag failed to prove it knows the key
  }

  // Store Transaction Identifier
  memcpy(transactionId, decryptedResponse, 4);

  // --- Derive session keys ---
  // SessAuthENCKey = CMAC(Key, SV1)
  // SV1 = A5 5A || 00 01 || 00 80 || RndA[0:1] || (RndA[2:7] XOR RndB[0:5]) || RndB[6:15] || RndA[8:15]
  uint8_t sv1[32] = { 0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80 };
  sv1[6] = rndA[0];
  sv1[7] = rndA[1];
  for (int i = 0; i < 6; i++) sv1[8 + i] = rndA[2 + i] ^ rndB[i];
  memcpy(sv1 + 14, rndB + 6, 10);
  memcpy(sv1 + 24, rndA + 8, 8);
  aes_calculateCmac(key, sv1, 32, sessionEncryptionKey);

  // SessAuthMACKey = CMAC(Key, SV2)
  // SV2 = 5A A5 || 00 01 || 00 80 || (same structure as SV1)
  uint8_t sv2[32] = { 0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80 };
  sv2[6] = rndA[0];
  sv2[7] = rndA[1];
  for (int i = 0; i < 6; i++) sv2[8 + i] = rndA[2 + i] ^ rndB[i];
  memcpy(sv2 + 14, rndB + 6, 10);
  memcpy(sv2 + 24, rndA + 8, 8);
  aes_calculateCmac(key, sv2, 32, sessionMacKey);

  isAuthenticated = true;

  // Zero sensitive intermediates from stack
  secure_zero(rndA, 16);
  secure_zero(rndB, 16);
  secure_zero(rndBrotated, 16);
  secure_zero(challengeResponse, 32);
  secure_zero(encryptedChallenge, 32);
  secure_zero(sv1, 32);
  secure_zero(sv2, 32);

  return true;
}

// =============================================================================
// NTAG 424 DNA OPERATIONS
// =============================================================================

/**
 * CRC32 per NTAG 424 DNA spec (ISO 3309 / ITU-T V.42)
 */
uint32_t crc32(const uint8_t *data, size_t length) {
  uint32_t crc = 0xFFFFFFFF;
  for (size_t i = 0; i < length; i++) {
    crc ^= data[i];
    for (int bit = 0; bit < 8; bit++) {
      if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320;
      else crc >>= 1;
    }
  }
  return crc;
}

/**
 * Change a key on the tag (CommMode.Full: encrypt-then-MAC).
 * Must be authenticated with Key 0 (AppMasterKey).
 *
 * Per datasheet Table 63:
 *   Same key (keySlot == 0, the authenticated key):
 *     plaintext = NewKey(16) || KeyVersion(1) || ISO padding to 32 bytes
 *   Different key (keySlot 1-4):
 *     plaintext = (NewKey XOR OldKey)(16) || KeyVersion(1) || CRC32NK(4) || ISO padding to 32 bytes
 *
 * CRC32NK = IEEE Std 802.3-2008 FCS over NewKey (standard CRC32: init=0xFFFFFFFF, final XOR=0xFFFFFFFF)
 *
 * Command structure (CommMode.Full):
 *   CmdHeader = KeyNo (included in MAC, NOT encrypted)
 *   CmdData   = KeyData (encrypted)
 *   Command = ChangeKey(0xC4) || KeyNo || E(SesAuthENCKey, KeyData) || MACt(...)
 */
bool ntag_changeKey(uint8_t keySlot, const uint8_t *newKey, const uint8_t *oldKey) {
  if (!isAuthenticated) return false;

  uint8_t plaintext[32] = {0};
  size_t plaintextDataLength;

  bool isSameKey = (keySlot == KEY_SLOT_MASTER);

  if (isSameKey) {
    // Changing the key we authenticated with: NewKey || KeyVer
    memcpy(plaintext, newKey, 16);
    plaintext[16] = 0x01;  // Key version
    plaintextDataLength = 17;
  } else {
    // Changing a different key: (NewKey XOR OldKey) || KeyVer || CRC32(NewKey)
    for (int i = 0; i < 16; i++) {
      plaintext[i] = newKey[i] ^ oldKey[i];
    }
    plaintext[16] = 0x01;  // Key version

    // CRC32NK per NXP AN12196: JAMCRC (init=0xFFFFFFFF, poly=0xEDB88320, NO final XOR)
    // Verified: CRC32NK(F3847D627727ED3BC9C4CC050489B966) = DCFA9D78 stored as 78 9D FA DC (LSB first)
    uint32_t crc = 0xFFFFFFFF;
    for (int i = 0; i < 16; i++) {
      crc ^= newKey[i];
      for (int bit = 0; bit < 8; bit++) {
        if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320;
        else crc >>= 1;
      }
    }
    // NO final XOR — this is JAMCRC, not standard IEEE 802.3 CRC32

    // Store CRC32 LSB first
    plaintext[17] = (crc >> 0) & 0xFF;
    plaintext[18] = (crc >> 8) & 0xFF;
    plaintext[19] = (crc >> 16) & 0xFF;
    plaintext[20] = (crc >> 24) & 0xFF;

    plaintextDataLength = 21;
  }

  // ISO 9797-1 Method 2 padding: 0x80 then zeros to fill 32 bytes
  plaintext[plaintextDataLength] = 0x80;
  // Remaining bytes already zero from initialization
  size_t encryptedLength = 32;

  // Encrypt: IV = E(SesAuthENCKey, A55A || TI || CmdCtr || 0000000000000000)
  uint8_t iv[16];
  secureMessaging_calculateCommandIv(iv);

  uint8_t encryptedKeyData[32];
  aes_encryptCbc(sessionEncryptionKey, iv, plaintext, encryptedKeyData, encryptedLength);

  // MAC over: Cmd || CmdCtr || TI || CmdHeader(KeyNo) || EncryptedCmdData
  uint8_t macInput[64];
  size_t macInputLength = 0;
  macInput[macInputLength++] = NTAG_CHANGE_KEY;
  macInput[macInputLength++] = commandCounter & 0xFF;
  macInput[macInputLength++] = (commandCounter >> 8) & 0xFF;
  memcpy(macInput + macInputLength, transactionId, 4);
  macInputLength += 4;
  macInput[macInputLength++] = keySlot;  // CmdHeader
  memcpy(macInput + macInputLength, encryptedKeyData, encryptedLength);
  macInputLength += encryptedLength;

  uint8_t fullMac[16];
  aes_calculateCmac(sessionMacKey, macInput, macInputLength, fullMac);
  uint8_t truncatedMac[8];
  for (int i = 0; i < 8; i++) truncatedMac[i] = fullMac[i * 2 + 1];

  // Assemble: ChangeKey || KeyNo || EncData(32) || MAC(8) = 42 bytes total
  uint8_t command[42];
  command[0] = NTAG_CHANGE_KEY;
  command[1] = keySlot;
  memcpy(command + 2, encryptedKeyData, 32);
  memcpy(command + 34, truncatedMac, 8);

  uint8_t response[64];
  uint8_t responseLength = sizeof(response);
  if (!ntag_sendCommand(command, 42, response, &responseLength)) {
    secure_zero(plaintext, 32);
    secure_zero(encryptedKeyData, 32);
    return false;
  }

  commandCounter++;

  if (response[0] != 0x00) {
    Serial0.printf("(error: 0x%02X) ", response[0]);
    secure_zero(plaintext, 32);
    secure_zero(encryptedKeyData, 32);
    return false;
  }

  // Verify response MAC (8 bytes after status byte)
  if (responseLength >= 9) {
    if (!secureMessaging_verifyResponseMac(response[0], NULL, 0, response + 1)) {
      Serial0.println("  WARNING: Response MAC verification failed");
    }
  }

  secure_zero(plaintext, 32);
  secure_zero(encryptedKeyData, 32);
  return true;
}

/**
 * Change file access rights (CommMode.Full: encrypt-then-MAC).
 *
 * Per datasheet Section 10.7.1 / Figure 9 (CommMode.Full):
 *   CmdHeader = FileNo (goes into MAC but is NOT encrypted)
 *   CmdData   = FileOption(1) || AccessRights(2) (encrypted with ISO padding)
 *
 * FileOption byte:
 *   Bit 7: RFU (0)
 *   Bit 6: SDM enable (0=disabled)
 *   Bit 5-2: RFU (0000)
 *   Bit 1-0: CommMode (00=Plain, 01=MAC, 11=Full)
 *
 * AccessRights (2 bytes, LSB first):
 *   Bits 15-12: Read access condition
 *   Bits 11-8:  Write access condition
 *   Bits 7-4:   ReadWrite access condition
 *   Bits 3-0:   Change access condition
 */
bool ntag_changeFileSettings(uint8_t fileNumber, uint8_t commMode,
                             uint8_t readKey, uint8_t writeKey,
                             uint8_t readWriteKey, uint8_t changeKey) {
  if (!isAuthenticated) return false;

  // CmdData: FileOption(1) + AccessRights(2) = 3 bytes of real data
  // With ISO 9797-1 M2 padding: 3 + 1(0x80) + 12(zeros) = 16 bytes (one AES block)
  uint8_t plaintext[16] = { 0 };
  plaintext[0] = commMode & 0x03;  // FileOption: CommMode in bits 1-0, SDM disabled
  // AccessRights: 16-bit = Read(4)|Write(4)|RW(4)|Change(4), sent LSB first
  plaintext[1] = (readWriteKey << 4) | changeKey;   // LSB: RW(hi nibble) | Change(lo nibble)
  plaintext[2] = (readKey << 4) | writeKey;         // MSB: Read(hi nibble) | Write(lo nibble)
  plaintext[3] = 0x80;  // ISO 9797-1 M2 padding start
  // Bytes 4-15 remain zero (padding)

  // Encrypt CmdData
  uint8_t iv[16];
  secureMessaging_calculateCommandIv(iv);
  uint8_t encryptedData[16];
  aes_encryptCbc(sessionEncryptionKey, iv, plaintext, encryptedData, 16);

  // MAC over: Cmd || CmdCtr || TI || CmdHeader(FileNo) || E(CmdData)
  uint8_t macInput[32];
  size_t macLen = 0;
  macInput[macLen++] = NTAG_CHANGE_FILE_SETTINGS;
  macInput[macLen++] = commandCounter & 0xFF;
  macInput[macLen++] = (commandCounter >> 8) & 0xFF;
  memcpy(macInput + macLen, transactionId, 4);
  macLen += 4;
  macInput[macLen++] = fileNumber;  // CmdHeader — NOT encrypted
  memcpy(macInput + macLen, encryptedData, 16);
  macLen += 16;

  uint8_t fullMac[16];
  aes_calculateCmac(sessionMacKey, macInput, macLen, fullMac);
  uint8_t truncatedMac[8];
  for (int i = 0; i < 8; i++) truncatedMac[i] = fullMac[i * 2 + 1];

  // Assemble: ChangeFileSettings || FileNo || EncData(16) || MAC(8) = 26 bytes
  uint8_t command[26];
  command[0] = NTAG_CHANGE_FILE_SETTINGS;
  command[1] = fileNumber;
  memcpy(command + 2, encryptedData, 16);
  memcpy(command + 18, truncatedMac, 8);

  uint8_t response[64];
  uint8_t responseLength = sizeof(response);
  if (!ntag_sendCommand(command, 26, response, &responseLength)) return false;

  commandCounter++;
  if (response[0] != 0x00) {
    Serial0.printf("(error: 0x%02X) ", response[0]);
    return false;
  }

  // Verify response MAC
  if (responseLength >= 9) {
    if (!secureMessaging_verifyResponseMac(response[0], NULL, 0, response + 1)) {
      Serial0.println("  WARNING: ChangeFileSettings response MAC failed");
    }
  }

  return true;
}

/**
 * Write data to a file with CommMode.MAC (MAC on command, MAC on response).
 *
 * Per datasheet Section 10.8.2 / Figure 8 (CommMode.MAC):
 *   CmdHeader = FileNo(1) || Offset(3) || Length(3)
 *   CmdData   = Data (plain, not encrypted)
 *   Command = WriteData || CmdHeader || CmdData || MACt(SesAuthMACKey, Cmd||CmdCtr||TI||CmdHeader||CmdData)
 *
 * Use this when the file CommMode is set to MAC (0x01).
 */
bool ntag_writeDataMac(uint8_t fileNumber, const uint8_t *data, size_t dataLength) {
  if (!isAuthenticated) return false;

  // CmdHeader: FileNo(1) + Offset(3) + Length(3) = 7 bytes
  uint8_t cmdHeader[7];
  cmdHeader[0] = fileNumber;
  cmdHeader[1] = 0x00; cmdHeader[2] = 0x00; cmdHeader[3] = 0x00;  // Offset = 0
  cmdHeader[4] = dataLength & 0xFF;
  cmdHeader[5] = (dataLength >> 8) & 0xFF;
  cmdHeader[6] = (dataLength >> 16) & 0xFF;

  // MAC over: Cmd || CmdCtr || TI || CmdHeader || CmdData
  uint8_t macInput[96];
  size_t macLen = 0;
  macInput[macLen++] = NTAG_WRITE_DATA;
  macInput[macLen++] = commandCounter & 0xFF;
  macInput[macLen++] = (commandCounter >> 8) & 0xFF;
  memcpy(macInput + macLen, transactionId, 4); macLen += 4;
  memcpy(macInput + macLen, cmdHeader, 7); macLen += 7;
  memcpy(macInput + macLen, data, dataLength); macLen += dataLength;

  uint8_t fullMac[16];
  aes_calculateCmac(sessionMacKey, macInput, macLen, fullMac);
  uint8_t truncatedMac[8];
  for (int i = 0; i < 8; i++) truncatedMac[i] = fullMac[i * 2 + 1];

  // Assemble: WriteData || CmdHeader(7) || Data || MAC(8)
  uint8_t command[80];
  command[0] = NTAG_WRITE_DATA;
  memcpy(command + 1, cmdHeader, 7);
  memcpy(command + 8, data, dataLength);
  memcpy(command + 8 + dataLength, truncatedMac, 8);
  uint8_t totalLen = 1 + 7 + dataLength + 8;

  uint8_t response[64];
  uint8_t responseLength = sizeof(response);
  if (!ntag_sendCommand(command, totalLen, response, &responseLength)) return false;

  commandCounter++;
  if (response[0] != 0x00) {
    Serial0.printf("(error: 0x%02X) ", response[0]);
    return false;
  }

  // Verify response MAC
  if (responseLength >= 9) {
    if (!secureMessaging_verifyResponseMac(response[0], NULL, 0, response + 1)) {
      Serial0.println("  WARNING: Write response MAC verification failed");
    }
  }

  return true;
}

/**
 * Write data to a file with CommMode.Full (encrypt data + MAC).
 *
 * Per datasheet Figure 9 (CommMode.Full):
 *   CmdHeader = FileNo(1) || Offset(3) || Length(3) (NOT encrypted, included in MAC)
 *   CmdData   = Data (encrypted with ISO padding)
 *   Command = WriteData || CmdHeader || E(SesAuthENCKey, Data||Padding) || MACt(...)
 */
bool ntag_writeDataFull(uint8_t fileNumber, const uint8_t *data, size_t dataLength) {
  if (!isAuthenticated) return false;

  // CmdHeader: FileNo(1) + Offset(3) + Length(3) = 7 bytes
  uint8_t cmdHeader[7];
  cmdHeader[0] = fileNumber;
  cmdHeader[1] = 0x00; cmdHeader[2] = 0x00; cmdHeader[3] = 0x00;
  cmdHeader[4] = dataLength & 0xFF;
  cmdHeader[5] = (dataLength >> 8) & 0xFF;
  cmdHeader[6] = (dataLength >> 16) & 0xFF;

  // Pad data: ISO 9797-1 M2 (0x80 + zeros to multiple of 16)
  size_t paddedLen = ((dataLength + 1 + 15) / 16) * 16;
  uint8_t paddedData[48] = {0};  // Max: 16 bytes data + padding = 32 bytes
  memcpy(paddedData, data, dataLength);
  paddedData[dataLength] = 0x80;
  // Remaining already zero

  // Encrypt CmdData
  uint8_t iv[16];
  secureMessaging_calculateCommandIv(iv);
  uint8_t encryptedData[48];
  aes_encryptCbc(sessionEncryptionKey, iv, paddedData, encryptedData, paddedLen);

  // MAC over: Cmd || CmdCtr || TI || CmdHeader || E(CmdData)
  uint8_t macInput[96];
  size_t macLen = 0;
  macInput[macLen++] = NTAG_WRITE_DATA;
  macInput[macLen++] = commandCounter & 0xFF;
  macInput[macLen++] = (commandCounter >> 8) & 0xFF;
  memcpy(macInput + macLen, transactionId, 4); macLen += 4;
  memcpy(macInput + macLen, cmdHeader, 7); macLen += 7;
  memcpy(macInput + macLen, encryptedData, paddedLen); macLen += paddedLen;

  uint8_t fullMac[16];
  aes_calculateCmac(sessionMacKey, macInput, macLen, fullMac);
  uint8_t truncatedMac[8];
  for (int i = 0; i < 8; i++) truncatedMac[i] = fullMac[i * 2 + 1];

  // Assemble: WriteData || CmdHeader(7) || EncData || MAC(8)
  uint8_t command[80];
  command[0] = NTAG_WRITE_DATA;
  memcpy(command + 1, cmdHeader, 7);
  memcpy(command + 8, encryptedData, paddedLen);
  memcpy(command + 8 + paddedLen, truncatedMac, 8);
  uint8_t totalLen = 1 + 7 + paddedLen + 8;

  uint8_t response[64];
  uint8_t responseLength = sizeof(response);
  if (!ntag_sendCommand(command, totalLen, response, &responseLength)) return false;

  commandCounter++;
  if (response[0] != 0x00) {
    Serial0.printf("(error: 0x%02X) ", response[0]);
    return false;
  }

  // Verify response MAC
  if (responseLength >= 9) {
    if (!secureMessaging_verifyResponseMac(response[0], NULL, 0, response + 1)) {
      Serial0.println("  WARNING: Write response MAC verification failed");
    }
  }

  return true;
}

/**
 * Write data to a file (CommMode.Plain, but with command counter increment when authenticated).
 *
 * Per datasheet Section 9.1.8: In authenticated state, even for CommMode.Plain,
 * the command counter still increments. No MAC or encryption is applied to the data.
 */
bool ntag_writeDataPlain(uint8_t fileNumber, const uint8_t *data, size_t dataLength) {
  // Assemble plain WriteData command (no MAC, no encryption)
  uint8_t command[64];
  size_t pos = 0;
  command[pos++] = NTAG_WRITE_DATA;
  command[pos++] = fileNumber;
  command[pos++] = 0x00; command[pos++] = 0x00; command[pos++] = 0x00;  // Offset
  command[pos++] = dataLength & 0xFF;
  command[pos++] = (dataLength >> 8) & 0xFF;
  command[pos++] = (dataLength >> 16) & 0xFF;
  memcpy(command + pos, data, dataLength);
  pos += dataLength;

  uint8_t response[64];
  uint8_t responseLength = sizeof(response);
  if (!ntag_sendCommand(command, pos, response, &responseLength)) return false;

  if (isAuthenticated) commandCounter++;

  if (response[0] != 0x00) {
    Serial0.printf("(error: 0x%02X) ", response[0]);
    return false;
  }

  return true;
}

/**
 * Read data from a file (CommMode.Plain with MAC).
 */
bool ntag_readData(uint8_t fileNumber, uint8_t *outputBuffer, size_t readLength) {
  if (!isAuthenticated) return false;

  uint8_t commandData[7];
  size_t position = 0;
  commandData[position++] = fileNumber;
  commandData[position++] = 0x00;
  commandData[position++] = 0x00;
  commandData[position++] = 0x00;
  commandData[position++] = readLength & 0xFF;
  commandData[position++] = (readLength >> 8) & 0xFF;
  commandData[position++] = (readLength >> 16) & 0xFF;

  uint8_t truncatedMac[8];
  secureMessaging_calculateMac(NTAG_READ_DATA, commandData, position, truncatedMac);

  uint8_t command[16];
  command[0] = NTAG_READ_DATA;
  memcpy(command + 1, commandData, position);
  memcpy(command + 1 + position, truncatedMac, 8);

  uint8_t response[64];
  uint8_t responseLength = sizeof(response);
  if (!ntag_sendCommand(command, 1 + position + 8, response, &responseLength)) {
    Serial0.println("(send failed) ");
    return false;
  }

  commandCounter++;
  if (response[0] != 0x00) {
    Serial0.printf("(error: 0x%02X) ", response[0]);
    return false;
  }

  // Response layout: status(1) + data(readLength) + MAC(8)
  size_t availableData = responseLength - 1;

  if (availableData >= readLength + 8) {
    // We have data + MAC — verify the MAC
    const uint8_t *responseData = response + 1;
    const uint8_t *responseMac = response + 1 + readLength;

    if (!secureMessaging_verifyResponseMac(response[0], responseData, readLength, responseMac)) {
      Serial0.println("  WARNING: Read response MAC verification failed");
      return false;
    }

    memcpy(outputBuffer, responseData, readLength);
    return true;
  } else if (availableData >= readLength) {
    // No MAC in response (plain mode) — accept data without verification
    memcpy(outputBuffer, response + 1, readLength);
    return true;
  }

  return false;
}

/**
 * Read data from a file with CommMode.Full (encrypted response + MAC).
 *
 * Per datasheet Figure 9 (CommMode.Full response):
 *   Response = RC(1) || E(SesAuthENCKey, Data||Padding) || MACt(8)
 *   Response IV uses the INCREMENTED CmdCtr (after tag accepted the command).
 *   Response IV = E(SesAuthENCKey, 5AA5 || TI || CmdCtr || 0000000000000000)
 *
 * Command is sent with CommMode.Full:
 *   CmdHeader = FileNo(1) || Offset(3) || Length(3)
 *   No CmdData for ReadData, so command is: Cmd || CmdHeader || MACt
 */
bool ntag_readDataFull(uint8_t fileNumber, uint8_t *outputBuffer, size_t readLength) {
  if (!isAuthenticated) return false;

  // CmdHeader: FileNo(1) + Offset(3) + Length(3) = 7 bytes
  uint8_t cmdHeader[7];
  cmdHeader[0] = fileNumber;
  cmdHeader[1] = 0x00; cmdHeader[2] = 0x00; cmdHeader[3] = 0x00;
  cmdHeader[4] = readLength & 0xFF;
  cmdHeader[5] = (readLength >> 8) & 0xFF;
  cmdHeader[6] = (readLength >> 16) & 0xFF;

  // MAC over: Cmd || CmdCtr || TI || CmdHeader (no CmdData for read)
  uint8_t macInput[32];
  size_t macLen = 0;
  macInput[macLen++] = NTAG_READ_DATA;
  macInput[macLen++] = commandCounter & 0xFF;
  macInput[macLen++] = (commandCounter >> 8) & 0xFF;
  memcpy(macInput + macLen, transactionId, 4); macLen += 4;
  memcpy(macInput + macLen, cmdHeader, 7); macLen += 7;

  uint8_t fullMac[16];
  aes_calculateCmac(sessionMacKey, macInput, macLen, fullMac);
  uint8_t truncatedMac[8];
  for (int i = 0; i < 8; i++) truncatedMac[i] = fullMac[i * 2 + 1];

  // Assemble: ReadData || CmdHeader(7) || MAC(8) = 16 bytes
  uint8_t command[16];
  command[0] = NTAG_READ_DATA;
  memcpy(command + 1, cmdHeader, 7);
  memcpy(command + 8, truncatedMac, 8);

  uint8_t response[64];
  uint8_t responseLength = sizeof(response);
  if (!ntag_sendCommand(command, 16, response, &responseLength)) return false;

  commandCounter++;  // Incremented BEFORE response processing
  if (response[0] != 0x00) {
    Serial0.printf("(error: 0x%02X) ", response[0]);
    return false;
  }

  // Response: status(1) || E(Data||Padding)(encLen) || MAC(8)
  // For 16 bytes of data + ISO padding = 32 bytes encrypted
  size_t encLen = ((readLength + 1 + 15) / 16) * 16;  // padded to AES block boundary
  size_t expectedRespLen = 1 + encLen + 8;  // status + encrypted + MAC

  if (responseLength < expectedRespLen) {
    Serial0.printf("(short resp: %d < %d) ", responseLength, expectedRespLen);
    return false;
  }

  const uint8_t *encryptedData = response + 1;
  const uint8_t *responseMac = response + 1 + encLen;

  // Verify response MAC: MAC(SessMACKey, RC || CmdCtr || TI || EncData)
  if (!secureMessaging_verifyResponseMac(response[0], encryptedData, encLen, responseMac)) {
    Serial0.println("  WARNING: Read response MAC verification failed");
    return false;
  }

  // Decrypt response data
  // Response IV = E(SesAuthENCKey, 5A A5 || TI || CmdCtr || 0000000000000000)
  // Note: CmdCtr here is the ALREADY INCREMENTED value
  uint8_t respIvInput[16] = { 0 };
  respIvInput[0] = 0x5A;
  respIvInput[1] = 0xA5;
  memcpy(respIvInput + 2, transactionId, 4);
  respIvInput[6] = commandCounter & 0xFF;
  respIvInput[7] = (commandCounter >> 8) & 0xFF;

  uint8_t respIv[16];
  aes_encryptEcb(sessionEncryptionKey, respIvInput, respIv);

  uint8_t decrypted[48];
  aes_decryptCbc(sessionEncryptionKey, respIv, encryptedData, decrypted, encLen);

  // Copy the actual data (strip padding)
  memcpy(outputBuffer, decrypted, readLength);
  secure_zero(decrypted, sizeof(decrypted));

  return true;
}

// =============================================================================
// NVS DATABASE
// =============================================================================

String uidToHexString(const uint8_t *uid, uint8_t length) {
  String result = "";
  for (uint8_t i = 0; i < length; i++) {
    if (uid[i] < 0x10) result += "0";
    result += String(uid[i], HEX);
  }
  result.toUpperCase();
  return result;
}

void db_storeTag(const uint8_t *uid, uint8_t uidLength,
                 const uint8_t *masterKey, const uint8_t *readKey,
                 const uint8_t *writeKey, const uint8_t *secret) {
  String nvsKey = uidToHexString(uid, uidLength);

  uint8_t record[NVS_RECORD_SIZE];
  memcpy(record, masterKey, 16);
  memcpy(record + 16, readKey, 16);
  memcpy(record + 32, writeKey, 16);
  memcpy(record + 48, secret, 16);

  storage.begin("ntag", false);
  storage.putBytes(nvsKey.c_str(), record, NVS_RECORD_SIZE);

  // Maintain UID index (8 bytes per entry: 1 byte length + 7 bytes UID padded)
  size_t indexSize = storage.getBytesLength("uids");
  uint8_t *indexBuffer = (uint8_t *)malloc(indexSize + 8);
  if (indexBuffer == NULL) {
    Serial0.println("ERROR: Out of memory (db_storeTag)");
    storage.end();
    return;
  }

  if (indexSize > 0) {
    storage.getBytes("uids", indexBuffer, indexSize);
    // Check if UID already exists in index
    for (size_t i = 0; i < indexSize; i += 8) {
      if (indexBuffer[i] == uidLength && memcmp(indexBuffer + i + 1, uid, uidLength) == 0) {
        free(indexBuffer);
        storage.end();
        return;  // Already indexed
      }
    }
  }

  // Append new entry to index
  indexBuffer[indexSize] = uidLength;
  memset(indexBuffer + indexSize + 1, 0, 7);
  memcpy(indexBuffer + indexSize + 1, uid, uidLength);
  storage.putBytes("uids", indexBuffer, indexSize + 8);

  free(indexBuffer);
  storage.end();
}

bool db_loadTag(const uint8_t *uid, uint8_t uidLength,
                uint8_t *masterKey, uint8_t *readKey,
                uint8_t *writeKey, uint8_t *secret) {
  String nvsKey = uidToHexString(uid, uidLength);

  uint8_t record[NVS_RECORD_SIZE];
  storage.begin("ntag", true);
  size_t bytesRead = storage.getBytes(nvsKey.c_str(), record, NVS_RECORD_SIZE);
  storage.end();

  if (bytesRead != NVS_RECORD_SIZE) return false;

  memcpy(masterKey, record, 16);
  memcpy(readKey, record + 16, 16);
  memcpy(writeKey, record + 32, 16);
  memcpy(secret, record + 48, 16);
  return true;
}

bool db_tagExists(const uint8_t *uid, uint8_t uidLength) {
  String nvsKey = uidToHexString(uid, uidLength);
  storage.begin("ntag", true);
  bool exists = storage.isKey(nvsKey.c_str());
  storage.end();
  return exists;
}

uint32_t db_getTagCount() {
  storage.begin("ntag", true);
  size_t indexSize = storage.getBytesLength("uids");
  storage.end();
  return indexSize / 8;
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Securely zero sensitive memory. Uses volatile to prevent compiler optimization.
 */
void secure_zero(void *buffer, size_t length) {
  volatile uint8_t *p = (volatile uint8_t *)buffer;
  while (length--) *p++ = 0;
}

void printHex(const char *label, const uint8_t *data, size_t length) {
  Serial0.printf("%s: ", label);
  for (size_t i = 0; i < length; i++) Serial0.printf("%02X", data[i]);
  Serial0.println();
}

String readSerialLine() {
  String line = "";
  uint32_t startTime = millis();
  while (millis() - startTime < 30000) {  // 30 second timeout
    if (Serial0.available()) {
      char c = Serial0.read();
      if (c == '\n' || c == '\r') {
        if (line.length() > 0) return line;
      } else {
        line += c;
      }
    }
    delay(10);
  }
  return line;
}

uint8_t hexCharToValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return 0xFF;
}

bool parseHexString(const String &hexString, uint8_t *output, size_t expectedBytes) {
  if (hexString.length() != expectedBytes * 2) return false;
  for (size_t i = 0; i < expectedBytes; i++) {
    uint8_t highNibble = hexCharToValue(hexString.charAt(i * 2));
    uint8_t lowNibble = hexCharToValue(hexString.charAt(i * 2 + 1));
    if (highNibble == 0xFF || lowNibble == 0xFF) return false;
    output[i] = (highNibble << 4) | lowNibble;
  }
  return true;
}

// =============================================================================
// PROGRAM MODE
// =============================================================================

/**
 * Provision keys, file settings, and write secret to an already-authenticated tag.
 *
 * Prerequisites:
 *   - Tag is already authenticated with Key 0 (masterKey)
 *   - commandCounter and session keys are valid
 *
 * Flow (all in a single authenticated session with Key 0):
 *   1. ChangeKey(Key 1) — XOR'd with oldReadKey, CRC32 over newKey
 *   2. ChangeKey(Key 2) — XOR'd with oldWriteKey, CRC32 over newKey
 *   3. ChangeFileSettings — unlock: set Write=Free so we can write
 *   4. Write secret — plain write (file has Write=Free)
 *   5. ChangeFileSettings — lock down: Read=Key1, Write=Key2, RW=Key2, Change=Key0
 *
 * Per datasheet: ChangeKey requires auth with AppMasterKey (Key 0).
 * No need to re-authenticate between key changes — the session remains valid.
 * The commandCounter increments after each successful command.
 */
void provisionTagKeys(uint8_t *uid, uint8_t uidLength,
                      uint8_t *masterKey, uint8_t *readKey,
                      uint8_t *writeKey, uint8_t *secret,
                      const uint8_t *oldReadKey, const uint8_t *oldWriteKey) {
  bool key1Changed = false;
  bool key2Changed = false;
  bool secretWritten = false;

  // Step 1: Change Key 1 (read key)
  // We're already authenticated with Key 0; ChangeKey for a different key uses
  // (NewKey XOR OldKey) || KeyVer || CRC32(NewKey) format
  Serial0.print("[4] Change Key 1 (read)... ");
  if (ntag_changeKey(KEY_SLOT_READ, readKey, oldReadKey)) {
    Serial0.println("OK");
    key1Changed = true;
  } else {
    Serial0.println("FAILED");
  }

  // Step 2: Change Key 2 (write key)
  // Still in the same session, commandCounter has incremented
  Serial0.print("[5] Change Key 2 (write)... ");
  if (ntag_changeKey(KEY_SLOT_WRITE, writeKey, oldWriteKey)) {
    Serial0.println("OK");
    key2Changed = true;
  } else {
    Serial0.println("FAILED");
  }

  // Step 3: Temporarily set file to Full+Free so we can write the secret
  // On fresh tags, Write is already E (free), so this just sets CommMode.Full.
  // Per datasheet Section 8.2.3.3: CommMode is only applied when the satisfied
  // access condition is a KEY (not free access 0xE). With Write=Key0 and us
  // authenticated as Key0, CommMode.Full is enforced → encrypted write works.
  Serial0.print("[6] Unlock file for write... ");
  if (ntag_changeFileSettings(SECRET_FILE_NUMBER, 0x03, 0x0E, KEY_SLOT_MASTER, KEY_SLOT_MASTER, KEY_SLOT_MASTER)) {
    Serial0.println("OK");
  } else {
    Serial0.println("SKIPPED (may already be unlocked)");
  }

  // Step 4: Write secret encrypted (CommMode.Full, Write=Key0, authed as Key0)
  Serial0.print("[7] Write secret... ");
  if (ntag_writeDataFull(SECRET_FILE_NUMBER, secret, SECRET_LENGTH)) {
    Serial0.println("OK");
    secretWritten = true;
  } else {
    Serial0.println("FAILED");
  }

  // Step 5: Set final file access rights with CommMode.Full (encrypted + MAC)
  // Read=Key1, Write=Key2, RW=Key2, Change=Key0, CommMode=Full(0x03)
  // This ensures the secret is encrypted on the air during ReadData/WriteData.
  Serial0.print("[8] Lock file (Full encryption)... ");
  if (ntag_changeFileSettings(SECRET_FILE_NUMBER, 0x03,
                               KEY_SLOT_READ, KEY_SLOT_WRITE,
                               KEY_SLOT_WRITE, KEY_SLOT_MASTER)) {
    Serial0.println("OK");
  } else {
    Serial0.println("FAILED");
  }

  // Store in NVS
  uint8_t storedKey1[16], storedKey2[16], storedSecret[16];
  memcpy(storedKey1, key1Changed ? readKey : oldReadKey, 16);
  memcpy(storedKey2, key2Changed ? writeKey : oldWriteKey, 16);
  if (secretWritten) {
    memcpy(storedSecret, secret, 16);
  } else {
    // Secret write failed — preserve the old secret from DB if it exists
    uint8_t oldMk[16], oldRk[16], oldWk[16], oldSecret[16];
    if (db_loadTag(uid, uidLength, oldMk, oldRk, oldWk, oldSecret)) {
      memcpy(storedSecret, oldSecret, 16);
      secure_zero(oldMk, 16);
      secure_zero(oldRk, 16);
      secure_zero(oldWk, 16);
      secure_zero(oldSecret, 16);
    } else {
      memset(storedSecret, 0, 16);  // No previous record — nothing to preserve
    }
  }

  db_storeTag(uid, uidLength, masterKey, storedKey1, storedKey2, storedSecret);

  Serial0.println("\n--- PROVISIONING RESULT ---");
  printHex("  Key 0 (master)", masterKey, 16);
  if (key1Changed) printHex("  Key 1 (read)", readKey, 16);
  else Serial0.println("  Key 1 (read): UNCHANGED");
  if (key2Changed) printHex("  Key 2 (write)", writeKey, 16);
  else Serial0.println("  Key 2 (write): UNCHANGED");
  if (secretWritten) printHex("  Secret", secret, 16);
  else Serial0.println("  Secret: NOT WRITTEN");
  Serial0.printf("  Tags in DB: %d\n", db_getTagCount());
  Serial0.println("╚══════════════════╝\n");
}

void handleProgramMode(uint8_t *uid, uint8_t uidLength) {
  Serial0.println("\n╔══ PROGRAM MODE ══╗");
  printHex("UID", uid, uidLength);

  // Generate random keys and secret
  uint8_t newMasterKey[16], newReadKey[16], newWriteKey[16], newSecret[16];
  esp_fill_random(newMasterKey, 16);
  esp_fill_random(newReadKey, 16);
  esp_fill_random(newWriteKey, 16);
  esp_fill_random(newSecret, 16);

  // ---------------------------------------------------------------
  // PATH A: Tag already in database — re-programming
  // ---------------------------------------------------------------
  if (db_tagExists(uid, uidLength)) {
    Serial0.println("\n⚠ TAG ALREADY IN DATABASE!");
    Serial0.println("  [F] Full re-program (all new keys + secret)");
    Serial0.println("  [R] Rotate (keep Key0, new Key1 + Key2 + secret)");
    Serial0.println("  [N] Cancel");
    Serial0.print("> ");
    String choice = readSerialLine();
    Serial0.println(choice);

    char option = (choice.length() > 0) ? toupper(choice.charAt(0)) : 'N';
    if (option != 'F' && option != 'R') {
      Serial0.println("Cancelled.");
      Serial0.println("╚══════════════════╝\n");
      return;
    }

    // Re-detect tag after user interaction
    Serial0.println("Tap tag again...");
    uint8_t retryUid[7];
    uint8_t retryUidLength;
    bool tagFound = false;
    uint32_t startTime = millis();
    while (millis() - startTime < 10000) {
      if (nfc_findTag(retryUid, &retryUidLength)) {
        if (retryUidLength == uidLength && memcmp(retryUid, uid, uidLength) == 0) {
          if (nfc_selectNtagApp()) {
            tagFound = true;
            break;
          }
        }
      }
      delay(200);
    }
    if (!tagFound) {
      Serial0.println("Tag not found. Cancelled.");
      Serial0.println("╚══════════════════╝\n");
      return;
    }

    // Load stored keys
    uint8_t storedMasterKey[16], storedReadKey[16], storedWriteKey[16], storedSecret[16];
    db_loadTag(uid, uidLength, storedMasterKey, storedReadKey, storedWriteKey, storedSecret);

    // Authenticate with stored master key
    Serial0.print("[1] Authenticating (stored key)... ");
    if (!ntag_authenticate(KEY_SLOT_MASTER, storedMasterKey)) {
      Serial0.println("FAILED");
      Serial0.println("╚══════════════════╝\n");
      return;
    }
    Serial0.println("OK");

    if (option == 'F') {
      // Full: change Key 0 to new random
      Serial0.print("[2] Change Key 0 (master)... ");
      if (!ntag_changeKey(KEY_SLOT_MASTER, newMasterKey, storedMasterKey)) {
        Serial0.println("FAILED");
        Serial0.println("╚══════════════════╝\n");
        return;
      }
      Serial0.println("OK");

      Serial0.print("[3] Re-authenticating... ");
      if (!ntag_authenticate(KEY_SLOT_MASTER, newMasterKey)) {
        Serial0.println("FAILED — key may be lost!");
        Serial0.println("╚══════════════════╝\n");
        return;
      }
      Serial0.println("OK");

      // Apply remaining keys (old keys for XOR are the stored ones)
      provisionTagKeys(uid, uidLength, newMasterKey, newReadKey, newWriteKey, newSecret,
                       storedReadKey, storedWriteKey);
    } else {
      // Rotate: keep existing Key 0, change Key 1/2/secret
      memcpy(newMasterKey, storedMasterKey, 16);
      provisionTagKeys(uid, uidLength, newMasterKey, newReadKey, newWriteKey, newSecret,
                       storedReadKey, storedWriteKey);
    }
    return;
  }

  // ---------------------------------------------------------------
  // PATH B: Fresh tag — full provisioning
  // ---------------------------------------------------------------
  Serial0.print("[1] Authenticating (factory key)... ");
  if (!ntag_authenticate(KEY_SLOT_MASTER, FACTORY_KEY)) {
    // Last resort: check if tag was already programmed but DB was erased
    if (db_tagExists(uid, uidLength)) {
      uint8_t sk[16], rk[16], wk[16], ss[16];
      db_loadTag(uid, uidLength, sk, rk, wk, ss);
      if (ntag_authenticate(KEY_SLOT_MASTER, sk)) {
        Serial0.println("OK (stored key)");
        memcpy(newMasterKey, sk, 16);
        provisionTagKeys(uid, uidLength, newMasterKey, newReadKey, newWriteKey, newSecret,
                         rk, wk);
        return;
      }
    }
    Serial0.println("FAILED");
    Serial0.println("╚══════════════════╝\n");
    return;
  }
  Serial0.println("OK");

  // Change Key 0 to new random
  Serial0.print("[2] Change Key 0 (master)... ");
  if (!ntag_changeKey(KEY_SLOT_MASTER, newMasterKey, FACTORY_KEY)) {
    Serial0.println("FAILED");
    Serial0.println("╚══════════════════╝\n");
    return;
  }
  Serial0.println("OK");

  // Re-authenticate with new Key 0
  Serial0.print("[3] Re-authenticating... ");
  if (!ntag_authenticate(KEY_SLOT_MASTER, newMasterKey)) {
    Serial0.println("FAILED — key may be lost!");
    Serial0.println("╚══════════════════╝\n");
    return;
  }
  Serial0.println("OK");

  // Apply remaining keys (old keys are factory default = all zeros)
  const uint8_t factoryKey[16] = { 0 };
  provisionTagKeys(uid, uidLength, newMasterKey, newReadKey, newWriteKey, newSecret,
                   factoryKey, factoryKey);

  // Zero key material from stack
  secure_zero(newMasterKey, 16);
  secure_zero(newReadKey, 16);
  secure_zero(newWriteKey, 16);
  secure_zero(newSecret, 16);
}

// =============================================================================
// RESET TAG FILE SETTINGS
// =============================================================================

void handleResetMode(uint8_t *uid, uint8_t uidLength) {
  Serial0.println("\n╔══ RESET FILE SETTINGS ══╗");
  printHex("UID", uid, uidLength);

  // Load stored master key
  uint8_t masterKey[16], k1[16], k2[16], secret[16];
  if (!db_loadTag(uid, uidLength, masterKey, k1, k2, secret)) {
    Serial0.println("Tag not in database — trying factory key");
    memset(masterKey, 0, 16);
  }

  // Authenticate with Key 0
  Serial0.print("[1] Auth (Key 0)... ");
  if (!ntag_authenticate(KEY_SLOT_MASTER, masterKey)) {
    // Try factory key
    if (!ntag_authenticate(KEY_SLOT_MASTER, FACTORY_KEY)) {
      Serial0.println("FAILED");
      Serial0.println("╚═════════════════════════╝\n");
      return;
    }
  }
  Serial0.println("OK");

  // Reset file settings to factory: Read=Free(E), Write=Free(E), RW=Free(E), Change=Key0(0)
  // AccessRights = 0xEEE0 → LSB first: byte1=0xE0, byte2=0xEE
  Serial0.print("[2] Resetting file settings to factory... ");
  
  uint8_t plaintext[16] = {0};
  plaintext[0] = 0x00;   // CommMode.Plain
  plaintext[1] = 0xE0;   // LSB: RW=E(free) | Change=0(Key0)
  plaintext[2] = 0xEE;   // MSB: Read=E(free) | Write=E(free)
  plaintext[3] = 0x80;   // ISO padding

  uint8_t iv[16];
  secureMessaging_calculateCommandIv(iv);
  uint8_t encSettings[16];
  aes_encryptCbc(sessionEncryptionKey, iv, plaintext, encSettings, 16);

  // MAC over: Cmd || CmdCtr || TI || FileNo || EncSettings
  uint8_t macInput[32];
  size_t macLen = 0;
  macInput[macLen++] = NTAG_CHANGE_FILE_SETTINGS;
  macInput[macLen++] = commandCounter & 0xFF;
  macInput[macLen++] = (commandCounter >> 8) & 0xFF;
  memcpy(macInput + macLen, transactionId, 4); macLen += 4;
  macInput[macLen++] = SECRET_FILE_NUMBER;
  memcpy(macInput + macLen, encSettings, 16); macLen += 16;
  
  uint8_t fullMac[16];
  aes_calculateCmac(sessionMacKey, macInput, macLen, fullMac);
  uint8_t mac8[8];
  for (int i = 0; i < 8; i++) mac8[i] = fullMac[i * 2 + 1];

  uint8_t cmd[26];
  cmd[0] = NTAG_CHANGE_FILE_SETTINGS;
  cmd[1] = SECRET_FILE_NUMBER;
  memcpy(cmd + 2, encSettings, 16);
  memcpy(cmd + 18, mac8, 8);

  uint8_t resp[64]; uint8_t respLen = sizeof(resp);
  if (ntag_sendCommand(cmd, 26, resp, &respLen) && resp[0] == 0x00) {
    Serial0.println("OK — file settings reset to factory!");
    commandCounter++;
  } else {
    Serial0.printf("FAILED (0x%02X)\n", resp[0]);
    Serial0.println("  File change access may require a different key.");
    
    // Try with each key 1-4
    for (int k = 1; k <= 4; k++) {
      uint8_t tryKey[16];
      if (k == 1) memcpy(tryKey, k1, 16);
      else if (k == 2) memcpy(tryKey, k2, 16);
      else memset(tryKey, 0, 16);
      
      Serial0.printf("  Trying Key %d... ", k);
      if (ntag_authenticate(k, tryKey)) {
        // Recalculate IV and MAC with new session
        secureMessaging_calculateCommandIv(iv);
        aes_encryptCbc(sessionEncryptionKey, iv, plaintext, encSettings, 16);
        
        macLen = 0;
        macInput[macLen++] = NTAG_CHANGE_FILE_SETTINGS;
        macInput[macLen++] = commandCounter & 0xFF;
        macInput[macLen++] = (commandCounter >> 8) & 0xFF;
        memcpy(macInput + macLen, transactionId, 4); macLen += 4;
        macInput[macLen++] = SECRET_FILE_NUMBER;
        memcpy(macInput + macLen, encSettings, 16); macLen += 16;
        aes_calculateCmac(sessionMacKey, macInput, macLen, fullMac);
        for (int i = 0; i < 8; i++) mac8[i] = fullMac[i * 2 + 1];
        
        cmd[0] = NTAG_CHANGE_FILE_SETTINGS;
        cmd[1] = SECRET_FILE_NUMBER;
        memcpy(cmd + 2, encSettings, 16);
        memcpy(cmd + 18, mac8, 8);
        
        respLen = sizeof(resp);
        if (ntag_sendCommand(cmd, 26, resp, &respLen) && resp[0] == 0x00) {
          Serial0.println("OK — RESET!");
          commandCounter++;
          break;
        } else {
          Serial0.printf("FAILED (0x%02X)\n", resp[0]);
        }
      } else {
        Serial0.println("auth failed");
      }
    }
  }

  // Reset Key 0 back to factory (all zeros)
  Serial0.print("[3] Resetting Key 0 to factory... ");
  uint8_t factoryKey[16] = {0};
  if (ntag_changeKey(KEY_SLOT_MASTER, factoryKey, masterKey)) {
    Serial0.println("OK");
  } else {
    Serial0.println("FAILED — Key 0 NOT reset!");
  }

  // Re-authenticate with factory Key 0 to reset Keys 1 and 2
  Serial0.print("[4] Re-auth (factory key)... ");
  if (ntag_authenticate(KEY_SLOT_MASTER, factoryKey)) {
    Serial0.println("OK");

    // Reset Key 1 to factory (all zeros)
    Serial0.print("[5] Resetting Key 1 to factory... ");
    if (ntag_changeKey(KEY_SLOT_READ, factoryKey, k1)) {
      Serial0.println("OK");
    } else {
      Serial0.println("FAILED — Key 1 NOT reset!");
    }

    // Reset Key 2 to factory (all zeros)
    Serial0.print("[6] Resetting Key 2 to factory... ");
    if (ntag_changeKey(KEY_SLOT_WRITE, factoryKey, k2)) {
      Serial0.println("OK");
    } else {
      Serial0.println("FAILED — Key 2 NOT reset!");
    }
  } else {
    Serial0.println("FAILED — cannot reset Keys 1/2!");
  }

  // Remove tag from database
  if (db_tagExists(uid, uidLength)) {
    String nvsKey = uidToHexString(uid, uidLength);
    storage.begin("ntag", false);
    storage.remove(nvsKey.c_str());
    storage.end();
    Serial0.println("  Tag removed from database.");
  }

  Serial0.println("╚═════════════════════════╝\n");
}

// =============================================================================
// VALIDATE MODE
// =============================================================================

void handleValidateMode(uint8_t *uid, uint8_t uidLength) {
  Serial0.println("\n╔══ VALIDATE MODE ══╗");
  printHex("UID", uid, uidLength);

  // Look up in database
  uint8_t storedMasterKey[16], storedReadKey[16], storedWriteKey[16], storedSecret[16];
  if (!db_loadTag(uid, uidLength, storedMasterKey, storedReadKey, storedWriteKey, storedSecret)) {
    Serial0.println("✗ UNKNOWN TAG — not in database");
    Serial0.println("╚═══════════════════╝\n");
    return;
  }

  // Authenticate with read key
  Serial0.print("[1] Authenticating (read key)... ");
  if (!ntag_authenticate(KEY_SLOT_READ, storedReadKey)) {
    // Fallback: try master key
    Serial0.print("trying master... ");
    if (!ntag_authenticate(KEY_SLOT_MASTER, storedMasterKey)) {
      Serial0.println("FAILED");
      Serial0.println("✗ VALIDATION FAILED — authentication error");
      Serial0.println("╚═══════════════════╝\n");
      return;
    }
  }
  Serial0.println("OK");

  // Read secret from file
  // Try plain read first (backward compatible), then Full-mode read.
  // We try plain first because a Full-mode command sent to a Plain-mode file
  // will fail and kill the auth session, making fallback impossible.
  Serial0.print("[2] Reading secret... ");
  uint8_t readSecret[SECRET_LENGTH];
  bool readOk = false;

  // Try plain read first (works for CommMode.Plain files)
  {
    uint8_t readCmd[8];
    size_t rp = 0;
    readCmd[rp++] = NTAG_READ_DATA;
    readCmd[rp++] = SECRET_FILE_NUMBER;
    readCmd[rp++] = 0x00; readCmd[rp++] = 0x00; readCmd[rp++] = 0x00;
    readCmd[rp++] = SECRET_LENGTH; readCmd[rp++] = 0x00; readCmd[rp++] = 0x00;
    uint8_t readResp[64]; uint8_t readRespLen = sizeof(readResp);
    if (ntag_sendCommand(readCmd, rp, readResp, &readRespLen) && readResp[0] == 0x00 && readRespLen >= SECRET_LENGTH + 1) {
      memcpy(readSecret, readResp + 1, SECRET_LENGTH);
      Serial0.println("OK (plain)");
      readOk = true;
    }
  }

  // If plain failed, try Full-mode read (CommMode.Full files)
  if (!readOk) {
    // Re-authenticate since the failed plain read may have invalidated the session
    if (ntag_authenticate(KEY_SLOT_READ, storedReadKey) ||
        ntag_authenticate(KEY_SLOT_MASTER, storedMasterKey)) {
      if (ntag_readDataFull(SECRET_FILE_NUMBER, readSecret, SECRET_LENGTH)) {
        Serial0.println("OK (encrypted)");
        readOk = true;
      } else {
        Serial0.println("FAILED");
      }
    } else {
      Serial0.println("FAILED (re-auth)");
    }
  }
  
  if (!readOk) {
    Serial0.println("FAILED");
    Serial0.println("✗ VALIDATION FAILED — cannot read file");
    Serial0.println("╚═══════════════════╝\n");
    return;
  }

  // Compare secrets
  if (memcmp(readSecret, storedSecret, SECRET_LENGTH) == 0) {
    Serial0.println("\n✓ VALIDATION PASSED — tag is genuine");
  } else {
    Serial0.println("\n✗ VALIDATION FAILED — secret mismatch!");
    printHex("  Expected", storedSecret, SECRET_LENGTH);
    printHex("  Read    ", readSecret, SECRET_LENGTH);
  }
  Serial0.println("╚═══════════════════╝\n");

  // Zero key material from stack
  secure_zero(storedMasterKey, 16);
  secure_zero(storedReadKey, 16);
  secure_zero(storedWriteKey, 16);
  secure_zero(storedSecret, 16);
  secure_zero(readSecret, SECRET_LENGTH);
}

// =============================================================================
// DUMP / EXPORT
// =============================================================================

void handleDump() {
  Serial0.println("\n--- BEGIN EXPORT ---");
  Serial0.println("[");

  storage.begin("ntag", true);
  size_t indexSize = storage.getBytesLength("uids");

  if (indexSize > 0) {
    uint8_t *indexBuffer = (uint8_t *)malloc(indexSize);
    if (indexBuffer == NULL) {
      Serial0.println("ERROR: Out of memory (handleDump)");
      storage.end();
      return;
    }
    storage.getBytes("uids", indexBuffer, indexSize);

    uint32_t tagsPrinted = 0;
    for (size_t i = 0; i < indexSize; i += 8) {
      uint8_t uidLength = indexBuffer[i];
      if (uidLength > 7) break;

      uint8_t uid[7];
      memcpy(uid, indexBuffer + i + 1, uidLength);
      String nvsKey = uidToHexString(uid, uidLength);

      uint8_t record[NVS_RECORD_SIZE];
      if (storage.getBytes(nvsKey.c_str(), record, NVS_RECORD_SIZE) == NVS_RECORD_SIZE) {
        if (tagsPrinted > 0) Serial0.println(",");
        Serial0.println("  {");
        Serial0.printf("    \"uid\":    \"%s\",\n", nvsKey.c_str());
        Serial0.print("    \"key0\":   \"");
        for (int j = 0; j < 16; j++) Serial0.printf("%02X", record[j]);
        Serial0.println("\",");
        Serial0.print("    \"key1\":   \"");
        for (int j = 16; j < 32; j++) Serial0.printf("%02X", record[j]);
        Serial0.println("\",");
        Serial0.print("    \"key2\":   \"");
        for (int j = 32; j < 48; j++) Serial0.printf("%02X", record[j]);
        Serial0.println("\",");
        Serial0.print("    \"secret\": \"");
        for (int j = 48; j < 64; j++) Serial0.printf("%02X", record[j]);
        Serial0.println("\"");
        Serial0.print("  }");
        tagsPrinted++;
      }
    }
    free(indexBuffer);
    Serial0.println();
  }

  storage.end();
  Serial0.println("]");
  Serial0.println("--- END EXPORT ---\n");
}

// =============================================================================
// IMPORT
// =============================================================================

void handleImport() {
  Serial0.println("\n=== IMPORT TAG RECORD ===");
  Serial0.println("Enter hex values (no spaces). Type 0 for default/empty.\n");

  Serial0.print("UID (14 hex chars): ");
  String uidInput = readSerialLine();
  Serial0.println(uidInput);
  if (uidInput.length() != 14) {
    Serial0.println("ERROR: UID must be 7 bytes");
    return;
  }
  uint8_t uid[7];
  if (!parseHexString(uidInput, uid, 7)) {
    Serial0.println("ERROR: Invalid hex");
    return;
  }

  Serial0.print("Key 0 — Master (32 hex, or 0): ");
  String k0Input = readSerialLine();
  Serial0.println(k0Input);
  uint8_t masterKey[16] = { 0 };
  if (k0Input != "0" && k0Input.length() > 0) {
    if (!parseHexString(k0Input, masterKey, 16)) {
      Serial0.println("ERROR: Invalid hex");
      return;
    }
  }

  Serial0.print("Key 1 — Read (32 hex, or 0): ");
  String k1Input = readSerialLine();
  Serial0.println(k1Input);
  uint8_t readKey[16] = { 0 };
  if (k1Input != "0" && k1Input.length() > 0) {
    if (!parseHexString(k1Input, readKey, 16)) {
      Serial0.println("ERROR: Invalid hex");
      return;
    }
  }

  Serial0.print("Key 2 — Write (32 hex, or 0): ");
  String k2Input = readSerialLine();
  Serial0.println(k2Input);
  uint8_t writeKey[16] = { 0 };
  if (k2Input != "0" && k2Input.length() > 0) {
    if (!parseHexString(k2Input, writeKey, 16)) {
      Serial0.println("ERROR: Invalid hex");
      return;
    }
  }

  Serial0.print("Secret (32 hex, or 0): ");
  String secretInput = readSerialLine();
  Serial0.println(secretInput);
  uint8_t secret[16] = { 0 };
  if (secretInput != "0" && secretInput.length() > 0) {
    if (!parseHexString(secretInput, secret, 16)) {
      Serial0.println("ERROR: Invalid hex");
      return;
    }
  }

  db_storeTag(uid, 7, masterKey, readKey, writeKey, secret);

  Serial0.println("\n✓ Imported successfully:");
  printHex("  UID", uid, 7);
  printHex("  Key 0", masterKey, 16);
  printHex("  Key 1", readKey, 16);
  printHex("  Key 2", writeKey, 16);
  printHex("  Secret", secret, 16);
  Serial0.printf("  Tags in DB: %d\n\n", db_getTagCount());
}

// =============================================================================
// MAIN
// =============================================================================

void showMenu() {
  Serial0.println("Commands:");
  Serial0.println("  [P] Program tag");
  Serial0.println("  [V] Validate tag");
  Serial0.println("  [D] Dump/export records");
  Serial0.println("  [I] Import a tag record");
  Serial0.println("  [X] Erase all records");
  Serial0.println("  [T] Reset tag file settings to factory");
  Serial0.println("  [C] Tag count");
  Serial0.print("> ");
}

void setup() {
  Serial0.begin(115200);
  while (!Serial0) delay(10);
  delay(2000);

  Serial0.println("\n╔══════════════════════════════════════╗");
  Serial0.println("║  NTAG 424 DNA Tag Manager v2.1 I2C  ║");
  Serial0.println("╚══════════════════════════════════════╝");

  nfc_initialize();
  delay(200);

  // Scan I2C bus to verify PN532 is visible
  Serial0.print("Scanning I2C... ");
  Wire.beginTransmission(PN532_I2C_ADDR);
  uint8_t i2cError = Wire.endTransmission();
  if (i2cError == 0) {
    Serial0.printf("PN532 found at 0x%02X\n", PN532_I2C_ADDR);
  } else {
    Serial0.printf("No device at 0x%02X (error=%d)\n", PN532_I2C_ADDR, i2cError);
    Serial0.println("Check: wiring, pull-ups (1.5K to 3.3V), switches (SEL0=ON, SEL1=OFF)");
  }

  if (!nfc_setup()) {
    Serial0.println("ERROR: PN532 not found! Check wiring and pull-ups.");
    while (1) delay(1000);
  }

  Serial0.printf("Tags in database: %d\n\n", db_getTagCount());
  showMenu();
}

void loop() {
  // Handle serial commands
  if (Serial0.available()) {
    char input = toupper(Serial0.read());
    while (Serial0.available()) Serial0.read();  // Flush buffer

    switch (input) {
      case 'P':
        appMode = MODE_PROGRAM;
        Serial0.println("PROGRAM — place tag on reader...");
        break;
      case 'V':
        appMode = MODE_VALIDATE;
        Serial0.println("VALIDATE — place tag on reader...");
        break;
      case 'T':
        appMode = MODE_RESET;
        Serial0.println("RESET — place tag on reader...");
        break;
      case 'D':
        Serial0.println("DUMP");
        handleDump();
        showMenu();
        return;
      case 'I':
        Serial0.println("IMPORT");
        handleImport();
        showMenu();
        return;
      case 'X':
        Serial0.print("Erase ALL records? (Y/N): ");
        {
          String confirm = readSerialLine();
          Serial0.println(confirm);
          if (confirm.length() > 0 && toupper(confirm.charAt(0)) == 'Y') {
            storage.begin("ntag", false);
            storage.clear();
            storage.end();
            Serial0.println("✓ Database erased.\n");
          } else {
            Serial0.println("Cancelled.\n");
          }
        }
        showMenu();
        return;
      case 'C':
        Serial0.printf("\nTags in database: %d\n\n", db_getTagCount());
        showMenu();
        return;
    }
  }

  // Wait for tag when in program/validate mode
  if (appMode == MODE_IDLE) return;

  static uint8_t scanFailCount = 0;

  uint8_t uid[7];
  uint8_t uidLength;

  if (nfc_findTag(uid, &uidLength)) {
    scanFailCount = 0;
    if (!nfc_selectNtagApp()) {
      Serial0.println("Not an NTAG 424 DNA tag.");
    } else {
      if (appMode == MODE_PROGRAM) {
        handleProgramMode(uid, uidLength);
      } else if (appMode == MODE_VALIDATE) {
        handleValidateMode(uid, uidLength);
      } else if (appMode == MODE_RESET) {
        handleResetMode(uid, uidLength);
      }
    }

    appMode = MODE_IDLE;
    Serial0.println("Remove tag...");
    delay(3000);
    // Reset PN532 to clear any stale tag session
    nfc_reset();
    showMenu();
  } else {
    scanFailCount++;
    // If PN532 fails to respond many times, it may have gone to sleep — wake it
    if (scanFailCount >= 15) {
      nfc_reset();
      scanFailCount = 0;
    }
  }

  delay(100);
}
