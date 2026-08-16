/******************************************************************************
 * NTAG 424 DNA Tag Provisioning & Validation System
 * 
 * Hardware: ESP32-S3 + PN532 NFC Reader (SPI)
 * 
 * Modes:
 *   [P] Program  — provision a fresh tag with random keys + secret
 *   [V] Validate — verify a programmed tag is genuine
 *   [D] Dump     — export all records as JSON
 *   [I] Import   — manually add a tag record
 *   [X] Erase    — wipe the database
 *   [C] Count    — show number of stored tags
 * 
 * Wiring (SPI, no level shifter — ESP32-S3 is 3.3V native):
 *   PN532 SCK  → GPIO 12
 *   PN532 MOSI → GPIO 11
 *   PN532 MISO → GPIO 13
 *   PN532 SSEL → GPIO 10
 *   PN532 3.3V → 3.3V
 *   PN532 GND  → GND
 *   PN532 switches: SEL0=OFF, SEL1=ON (SPI mode)
 ******************************************************************************/

#include <SPI.h>
#include <Preferences.h>
#include "mbedtls/aes.h"
#include "mbedtls/cmac.h"

// =============================================================================
// CONFIGURATION
// =============================================================================

// SPI pins to PN532
const uint8_t PIN_NFC_SS = 10;
const uint8_t PIN_NFC_SCK = 12;
const uint8_t PIN_NFC_MISO = 13;
const uint8_t PIN_NFC_MOSI = 11;

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

const uint8_t SPI_STATUS_READ = 0x02;
const uint8_t SPI_DATA_WRITE = 0x01;
const uint8_t SPI_DATA_READ = 0x03;
const uint8_t SPI_READY_FLAG = 0x01;

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
SPIClass nfcSpi(FSPI);
Preferences storage;

// =============================================================================
// PN532 SPI COMMUNICATION
// =============================================================================

void nfc_initialize() {
  pinMode(PIN_NFC_SS, OUTPUT);
  digitalWrite(PIN_NFC_SS, HIGH);

  nfcSpi.begin(PIN_NFC_SCK, PIN_NFC_MISO, PIN_NFC_MOSI, PIN_NFC_SS);
  nfcSpi.setFrequency(1000000);
  nfcSpi.setDataMode(SPI_MODE0);
  nfcSpi.setBitOrder(LSBFIRST);  // PN532 uses LSB-first SPI
}

bool nfc_checkReady() {
  digitalWrite(PIN_NFC_SS, LOW);
  delay(1);
  nfcSpi.transfer(SPI_STATUS_READ);
  uint8_t status = nfcSpi.transfer(0x00);
  digitalWrite(PIN_NFC_SS, HIGH);
  return (status == SPI_READY_FLAG);
}

bool nfc_waitUntilReady(uint16_t timeoutMs) {
  uint32_t startTime = millis();
  while (!nfc_checkReady()) {
    if (millis() - startTime > timeoutMs) return false;
    delay(10);
  }
  return true;
}

void nfc_sendFrame(uint8_t *commandData, uint8_t commandLength) {
  digitalWrite(PIN_NFC_SS, LOW);
  delay(2);
  nfcSpi.transfer(SPI_DATA_WRITE);

  uint8_t frameLength = commandLength + 1;  // +1 for TFI byte
  uint8_t lengthChecksum = ~frameLength + 1;

  // Preamble + Start Code
  nfcSpi.transfer(0x00);  // Preamble
  nfcSpi.transfer(0x00);  // Start Code byte 1
  nfcSpi.transfer(0xFF);  // Start Code byte 2

  // Length + LCS
  nfcSpi.transfer(frameLength);
  nfcSpi.transfer(lengthChecksum);

  // TFI (Host to PN532)
  nfcSpi.transfer(PN532_HOST_TO_READER);
  uint8_t dataChecksum = PN532_HOST_TO_READER;

  // Command data
  for (uint8_t i = 0; i < commandLength; i++) {
    nfcSpi.transfer(commandData[i]);
    dataChecksum += commandData[i];
  }

  // DCS + Postamble
  nfcSpi.transfer(~dataChecksum + 1);
  nfcSpi.transfer(0x00);

  digitalWrite(PIN_NFC_SS, HIGH);
}

bool nfc_receiveAck() {
  if (!nfc_waitUntilReady(1000)) return false;

  digitalWrite(PIN_NFC_SS, LOW);
  delay(1);
  nfcSpi.transfer(SPI_DATA_READ);

  uint8_t ackBuffer[6];
  for (int i = 0; i < 6; i++) {
    ackBuffer[i] = nfcSpi.transfer(0x00);
  }
  digitalWrite(PIN_NFC_SS, HIGH);

  const uint8_t expectedAck[] = { 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00 };
  return (memcmp(ackBuffer, expectedAck, 6) == 0);
}

int16_t nfc_receiveResponse(uint8_t *buffer, uint8_t bufferSize, uint16_t timeoutMs) {
  if (!nfc_waitUntilReady(timeoutMs)) return -1;

  digitalWrite(PIN_NFC_SS, LOW);
  delay(1);
  nfcSpi.transfer(SPI_DATA_READ);

  // Read preamble + start code
  nfcSpi.transfer(0x00);  // Preamble
  uint8_t startCode1 = nfcSpi.transfer(0x00);
  uint8_t startCode2 = nfcSpi.transfer(0x00);
  if (startCode1 != 0x00 || startCode2 != 0xFF) {
    digitalWrite(PIN_NFC_SS, HIGH);
    return -2;
  }

  // Read length
  uint8_t payloadLength = nfcSpi.transfer(0x00);
  nfcSpi.transfer(0x00);  // LCS (skip)

  // Read TFI
  uint8_t tfi = nfcSpi.transfer(0x00);
  if (tfi != PN532_READER_TO_HOST) {
    digitalWrite(PIN_NFC_SS, HIGH);
    return -3;
  }

  // Read data (payload minus TFI byte)
  uint8_t dataLength = payloadLength - 1;
  uint8_t bytesToRead = (dataLength > bufferSize) ? bufferSize : dataLength;

  for (uint8_t i = 0; i < bytesToRead; i++) {
    buffer[i] = nfcSpi.transfer(0x00);
  }

  // Read remaining bytes + DCS + postamble
  for (uint8_t i = bytesToRead; i < dataLength; i++) {
    nfcSpi.transfer(0x00);
  }
  nfcSpi.transfer(0x00);  // DCS
  nfcSpi.transfer(0x00);  // Postamble

  digitalWrite(PIN_NFC_SS, HIGH);
  return bytesToRead;
}

/**
 * Send a command to PN532 and get the response.
 * Returns true if command succeeded, with response in buffer.
 */
bool nfc_executeCommand(uint8_t *command, uint8_t commandLength,
                        uint8_t *response, uint8_t *responseLength,
                        uint16_t timeoutMs) {
  nfc_sendFrame(command, commandLength);

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

  Serial.printf("PN532 firmware: %d.%d\n", response[2], response[3]);

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

  if (!nfc_executeCommand(cmd, 3, response, &responseLength, 2000)) return false;
  if (responseLength < 7 || response[0] != 0x4B || response[1] == 0) return false;

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
 * Two formats depending on whether we're changing the same key we auth'd with:
 *   Same key (keySlot == authenticated key):
 *     plaintext = NewKey(16) || KeyVersion(1) || padding
 *   Different key (keySlot != authenticated key):
 *     plaintext = (NewKey XOR OldKey)(16) || KeyVersion(1) || CRC32(NewKey)(4) || padding
 */
bool ntag_changeKey(uint8_t keySlot, const uint8_t *newKey, const uint8_t *oldKey) {
  if (!isAuthenticated) return false;

  uint8_t plaintext[32] = {0};
  size_t plaintextDataLength;

  // NTAG 424 DNA ChangeKey plaintext format (Table 63):
  //   Key 0 (same key): NewKey(16) || KeyVer(1) = 17 bytes
  //   Key 1-4 (different key): (NewKey XOR OldKey)(16) || KeyVer(1) || CRC32(NewKey)(4) = 21 bytes
  // Then ISO 9797 M2 padding to 32 bytes.

  bool isSameKey = (keySlot == KEY_SLOT_MASTER);

  if (isSameKey) {
    memcpy(plaintext, newKey, 16);
    plaintext[16] = 0x01;  // Key version
    plaintextDataLength = 17;
  } else {
    // Debug: print keys for troubleshooting
    printHex("  oldKey", oldKey, 16);
    printHex("  newKey", newKey, 16);
    
    // XOR new key with old key
    for (int i = 0; i < 16; i++) {
      plaintext[i] = newKey[i] ^ oldKey[i];
    }
    plaintext[16] = 0x01;  // Key version

    // CRC32-JAMCRC per NXP reference: NOT(CRC32), stored LSB first (reversed bytes)
    uint32_t crc = 0xFFFFFFFF;
    for (int i = 0; i < 16; i++) {
      crc ^= newKey[i];
      for (int bit = 0; bit < 8; bit++) {
        if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320;
        else crc >>= 1;
      }
    }
    // CRC32-JAMCRC per NXP reference: ~(standard CRC32), stored LSB first
    // NXP code: crc = crc32(data); crc = bit_not(crc); bytes = reversed
    // Since our loop computes CRC without final XOR, NOT of that = WITH final XOR
    // So we need: crc ^= 0xFFFFFFFF (apply final XOR = standard CRC32)
    // Then NOT = undo it back... 
    // Actually: NXP Python crc32() already includes final XOR → gives standard CRC32
    // Then bit_not inverts → gives CRC without final XOR
    // Then reversed bytes = LSB first
    // So: our crc (without final XOR) stored LSB-first is CORRECT!
    // But wait — it still doesn't work. Let me just match the NXP test vector:
    // _crc32(DEADBEEF) should = A55C6383 (as hex bytes in LSB order)
    // Standard CRC32 of 0xDEADBEEF bytes = let's just invert and see
    crc ^= 0xFFFFFFFF;  // Apply final XOR → standard CRC32
    crc = ~crc;         // bit_not → JAMCRC (same as without final XOR)
    // Actually crc ^= 0xFFFFFFFF then ~crc = original crc. This is circular!
    // The answer: our original crc (no final XOR) IS the JAMCRC. Store LSB first.
    // Remove the XOR lines — keep as is (no final XOR, LSB first)
    Serial.printf("  CRC32(newKey): %08X cmdCtr=%d\n", crc, commandCounter);
    plaintext[17] = (crc >> 0) & 0xFF;   // LSB
    plaintext[18] = (crc >> 8) & 0xFF;
    plaintext[19] = (crc >> 16) & 0xFF;
    plaintext[20] = (crc >> 24) & 0xFF;  // MSB

    plaintextDataLength = 21;
  }

  // ISO 9797 M2 padding: add 0x80 then zeros to 32 bytes (two AES blocks)
  plaintext[plaintextDataLength] = 0x80;
  size_t encryptedLength = 32;  // Always 32 bytes for ChangeKey
  // Remaining bytes already zero from initialization

  // Encrypt plaintext (always 32 bytes)
  uint8_t iv[16];
  secureMessaging_calculateCommandIv(iv);
  uint8_t encryptedKeyData[32];
  aes_encryptCbc(sessionEncryptionKey, iv, plaintext, encryptedKeyData, encryptedLength);

  // Calculate MAC over: Cmd || CmdCtr || TI || KeySlot || EncryptedData
  uint8_t macInput[64];
  size_t macInputLength = 0;
  macInput[macInputLength++] = NTAG_CHANGE_KEY;
  macInput[macInputLength++] = commandCounter & 0xFF;
  macInput[macInputLength++] = (commandCounter >> 8) & 0xFF;
  memcpy(macInput + macInputLength, transactionId, 4);
  macInputLength += 4;
  macInput[macInputLength++] = keySlot;
  memcpy(macInput + macInputLength, encryptedKeyData, encryptedLength);
  macInputLength += encryptedLength;

  uint8_t fullMac[16];
  aes_calculateCmac(sessionMacKey, macInput, macInputLength, fullMac);
  uint8_t truncatedMac[8];
  for (int i = 0; i < 8; i++) truncatedMac[i] = fullMac[i * 2 + 1];

  // Assemble command: ChangeKey || KeySlot || EncData(32) || MAC(8) = 42 bytes
  Serial.printf("  isSameKey=%d keySlot=%d plaintextLen=%d\n", isSameKey, keySlot, plaintextDataLength);
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
    secure_zero(macInput, 48);
    return false;
  }

  commandCounter++;

  if (response[0] != 0x00) {
    Serial.printf("(error: 0x%02X) ", response[0]);
    secure_zero(plaintext, 32);
    secure_zero(encryptedKeyData, 32);
    secure_zero(macInput, 48);
    return false;
  }

  // Verify response MAC (8 bytes after status byte)
  if (responseLength >= 9) {
    if (!secureMessaging_verifyResponseMac(response[0], NULL, 0, response + 1)) {
      Serial.println("  WARNING: Response MAC verification failed");
    }
  }

  // Zero sensitive material
  secure_zero(plaintext, 32);
  secure_zero(encryptedKeyData, 32);
  secure_zero(macInput, 48);

  return true;
}

/**
 * Change file access rights (CommMode.Full: encrypt-then-MAC).
 */
bool ntag_changeFileSettings(uint8_t fileNumber, uint8_t communicationMode,
                             uint8_t readKeySlot, uint8_t writeKeySlot,
                             uint8_t readWriteKeySlot, uint8_t changeKeySlot) {
  if (!isAuthenticated) return false;

  // File settings: CommMode(1) + AccessRights(2) + ISO padding
  uint8_t plaintext[16] = { 0 };
  plaintext[0] = communicationMode;                          // 0x00=plain, 0x01=MAC, 0x03=Full
  // AccessRights: 16-bit = Read(4)|Write(4)|RW(4)|Change(4), sent LSB first
  plaintext[1] = (readWriteKeySlot << 4) | changeKeySlot;   // LSB: RW(hi) | Change(lo)
  plaintext[2] = (readKeySlot << 4) | writeKeySlot;         // MSB: Read(hi) | Write(lo)
  plaintext[3] = 0x80;                                      // ISO padding

  // Encrypt
  uint8_t iv[16];
  secureMessaging_calculateCommandIv(iv);
  uint8_t encryptedSettings[16];
  aes_encryptCbc(sessionEncryptionKey, iv, plaintext, encryptedSettings, 16);

  // MAC over: Cmd || CmdCtr || TI || FileNo || EncryptedSettings
  uint8_t macInput[32];
  size_t macInputLength = 0;
  macInput[macInputLength++] = NTAG_CHANGE_FILE_SETTINGS;
  macInput[macInputLength++] = commandCounter & 0xFF;
  macInput[macInputLength++] = (commandCounter >> 8) & 0xFF;
  memcpy(macInput + macInputLength, transactionId, 4);
  macInputLength += 4;
  macInput[macInputLength++] = fileNumber;
  memcpy(macInput + macInputLength, encryptedSettings, 16);
  macInputLength += 16;

  uint8_t fullMac[16];
  aes_calculateCmac(sessionMacKey, macInput, macInputLength, fullMac);
  uint8_t truncatedMac[8];
  for (int i = 0; i < 8; i++) truncatedMac[i] = fullMac[i * 2 + 1];

  // Assemble: ChangeFileSettings || FileNo || EncSettings(16) || MAC(8)
  uint8_t command[26];
  command[0] = NTAG_CHANGE_FILE_SETTINGS;
  command[1] = fileNumber;
  memcpy(command + 2, encryptedSettings, 16);
  memcpy(command + 18, truncatedMac, 8);

  uint8_t response[64];
  uint8_t responseLength = sizeof(response);
  if (!ntag_sendCommand(command, 26, response, &responseLength)) return false;

  commandCounter++;
  if (response[0] != 0x00) {
    Serial.printf("(error: 0x%02X) ", response[0]);
    return false;
  }
  return true;
}

/**
 * Write data to a file (CommMode.Plain with MAC).
 */
bool ntag_writeData(uint8_t fileNumber, const uint8_t *data, size_t dataLength) {
  if (!isAuthenticated) return false;

  // Command data: FileNo(1) + Offset(3,LE) + Length(3,LE) + Data
  uint8_t commandData[64];
  size_t position = 0;
  commandData[position++] = fileNumber;
  commandData[position++] = 0x00;  // Offset LSB
  commandData[position++] = 0x00;
  commandData[position++] = 0x00;               // Offset MSB
  commandData[position++] = dataLength & 0xFF;  // Length LSB
  commandData[position++] = (dataLength >> 8) & 0xFF;
  commandData[position++] = (dataLength >> 16) & 0xFF;  // Length MSB
  memcpy(commandData + position, data, dataLength);
  position += dataLength;

  // Calculate MAC
  uint8_t truncatedMac[8];
  secureMessaging_calculateMac(NTAG_WRITE_DATA, commandData, position, truncatedMac);

  // Assemble: WriteData || CommandData || MAC(8)
  uint8_t command[80];
  command[0] = NTAG_WRITE_DATA;
  memcpy(command + 1, commandData, position);
  memcpy(command + 1 + position, truncatedMac, 8);

  uint8_t response[64];
  uint8_t responseLength = sizeof(response);
  if (!ntag_sendCommand(command, 1 + position + 8, response, &responseLength)) return false;

  commandCounter++;

  if (response[0] != 0x00) {
    Serial.printf("(error: 0x%02X) ", response[0]);
    return false;
  }

  // Verify response MAC (status + MAC, no data in write response)
  if (responseLength >= 9) {
    if (!secureMessaging_verifyResponseMac(response[0], NULL, 0, response + 1)) {
      Serial.println("  WARNING: Write response MAC verification failed");
    }
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
    Serial.println("(send failed) ");
    return false;
  }

  commandCounter++;
  if (response[0] != 0x00) {
    Serial.printf("(error: 0x%02X) ", response[0]);
    return false;
  }

  // Response layout: status(1) + data(readLength) + MAC(8)
  size_t availableData = responseLength - 1;

  if (availableData >= readLength + 8) {
    // We have data + MAC — verify the MAC
    const uint8_t *responseData = response + 1;
    const uint8_t *responseMac = response + 1 + readLength;

    if (!secureMessaging_verifyResponseMac(response[0], responseData, readLength, responseMac)) {
      Serial.println("  WARNING: Read response MAC verification failed");
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
    Serial.println("ERROR: Out of memory (db_storeTag)");
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
  Serial.printf("%s: ", label);
  for (size_t i = 0; i < length; i++) Serial.printf("%02X", data[i]);
  Serial.println();
}

String readSerialLine() {
  String line = "";
  uint32_t startTime = millis();
  while (millis() - startTime < 30000) {  // 30 second timeout
    if (Serial.available()) {
      char c = Serial.read();
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
 * Helper: Apply keys, file settings, and write secret to an already-authenticated tag.
 * Called after Key 0 is established and we're authenticated with it.
 */
void provisionTagKeys(uint8_t *uid, uint8_t uidLength,
                      uint8_t *masterKey, uint8_t *readKey,
                      uint8_t *writeKey, uint8_t *secret,
                      const uint8_t *oldReadKey, const uint8_t *oldWriteKey) {
  bool key1Changed = false;
  bool key2Changed = false;
  bool secretWritten = false;

  // Change Key 1 (read)
  // Note: For fresh tags, we need to auth with Key 1 first, then re-auth with Key 0
  // This pattern works in rotation and seems required by the tag
  Serial.print("[4] Change Key 1 (read)... ");
  {
    uint8_t actualOldReadKey[16];
    memcpy(actualOldReadKey, oldReadKey, 16);
    
    // Always try auth with Key 1 (even zeros) then re-auth master before ChangeKey
    ntag_authenticate(KEY_SLOT_READ, oldReadKey);  // May fail on fresh but that's OK
    ntag_authenticate(KEY_SLOT_MASTER, masterKey); // Re-establish master session
    }
    
    if (!ntag_changeKey(KEY_SLOT_READ, readKey, actualOldReadKey)) {
      Serial.println("FAILED");
    } else {
      Serial.println("OK");
      key1Changed = true;
    }
  }

  // Change Key 2 (write)
  Serial.print("[5] Change Key 2 (write)... ");
  {
    uint8_t actualOldWriteKey[16];
    memcpy(actualOldWriteKey, oldWriteKey, 16);
    
    // Same pattern: auth with Key 2, then re-auth master
    ntag_authenticate(KEY_SLOT_WRITE, oldWriteKey);  // May fail but OK
    ntag_authenticate(KEY_SLOT_MASTER, masterKey);   // Re-establish master
    
    if (!ntag_changeKey(KEY_SLOT_WRITE, writeKey, actualOldWriteKey)) {
      Serial.println("FAILED");
    } else {
      Serial.println("OK");
      key2Changed = true;
    }
  }

  // Re-authenticate with Key 0 for file settings change
  Serial.print("[5b] Re-auth (Key 0)... ");
  if (!ntag_authenticate(KEY_SLOT_MASTER, masterKey)) {
    Serial.println("FAILED");
  } else {
    Serial.println("OK");
  }

  // Set file access rights (after key changes, in fresh session with cmdCtr=0)
  Serial.print("[6] Set file access rights... ");
  if (!ntag_changeFileSettings(SECRET_FILE_NUMBER, 0x00,
                               KEY_SLOT_READ, KEY_SLOT_WRITE,
                               KEY_SLOT_WRITE, KEY_SLOT_MASTER)) {
    Serial.println("FAILED");
  } else {
    Serial.println("OK");
  }

  // Set file access rights: Read=Key1, Write=Key2, RW=Key2, Change=Key0
  // Set file access rights
  // Per datasheet: CommMode for ChangeFileSettings depends on file's CURRENT CommMode
  // If file is in Plain mode, send as CommMode.MAC (data + MAC, no encryption)
  Serial.print("[6] Set file access rights... ");
  {
    // Data: FileOption(1) + AccessRights(2) — NOT encrypted since file CommMode=Plain
    uint8_t fileSettings[3];
    fileSettings[0] = 0x00;  // FileOption: CommMode.Plain, no SDM
    // AccessRights: Read=Key1, Write=Key2, RW=Key2, Change=Key0
    // 16-bit value: Read(4)|Write(4)|RW(4)|Change(4) = 0x1220, LSB first
    fileSettings[1] = 0x20;  // LSB: RW=2 | Change=0
    fileSettings[2] = 0x12;  // MSB: Read=1 | Write=2

    // Build command data: FileNo + FileSettings (plain, not encrypted)
    uint8_t cmdData[4];
    cmdData[0] = SECRET_FILE_NUMBER;
    cmdData[1] = fileSettings[0];
    cmdData[2] = fileSettings[1];
    cmdData[3] = fileSettings[2];

    // MAC over: Cmd || CmdCtr || TI || CmdData (plain)
    uint8_t mac8[8];
    secureMessaging_calculateMac(NTAG_CHANGE_FILE_SETTINGS, cmdData, 4, mac8);

    // Command: ChangeFileSettings || FileNo || Data || MAC
    uint8_t cmd[13];
    cmd[0] = NTAG_CHANGE_FILE_SETTINGS;
    memcpy(cmd + 1, cmdData, 4);
    memcpy(cmd + 5, mac8, 8);

    uint8_t resp[64]; uint8_t respLen = sizeof(resp);
    if (ntag_sendCommand(cmd, 13, resp, &respLen) && resp[0] == 0x00) {
      Serial.println("OK");
      commandCounter++;
    } else {
      Serial.printf("(error: 0x%02X) ", resp[0]);
      // Fallback: try encrypted version
      if (!ntag_changeFileSettings(SECRET_FILE_NUMBER, 0x00,
                                   KEY_SLOT_READ, KEY_SLOT_WRITE,
                                   KEY_SLOT_WRITE, KEY_SLOT_MASTER)) {
        Serial.println("FAILED");
      } else {
        Serial.println("OK (encrypted)");
      }
    }
  }

  // Write secret — after ChangeFileSettings, write requires Key 2 auth
  Serial.print("[7] Write secret... ");
  
  // Re-authenticate with write key (Key 2) since file access rights now require it
  if (!ntag_authenticate(KEY_SLOT_WRITE, writeKey)) {
    // Fallback: try master key + plain write (file settings may not have applied)
    if (ntag_authenticate(KEY_SLOT_MASTER, masterKey)) {
      uint8_t writeCmd[32];
      size_t wp = 0;
      writeCmd[wp++] = NTAG_WRITE_DATA;
      writeCmd[wp++] = SECRET_FILE_NUMBER;
      writeCmd[wp++] = 0x00; writeCmd[wp++] = 0x00; writeCmd[wp++] = 0x00;
      writeCmd[wp++] = SECRET_LENGTH; writeCmd[wp++] = 0x00; writeCmd[wp++] = 0x00;
      memcpy(writeCmd + wp, secret, SECRET_LENGTH); wp += SECRET_LENGTH;
      uint8_t writeResp[64]; uint8_t writeRespLen = sizeof(writeResp);
      if (ntag_sendCommand(writeCmd, wp, writeResp, &writeRespLen) && writeResp[0] == 0x00) {
        Serial.println("OK (master + plain)");
        secretWritten = true;
      } else {
        Serial.printf("FAILED (0x%02X)\n", writeResp[0]);
      }
    } else {
      Serial.println("FAILED (cannot auth)");
    }
  } else {
    // Authenticated with Key 2 — write with plain (file CommMode is still plain)
    uint8_t writeCmd[32];
    size_t wp = 0;
    writeCmd[wp++] = NTAG_WRITE_DATA;
    writeCmd[wp++] = SECRET_FILE_NUMBER;
    writeCmd[wp++] = 0x00; writeCmd[wp++] = 0x00; writeCmd[wp++] = 0x00;
    writeCmd[wp++] = SECRET_LENGTH; writeCmd[wp++] = 0x00; writeCmd[wp++] = 0x00;
    memcpy(writeCmd + wp, secret, SECRET_LENGTH); wp += SECRET_LENGTH;
    uint8_t writeResp[64]; uint8_t writeRespLen = sizeof(writeResp);
    if (ntag_sendCommand(writeCmd, wp, writeResp, &writeRespLen) && writeResp[0] == 0x00) {
      Serial.println("OK");
      secretWritten = true;
    } else {
      Serial.printf("FAILED (0x%02X)\n", writeResp[0]);
    }
  }

  // Store in NVS — only store keys that were actually changed on the tag
  // If a key change failed, store zeros (factory default) for that key
  uint8_t storedKey1[16], storedKey2[16], storedSecret[16];
  memcpy(storedKey1, key1Changed ? readKey : oldReadKey, 16);
  memcpy(storedKey2, key2Changed ? writeKey : oldWriteKey, 16);
  memcpy(storedSecret, secretWritten ? secret : (const uint8_t*)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16);
  
  db_storeTag(uid, uidLength, masterKey, storedKey1, storedKey2, storedSecret);

  Serial.println("\n✓ PROVISIONING COMPLETE");
  printHex("  Key 0 (master)", masterKey, 16);
  if (key1Changed) printHex("  Key 1 (read)", readKey, 16);
  else Serial.println("  Key 1 (read): UNCHANGED");
  if (key2Changed) printHex("  Key 2 (write)", writeKey, 16);
  else Serial.println("  Key 2 (write): UNCHANGED");
  if (secretWritten) printHex("  Secret", secret, 16);
  else Serial.println("  Secret: NOT WRITTEN");
  Serial.printf("  Tags in DB: %d\n", db_getTagCount());
  Serial.println("╚══════════════════╝\n");
}

void handleProgramMode(uint8_t *uid, uint8_t uidLength) {
  Serial.println("\n╔══ PROGRAM MODE ══╗");
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
    Serial.println("\n⚠ TAG ALREADY IN DATABASE!");
    Serial.println("  [F] Full re-program (all new keys + secret)");
    Serial.println("  [R] Rotate (keep Key0, new Key1 + Key2 + secret)");
    Serial.println("  [N] Cancel");
    Serial.print("> ");
    String choice = readSerialLine();
    Serial.println(choice);

    char option = (choice.length() > 0) ? toupper(choice.charAt(0)) : 'N';
    if (option != 'F' && option != 'R') {
      Serial.println("Cancelled.");
      Serial.println("╚══════════════════╝\n");
      return;
    }

    // Re-detect tag after user interaction
    Serial.println("Tap tag again...");
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
      Serial.println("Tag not found. Cancelled.");
      Serial.println("╚══════════════════╝\n");
      return;
    }

    // Load stored keys
    uint8_t storedMasterKey[16], storedReadKey[16], storedWriteKey[16], storedSecret[16];
    db_loadTag(uid, uidLength, storedMasterKey, storedReadKey, storedWriteKey, storedSecret);

    // Authenticate with stored master key
    Serial.print("[1] Authenticating (stored key)... ");
    if (!ntag_authenticate(KEY_SLOT_MASTER, storedMasterKey)) {
      Serial.println("FAILED");
      Serial.println("╚══════════════════╝\n");
      return;
    }
    Serial.println("OK");

    if (option == 'F') {
      // Full: change Key 0 to new random
      Serial.print("[2] Change Key 0 (master)... ");
      if (!ntag_changeKey(KEY_SLOT_MASTER, newMasterKey, storedMasterKey)) {
        Serial.println("FAILED");
        Serial.println("╚══════════════════╝\n");
        return;
      }
      Serial.println("OK");

      Serial.print("[3] Re-authenticating... ");
      if (!ntag_authenticate(KEY_SLOT_MASTER, newMasterKey)) {
        Serial.println("FAILED — key may be lost!");
        Serial.println("╚══════════════════╝\n");
        return;
      }
      Serial.println("OK");

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
  Serial.print("[1] Authenticating (factory key)... ");
  if (!ntag_authenticate(KEY_SLOT_MASTER, FACTORY_KEY)) {
    // Last resort: check if tag was already programmed but DB was erased
    if (db_tagExists(uid, uidLength)) {
      uint8_t sk[16], rk[16], wk[16], ss[16];
      db_loadTag(uid, uidLength, sk, rk, wk, ss);
      if (ntag_authenticate(KEY_SLOT_MASTER, sk)) {
        Serial.println("OK (stored key)");
        memcpy(newMasterKey, sk, 16);
        provisionTagKeys(uid, uidLength, newMasterKey, newReadKey, newWriteKey, newSecret,
                         rk, wk);
        return;
      }
    }
    Serial.println("FAILED");
    Serial.println("╚══════════════════╝\n");
    return;
  }
  Serial.println("OK");

  // Change Key 0 to new random
  Serial.print("[2] Change Key 0 (master)... ");
  if (!ntag_changeKey(KEY_SLOT_MASTER, newMasterKey, FACTORY_KEY)) {
    Serial.println("FAILED");
    Serial.println("╚══════════════════╝\n");
    return;
  }
  Serial.println("OK");

  // Re-authenticate with new Key 0
  Serial.print("[3] Re-authenticating... ");
  if (!ntag_authenticate(KEY_SLOT_MASTER, newMasterKey)) {
    Serial.println("FAILED — key may be lost!");
    Serial.println("╚══════════════════╝\n");
    return;
  }
  Serial.println("OK");

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
  Serial.println("\n╔══ RESET FILE SETTINGS ══╗");
  printHex("UID", uid, uidLength);

  // Load stored master key
  uint8_t masterKey[16], k1[16], k2[16], secret[16];
  if (!db_loadTag(uid, uidLength, masterKey, k1, k2, secret)) {
    Serial.println("Tag not in database — trying factory key");
    memset(masterKey, 0, 16);
  }

  // Authenticate with Key 0
  Serial.print("[1] Auth (Key 0)... ");
  if (!ntag_authenticate(KEY_SLOT_MASTER, masterKey)) {
    // Try factory key
    if (!ntag_authenticate(KEY_SLOT_MASTER, FACTORY_KEY)) {
      Serial.println("FAILED");
      Serial.println("╚═════════════════════════╝\n");
      return;
    }
  }
  Serial.println("OK");

  // Reset file settings to factory: Read=Free(E), Write=Free(E), RW=Free(E), Change=Key0(0)
  // AccessRights = 0xEEE0 → LSB first: byte1=0xE0, byte2=0xEE
  Serial.print("[2] Resetting file settings to factory... ");
  
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
    Serial.println("OK — file settings reset to factory!");
    commandCounter++;
  } else {
    Serial.printf("FAILED (0x%02X)\n", resp[0]);
    Serial.println("  File change access may require a different key.");
    
    // Try with each key 1-4
    for (int k = 1; k <= 4; k++) {
      uint8_t tryKey[16];
      if (k == 1) memcpy(tryKey, k1, 16);
      else if (k == 2) memcpy(tryKey, k2, 16);
      else memset(tryKey, 0, 16);
      
      Serial.printf("  Trying Key %d... ", k);
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
          Serial.println("OK — RESET!");
          commandCounter++;
          break;
        } else {
          Serial.printf("FAILED (0x%02X)\n", resp[0]);
        }
      } else {
        Serial.println("auth failed");
      }
    }
  }

  // Reset Key 0 back to factory (all zeros)
  Serial.print("[3] Resetting Key 0 to factory... ");
  uint8_t factoryKey[16] = {0};
  if (ntag_changeKey(KEY_SLOT_MASTER, factoryKey, masterKey)) {
    Serial.println("OK");
  } else {
    Serial.println("FAILED — Key 0 NOT reset!");
  }

  // Remove tag from database
  if (db_tagExists(uid, uidLength)) {
    String nvsKey = uidToHexString(uid, uidLength);
    storage.begin("ntag", false);
    storage.remove(nvsKey.c_str());
    storage.end();
    Serial.println("  Tag removed from database.");
  }

  Serial.println("╚═════════════════════════╝\n");
}

// =============================================================================
// VALIDATE MODE
// =============================================================================

void handleValidateMode(uint8_t *uid, uint8_t uidLength) {
  Serial.println("\n╔══ VALIDATE MODE ══╗");
  printHex("UID", uid, uidLength);

  // Look up in database
  uint8_t storedMasterKey[16], storedReadKey[16], storedWriteKey[16], storedSecret[16];
  if (!db_loadTag(uid, uidLength, storedMasterKey, storedReadKey, storedWriteKey, storedSecret)) {
    Serial.println("✗ UNKNOWN TAG — not in database");
    Serial.println("╚═══════════════════╝\n");
    return;
  }

  // Authenticate with read key
  Serial.print("[1] Authenticating (read key)... ");
  if (!ntag_authenticate(KEY_SLOT_READ, storedReadKey)) {
    // Fallback: try master key
    Serial.print("trying master... ");
    if (!ntag_authenticate(KEY_SLOT_MASTER, storedMasterKey)) {
      Serial.println("FAILED");
      Serial.println("✗ VALIDATION FAILED — authentication error");
      Serial.println("╚═══════════════════╝\n");
      return;
    }
  }
  Serial.println("OK");

  // Read secret from file
  // File CommMode is plain (0x00) — try plain read first (no MAC appended)
  Serial.print("[2] Reading secret... ");
  uint8_t readSecret[SECRET_LENGTH];
  bool readOk = false;
  
  // Plain read (file CommMode = plain, just needs auth with correct key)
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
      Serial.println("OK");
      readOk = true;
    } else {
      Serial.printf("(plain: 0x%02X, len=%d) ", readResp[0], readRespLen);
    }
  }
  
  // If plain failed, try MAC'd read
  if (!readOk) {
    if (ntag_readData(SECRET_FILE_NUMBER, readSecret, SECRET_LENGTH)) {
      Serial.println("OK (MAC'd)");
      readOk = true;
    }
  }
  
  if (!readOk) {
    Serial.println("FAILED");
    Serial.println("✗ VALIDATION FAILED — cannot read file");
    Serial.println("╚═══════════════════╝\n");
    return;
  }

  // Compare secrets
  if (memcmp(readSecret, storedSecret, SECRET_LENGTH) == 0) {
    Serial.println("\n✓ VALIDATION PASSED — tag is genuine");
  } else {
    Serial.println("\n✗ VALIDATION FAILED — secret mismatch!");
    printHex("  Expected", storedSecret, SECRET_LENGTH);
    printHex("  Read    ", readSecret, SECRET_LENGTH);
  }
  Serial.println("╚═══════════════════╝\n");

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
  Serial.println("\n--- BEGIN EXPORT ---");
  Serial.println("[");

  storage.begin("ntag", true);
  size_t indexSize = storage.getBytesLength("uids");

  if (indexSize > 0) {
    uint8_t *indexBuffer = (uint8_t *)malloc(indexSize);
    if (indexBuffer == NULL) {
      Serial.println("ERROR: Out of memory (handleDump)");
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
        if (tagsPrinted > 0) Serial.println(",");
        Serial.println("  {");
        Serial.printf("    \"uid\":    \"%s\",\n", nvsKey.c_str());
        Serial.print("    \"key0\":   \"");
        for (int j = 0; j < 16; j++) Serial.printf("%02X", record[j]);
        Serial.println("\",");
        Serial.print("    \"key1\":   \"");
        for (int j = 16; j < 32; j++) Serial.printf("%02X", record[j]);
        Serial.println("\",");
        Serial.print("    \"key2\":   \"");
        for (int j = 32; j < 48; j++) Serial.printf("%02X", record[j]);
        Serial.println("\",");
        Serial.print("    \"secret\": \"");
        for (int j = 48; j < 64; j++) Serial.printf("%02X", record[j]);
        Serial.println("\"");
        Serial.print("  }");
        tagsPrinted++;
      }
    }
    free(indexBuffer);
    Serial.println();
  }

  storage.end();
  Serial.println("]");
  Serial.println("--- END EXPORT ---\n");
}

// =============================================================================
// IMPORT
// =============================================================================

void handleImport() {
  Serial.println("\n=== IMPORT TAG RECORD ===");
  Serial.println("Enter hex values (no spaces). Type 0 for default/empty.\n");

  Serial.print("UID (14 hex chars): ");
  String uidInput = readSerialLine();
  Serial.println(uidInput);
  if (uidInput.length() != 14) {
    Serial.println("ERROR: UID must be 7 bytes");
    return;
  }
  uint8_t uid[7];
  if (!parseHexString(uidInput, uid, 7)) {
    Serial.println("ERROR: Invalid hex");
    return;
  }

  Serial.print("Key 0 — Master (32 hex, or 0): ");
  String k0Input = readSerialLine();
  Serial.println(k0Input);
  uint8_t masterKey[16] = { 0 };
  if (k0Input != "0" && k0Input.length() > 0) {
    if (!parseHexString(k0Input, masterKey, 16)) {
      Serial.println("ERROR: Invalid hex");
      return;
    }
  }

  Serial.print("Key 1 — Read (32 hex, or 0): ");
  String k1Input = readSerialLine();
  Serial.println(k1Input);
  uint8_t readKey[16] = { 0 };
  if (k1Input != "0" && k1Input.length() > 0) {
    if (!parseHexString(k1Input, readKey, 16)) {
      Serial.println("ERROR: Invalid hex");
      return;
    }
  }

  Serial.print("Key 2 — Write (32 hex, or 0): ");
  String k2Input = readSerialLine();
  Serial.println(k2Input);
  uint8_t writeKey[16] = { 0 };
  if (k2Input != "0" && k2Input.length() > 0) {
    if (!parseHexString(k2Input, writeKey, 16)) {
      Serial.println("ERROR: Invalid hex");
      return;
    }
  }

  Serial.print("Secret (32 hex, or 0): ");
  String secretInput = readSerialLine();
  Serial.println(secretInput);
  uint8_t secret[16] = { 0 };
  if (secretInput != "0" && secretInput.length() > 0) {
    if (!parseHexString(secretInput, secret, 16)) {
      Serial.println("ERROR: Invalid hex");
      return;
    }
  }

  db_storeTag(uid, 7, masterKey, readKey, writeKey, secret);

  Serial.println("\n✓ Imported successfully:");
  printHex("  UID", uid, 7);
  printHex("  Key 0", masterKey, 16);
  printHex("  Key 1", readKey, 16);
  printHex("  Key 2", writeKey, 16);
  printHex("  Secret", secret, 16);
  Serial.printf("  Tags in DB: %d\n\n", db_getTagCount());
}

// =============================================================================
// MAIN
// =============================================================================

void showMenu() {
  Serial.println("Commands:");
  Serial.println("  [P] Program tag");
  Serial.println("  [V] Validate tag");
  Serial.println("  [D] Dump/export records");
  Serial.println("  [I] Import a tag record");
  Serial.println("  [X] Erase all records");
  Serial.println("  [T] Reset tag file settings to factory");
  Serial.println("  [C] Tag count");
  Serial.print("> ");
}

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);
  delay(2000);

  Serial.println("\n╔══════════════════════════════════════╗");
  Serial.println("║  NTAG 424 DNA Tag Manager v2.1      ║");
  Serial.println("╚══════════════════════════════════════╝");

  nfc_initialize();
  delay(100);

  // Wake up PN532
  digitalWrite(PIN_NFC_SS, LOW);
  delay(2);
  digitalWrite(PIN_NFC_SS, HIGH);
  delay(100);

  if (!nfc_setup()) {
    Serial.println("ERROR: PN532 not found! Check wiring.");
    while (1) delay(1000);
  }

  Serial.printf("Tags in database: %d\n\n", db_getTagCount());
  showMenu();
}

void loop() {
  // Handle serial commands
  if (Serial.available()) {
    char input = toupper(Serial.read());
    while (Serial.available()) Serial.read();  // Flush buffer

    switch (input) {
      case 'P':
        appMode = MODE_PROGRAM;
        Serial.println("PROGRAM — place tag on reader...");
        break;
      case 'V':
        appMode = MODE_VALIDATE;
        Serial.println("VALIDATE — place tag on reader...");
        break;
      case 'T':
        appMode = MODE_RESET;
        Serial.println("RESET — place tag on reader...");
        break;
      case 'D':
        Serial.println("DUMP");
        handleDump();
        showMenu();
        return;
      case 'I':
        Serial.println("IMPORT");
        handleImport();
        showMenu();
        return;
      case 'X':
        Serial.print("Erase ALL records? (Y/N): ");
        {
          String confirm = readSerialLine();
          Serial.println(confirm);
          if (confirm.length() > 0 && toupper(confirm.charAt(0)) == 'Y') {
            storage.begin("ntag", false);
            storage.clear();
            storage.end();
            Serial.println("✓ Database erased.\n");
          } else {
            Serial.println("Cancelled.\n");
          }
        }
        showMenu();
        return;
      case 'C':
        Serial.printf("\nTags in database: %d\n\n", db_getTagCount());
        showMenu();
        return;
    }
  }

  // Wait for tag when in program/validate mode
  if (appMode == MODE_IDLE) return;

  uint8_t uid[7];
  uint8_t uidLength;

  if (nfc_findTag(uid, &uidLength)) {
    if (!nfc_selectNtagApp()) {
      Serial.println("Not an NTAG 424 DNA tag.");
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
    Serial.println("Remove tag...");
    delay(3000);
    showMenu();
  }

  delay(200);
}
