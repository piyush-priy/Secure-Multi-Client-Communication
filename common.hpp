#ifndef COMMON_HPP
#define COMMON_HPP

#include <cstdint>
#include <array>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>

// ============================================================================
// Constants
// ============================================================================

constexpr size_t AES_BLOCK_SIZE = 16;
constexpr size_t AES_KEY_SIZE = 16;        // AES-128
constexpr size_t HMAC_SIZE = 32;           // HMAC-SHA256
constexpr size_t IV_SIZE = 16;
constexpr size_t MAC_KEY_SIZE = 32;

constexpr uint16_t DEFAULT_PORT = 8443;
constexpr size_t MAX_PAYLOAD_SIZE = 4096;
constexpr size_t MAX_CLIENTS = 10;

// ============================================================================
// Protocol Opcodes
// ============================================================================

enum class Opcode : uint8_t {
    CLIENT_HELLO         = 10,  // Client initiates protocol
    SERVER_CHALLENGE     = 20,  // Encrypted server challenge
    CLIENT_DATA          = 30,  // Encrypted client data
    SERVER_AGGR_RESPONSE = 40,  // Encrypted aggregate result
    KEY_DESYNC_ERROR     = 50,  // Desynchronization detected
    TERMINATE            = 60   // Session termination
};

// ============================================================================
// Protocol Phases (State Machine States)
// ============================================================================

enum class ProtocolPhase : uint8_t {
    INIT       = 0,   // Initial state, awaiting handshake
    ACTIVE     = 1,   // Normal communication state
    TERMINATED = 2    // Session ended (cannot recover)
};

// ============================================================================
// Direction Field
// ============================================================================

enum class Direction : uint8_t {
    CLIENT_TO_SERVER = 0,
    SERVER_TO_CLIENT = 1
};

// ============================================================================
// Message Header Structure
// ============================================================================
// | Opcode (1) | Client ID (1) | Round (4) | Direction (1) | IV (16) |
// Total header size: 23 bytes

constexpr size_t HEADER_SIZE = 1 + 1 + 4 + 1 + 16;  // 23 bytes

#pragma pack(push, 1)
struct MessageHeader {
    uint8_t opcode;
    uint8_t client_id;
    uint32_t round;        // Network byte order (big-endian)
    uint8_t direction;
    uint8_t iv[IV_SIZE];
};
#pragma pack(pop)

static_assert(sizeof(MessageHeader) == HEADER_SIZE, "MessageHeader size mismatch");

// ============================================================================
// Key Labels for Key Derivation
// ============================================================================

namespace KeyLabels {
    constexpr const char* C2S_ENC = "C2S-ENC";
    constexpr const char* C2S_MAC = "C2S-MAC";
    constexpr const char* S2C_ENC = "S2C-ENC";
    constexpr const char* S2C_MAC = "S2C-MAC";
}

// ============================================================================
// Type Aliases
// ============================================================================

using AESKey = std::array<uint8_t, AES_KEY_SIZE>;
using MACKey = std::array<uint8_t, MAC_KEY_SIZE>;
using IV = std::array<uint8_t, IV_SIZE>;
using HMACTag = std::array<uint8_t, HMAC_SIZE>;  // Renamed to avoid conflict with OpenSSL HMAC function
using ByteVector = std::vector<uint8_t>;

// ============================================================================
// Session Keys Structure
// ============================================================================

struct SessionKeys {
    // Client -> Server keys
    AESKey c2s_enc_key;
    MACKey c2s_mac_key;
    
    // Server -> Client keys
    AESKey s2c_enc_key;
    MACKey s2c_mac_key;
};

// ============================================================================
// Session State Structure
// ============================================================================

struct SessionState {
    uint8_t client_id;
    uint32_t round;
    ProtocolPhase phase;
    SessionKeys keys;
    
    // Master key (kept for potential re-derivation)
    ByteVector master_key;
    
    // Socket descriptor (for server-side tracking)
    int socket_fd;
    
    // Flag to indicate if session is valid
    bool valid;
    
    SessionState() : client_id(0), round(0), phase(ProtocolPhase::INIT),
                     socket_fd(-1), valid(false) {}
};

// ============================================================================
// Parsed Message Structure
// ============================================================================

struct ParsedMessage {
    Opcode opcode;
    uint8_t client_id;
    uint32_t round;
    Direction direction;
    IV iv;
    ByteVector ciphertext;
    HMACTag hmac;
    ByteVector decrypted_payload;  // Filled after successful decryption
    
    bool valid;
    std::string error_message;
    
    ParsedMessage() : opcode(Opcode::TERMINATE), client_id(0), round(0),
                      direction(Direction::CLIENT_TO_SERVER), valid(false) {}
};

// ============================================================================
// Utility Functions
// ============================================================================

// Convert uint32_t to network byte order (big-endian)
inline uint32_t hton32(uint32_t host) {
    uint8_t bytes[4];
    bytes[0] = (host >> 24) & 0xFF;
    bytes[1] = (host >> 16) & 0xFF;
    bytes[2] = (host >> 8) & 0xFF;
    bytes[3] = host & 0xFF;
    uint32_t result;
    std::memcpy(&result, bytes, 4);
    return result;
}

// Convert uint32_t from network byte order (big-endian) to host
inline uint32_t ntoh32(uint32_t net) {
    uint8_t bytes[4];
    std::memcpy(bytes, &net, 4);
    return ((uint32_t)bytes[0] << 24) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) |
           (uint32_t)bytes[3];
}

// Convert byte vector to hex string (for debugging)
inline std::string bytes_to_hex(const uint8_t* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result.push_back(hex_chars[(data[i] >> 4) & 0x0F]);
        result.push_back(hex_chars[data[i] & 0x0F]);
    }
    return result;
}

inline std::string bytes_to_hex(const ByteVector& data) {
    return bytes_to_hex(data.data(), data.size());
}

template<size_t N>
inline std::string bytes_to_hex(const std::array<uint8_t, N>& data) {
    return bytes_to_hex(data.data(), N);
}

// Convert hex string to byte vector
inline ByteVector hex_to_bytes(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have even length");
    }
    
    ByteVector result;
    result.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        uint8_t byte = 0;
        for (int j = 0; j < 2; ++j) {
            char c = hex[i + j];
            uint8_t nibble;
            if (c >= '0' && c <= '9') {
                nibble = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                nibble = c - 'a' + 10;
            } else if (c >= 'A' && c <= 'F') {
                nibble = c - 'A' + 10;
            } else {
                throw std::invalid_argument("Invalid hex character");
            }
            byte = (byte << 4) | nibble;
        }
        result.push_back(byte);
    }
    return result;
}

// Opcode to string (for debugging)
inline const char* opcode_to_string(Opcode op) {
    switch (op) {
        case Opcode::CLIENT_HELLO:         return "CLIENT_HELLO";
        case Opcode::SERVER_CHALLENGE:     return "SERVER_CHALLENGE";
        case Opcode::CLIENT_DATA:          return "CLIENT_DATA";
        case Opcode::SERVER_AGGR_RESPONSE: return "SERVER_AGGR_RESPONSE";
        case Opcode::KEY_DESYNC_ERROR:     return "KEY_DESYNC_ERROR";
        case Opcode::TERMINATE:            return "TERMINATE";
        default:                           return "UNKNOWN";
    }
}

// Phase to string (for debugging)
inline const char* phase_to_string(ProtocolPhase phase) {
    switch (phase) {
        case ProtocolPhase::INIT:       return "INIT";
        case ProtocolPhase::ACTIVE:     return "ACTIVE";
        case ProtocolPhase::TERMINATED: return "TERMINATED";
        default:                        return "UNKNOWN";
    }
}

#endif // COMMON_HPP
