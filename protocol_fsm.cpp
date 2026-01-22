#include "protocol_fsm.hpp"
#include <cstring>
#include <algorithm>

namespace ProtocolFSM {

// ============================================================================
// Error Code Strings
// ============================================================================

const char* error_to_string(ProtocolError err) {
    switch (err) {
        case ProtocolError::SUCCESS:                  return "Success";
        case ProtocolError::INVALID_OPCODE:           return "Invalid opcode for current state";
        case ProtocolError::INVALID_ROUND:            return "Round number mismatch";
        case ProtocolError::INVALID_DIRECTION:        return "Invalid message direction";
        case ProtocolError::HMAC_VERIFICATION_FAILED: return "HMAC verification failed";
        case ProtocolError::DECRYPTION_FAILED:        return "Decryption failed";
        case ProtocolError::INVALID_PADDING:          return "Invalid padding detected";
        case ProtocolError::INVALID_PAYLOAD:          return "Invalid payload format";
        case ProtocolError::SESSION_TERMINATED:       return "Session has been terminated";
        case ProtocolError::INVALID_STATE_TRANSITION: return "Invalid state transition";
        case ProtocolError::UNKNOWN_CLIENT:           return "Unknown client ID";
        case ProtocolError::MESSAGE_TOO_SHORT:        return "Message too short";
        case ProtocolError::MESSAGE_TOO_LONG:         return "Message too long";
        default:                                      return "Unknown error";
    }
}

// ============================================================================
// Key Management Implementation
// ============================================================================

SessionKeys initialize_keys(const ByteVector& master_key) {
    SessionKeys keys;
    
    // Client -> Server keys
    keys.c2s_enc_key = CryptoUtils::derive_aes_key(master_key, KeyLabels::C2S_ENC);
    keys.c2s_mac_key = CryptoUtils::derive_mac_key(master_key, KeyLabels::C2S_MAC);
    
    // Server -> Client keys
    keys.s2c_enc_key = CryptoUtils::derive_aes_key(master_key, KeyLabels::S2C_ENC);
    keys.s2c_mac_key = CryptoUtils::derive_mac_key(master_key, KeyLabels::S2C_MAC);
    
    return keys;
}

void evolve_c2s_keys(SessionKeys& keys, const ByteVector& ciphertext, const IV& nonce) {
    // C2S_Enc_R+1 = H(C2S_Enc_R || Ciphertext_R)
    keys.c2s_enc_key = CryptoUtils::evolve_aes_key(keys.c2s_enc_key, ciphertext);
    
    // C2S_Mac_R+1 = H(C2S_Mac_R || Nonce_R)
    ByteVector nonce_vec(nonce.begin(), nonce.end());
    keys.c2s_mac_key = CryptoUtils::evolve_mac_key(keys.c2s_mac_key, nonce_vec);
}

void evolve_s2c_keys(SessionKeys& keys, const ByteVector& aggregated_data,
                     const ByteVector& status_code) {
    // S2C_Enc_R+1 = H(S2C_Enc_R || AggregatedData_R)
    keys.s2c_enc_key = CryptoUtils::evolve_aes_key(keys.s2c_enc_key, aggregated_data);
    
    // S2C_Mac_R+1 = H(S2C_Mac_R || StatusCode_R)
    keys.s2c_mac_key = CryptoUtils::evolve_mac_key(keys.s2c_mac_key, status_code);
}

// ============================================================================
// Message Building Implementation
// ============================================================================

ByteVector build_message(Opcode opcode, uint8_t client_id, uint32_t round,
                         Direction direction, const ByteVector& payload,
                         const AESKey& enc_key, const MACKey& mac_key) {
    // Generate random IV
    IV iv = CryptoUtils::generate_random_iv();
    
    // Pad and encrypt payload
    ByteVector padded = CryptoUtils::pkcs7_pad(payload);
    ByteVector ciphertext = CryptoUtils::aes_cbc_encrypt(padded, enc_key, iv);
    
    // Build message: Header || Ciphertext || HMAC
    ByteVector message;
    message.reserve(HEADER_SIZE + ciphertext.size() + HMAC_SIZE);
    
    // Add header fields
    message.push_back(static_cast<uint8_t>(opcode));
    message.push_back(client_id);
    
    // Round in network byte order
    uint32_t round_net = hton32(round);
    uint8_t* round_bytes = reinterpret_cast<uint8_t*>(&round_net);
    message.insert(message.end(), round_bytes, round_bytes + 4);
    
    message.push_back(static_cast<uint8_t>(direction));
    
    // Add IV
    message.insert(message.end(), iv.begin(), iv.end());
    
    // Add ciphertext
    message.insert(message.end(), ciphertext.begin(), ciphertext.end());
    
    // Compute HMACTag over (Header || Ciphertext)
    HMACTag hmac = CryptoUtils::hmac_sha256(mac_key, message);
    
    // Append HMAC
    message.insert(message.end(), hmac.begin(), hmac.end());
    
    return message;
}

ByteVector build_hello_message(uint8_t client_id, uint32_t round,
                               const MACKey& mac_key) {
    // CLIENT_HELLO has minimal payload - just the header with zero IV
    IV iv = {};  // Zero IV for HELLO (no encryption)
    
    ByteVector message;
    message.reserve(HEADER_SIZE + HMAC_SIZE);
    
    // Add header fields
    message.push_back(static_cast<uint8_t>(Opcode::CLIENT_HELLO));
    message.push_back(client_id);
    
    // Round in network byte order
    uint32_t round_net = hton32(round);
    uint8_t* round_bytes = reinterpret_cast<uint8_t*>(&round_net);
    message.insert(message.end(), round_bytes, round_bytes + 4);
    
    message.push_back(static_cast<uint8_t>(Direction::CLIENT_TO_SERVER));
    
    // Add zero IV
    message.insert(message.end(), iv.begin(), iv.end());
    
    // Compute HMAC
    HMACTag hmac = CryptoUtils::hmac_sha256(mac_key, message);
    
    // Append HMAC
    message.insert(message.end(), hmac.begin(), hmac.end());
    
    return message;
}

ByteVector build_error_message(Opcode opcode, uint8_t client_id, uint32_t round,
                               Direction direction, const MACKey& mac_key) {
    IV iv = {};  // Zero IV for error messages
    
    ByteVector message;
    message.reserve(HEADER_SIZE + HMAC_SIZE);
    
    // Add header
    message.push_back(static_cast<uint8_t>(opcode));
    message.push_back(client_id);
    
    uint32_t round_net = hton32(round);
    uint8_t* round_bytes = reinterpret_cast<uint8_t*>(&round_net);
    message.insert(message.end(), round_bytes, round_bytes + 4);
    
    message.push_back(static_cast<uint8_t>(direction));
    message.insert(message.end(), iv.begin(), iv.end());
    
    // Compute HMAC
    HMACTag hmac = CryptoUtils::hmac_sha256(mac_key, message);
    message.insert(message.end(), hmac.begin(), hmac.end());
    
    return message;
}

// ============================================================================
// Message Parsing and Verification Implementation
// ============================================================================

ParsedMessage parse_header(const ByteVector& raw_message) {
    ParsedMessage parsed;
    parsed.valid = false;
    
    // Minimum message size: header + HMACTag (no ciphertext for some messages)
    if (raw_message.size() < HEADER_SIZE + HMAC_SIZE) {
        parsed.error_message = "Message too short";
        return parsed;
    }
    
    // Parse header
    parsed.opcode = static_cast<Opcode>(raw_message[0]);
    parsed.client_id = raw_message[1];
    
    uint32_t round_net;
    std::memcpy(&round_net, &raw_message[2], 4);
    parsed.round = ntoh32(round_net);
    
    parsed.direction = static_cast<Direction>(raw_message[6]);
    
    std::copy(raw_message.begin() + 7, raw_message.begin() + 7 + IV_SIZE, 
              parsed.iv.begin());
    
    // Extract ciphertext and HMAC
    size_t ciphertext_size = raw_message.size() - HEADER_SIZE - HMAC_SIZE;
    if (ciphertext_size > 0) {
        parsed.ciphertext.assign(raw_message.begin() + HEADER_SIZE,
                                 raw_message.end() - HMAC_SIZE);
    }
    
    std::copy(raw_message.end() - HMAC_SIZE, raw_message.end(), 
              parsed.hmac.begin());
    
    parsed.valid = true;
    return parsed;
}

ParsedMessage parse_and_verify(const ByteVector& raw_message,
                               uint32_t expected_round,
                               Direction expected_direction,
                               const MACKey& mac_key,
                               const AESKey* enc_key) {
    ParsedMessage parsed = parse_header(raw_message);
    if (!parsed.valid) {
        return parsed;
    }
    
    // ==========================================
    // CRITICAL: Verify HMACTag BEFORE decryption
    // ==========================================
    
    // Data covered by HMAC: everything except the HMACTag itself
    ByteVector hmac_data(raw_message.begin(), raw_message.end() - HMAC_SIZE);
    
    if (!CryptoUtils::hmac_verify(mac_key, hmac_data, parsed.hmac)) {
        parsed.valid = false;
        parsed.error_message = "HMAC verification failed";
        return parsed;
    }
    
    // Verify round number
    if (parsed.round != expected_round) {
        parsed.valid = false;
        parsed.error_message = "Round number mismatch (expected " + 
                               std::to_string(expected_round) + ", got " +
                               std::to_string(parsed.round) + ")";
        return parsed;
    }
    
    // Verify direction
    if (parsed.direction != expected_direction) {
        parsed.valid = false;
        parsed.error_message = "Direction mismatch";
        return parsed;
    }
    
    // Decrypt if encryption key provided and there's ciphertext
    if (enc_key && !parsed.ciphertext.empty()) {
        try {
            ByteVector decrypted = CryptoUtils::aes_cbc_decrypt(
                parsed.ciphertext, *enc_key, parsed.iv);
            parsed.decrypted_payload = CryptoUtils::pkcs7_unpad(decrypted);
        } catch (const std::exception& e) {
            parsed.valid = false;
            parsed.error_message = std::string("Decryption failed: ") + e.what();
            return parsed;
        }
    }
    
    parsed.valid = true;
    return parsed;
}

// ============================================================================
// State Machine Operations
// ============================================================================

bool is_valid_opcode(ProtocolPhase phase, Opcode opcode, Direction direction) {
    switch (phase) {
        case ProtocolPhase::INIT:
            // In INIT: 
            // - Client can send CLIENT_HELLO
            // - Server can send SERVER_CHALLENGE
            if (direction == Direction::CLIENT_TO_SERVER) {
                return opcode == Opcode::CLIENT_HELLO;
            } else {
                return opcode == Opcode::SERVER_CHALLENGE;
            }
            
        case ProtocolPhase::ACTIVE:
            // In ACTIVE:
            // - Client can send CLIENT_DATA or TERMINATE
            // - Server can send SERVER_AGGR_RESPONSE, KEY_DESYNC_ERROR, or TERMINATE
            if (direction == Direction::CLIENT_TO_SERVER) {
                return opcode == Opcode::CLIENT_DATA || opcode == Opcode::TERMINATE;
            } else {
                return opcode == Opcode::SERVER_AGGR_RESPONSE ||
                       opcode == Opcode::KEY_DESYNC_ERROR ||
                       opcode == Opcode::TERMINATE;
            }
            
        case ProtocolPhase::TERMINATED:
            // No messages are valid in TERMINATED state
            return false;
            
        default:
            return false;
    }
}

ProtocolPhase get_next_phase(ProtocolPhase current_phase, Opcode opcode,
                             Direction direction) {
    // Termination always leads to TERMINATED
    if (opcode == Opcode::TERMINATE || opcode == Opcode::KEY_DESYNC_ERROR) {
        return ProtocolPhase::TERMINATED;
    }
    
    switch (current_phase) {
        case ProtocolPhase::INIT:
            // After SERVER_CHALLENGE, transition to ACTIVE
            if (direction == Direction::SERVER_TO_CLIENT &&
                opcode == Opcode::SERVER_CHALLENGE) {
                return ProtocolPhase::ACTIVE;
            }
            return ProtocolPhase::INIT;
            
        case ProtocolPhase::ACTIVE:
            // Stay in ACTIVE during normal operation
            return ProtocolPhase::ACTIVE;
            
        case ProtocolPhase::TERMINATED:
            return ProtocolPhase::TERMINATED;
            
        default:
            return ProtocolPhase::TERMINATED;
    }
}

SessionState initialize_session(uint8_t client_id, const ByteVector& master_key) {
    SessionState state;
    state.client_id = client_id;
    state.round = 0;
    state.phase = ProtocolPhase::INIT;
    state.keys = initialize_keys(master_key);
    state.master_key = master_key;
    state.socket_fd = -1;
    state.valid = true;
    return state;
}

ParsedMessage process_message(SessionState& state, const ByteVector& raw_message,
                              Direction expected_direction) {
    ParsedMessage parsed;
    parsed.valid = false;
    
    // Check if session is terminated
    if (state.phase == ProtocolPhase::TERMINATED) {
        parsed.error_message = "Session is terminated";
        return parsed;
    }
    
    // Determine which keys to use based on direction
    const MACKey* mac_key;
    const AESKey* enc_key;
    
    if (expected_direction == Direction::CLIENT_TO_SERVER) {
        mac_key = &state.keys.c2s_mac_key;
        enc_key = &state.keys.c2s_enc_key;
    } else {
        mac_key = &state.keys.s2c_mac_key;
        enc_key = &state.keys.s2c_enc_key;
    }
    
    // Parse and verify
    parsed = parse_and_verify(raw_message, state.round, expected_direction,
                              *mac_key, enc_key);
    
    if (!parsed.valid) {
        // Any verification failure terminates the session
        terminate_session(state);
        return parsed;
    }
    
    // Check if opcode is valid for current phase
    if (!is_valid_opcode(state.phase, parsed.opcode, expected_direction)) {
        parsed.valid = false;
        parsed.error_message = "Invalid opcode for current phase";
        terminate_session(state);
        return parsed;
    }
    
    // Update phase
    state.phase = get_next_phase(state.phase, parsed.opcode, expected_direction);
    
    return parsed;
}

void terminate_session(SessionState& state) {
    state.phase = ProtocolPhase::TERMINATED;
    state.valid = false;
    
    // Zero out keys for security
    std::fill(state.keys.c2s_enc_key.begin(), state.keys.c2s_enc_key.end(), 0);
    std::fill(state.keys.c2s_mac_key.begin(), state.keys.c2s_mac_key.end(), 0);
    std::fill(state.keys.s2c_enc_key.begin(), state.keys.s2c_enc_key.end(), 0);
    std::fill(state.keys.s2c_mac_key.begin(), state.keys.s2c_mac_key.end(), 0);
}

// ============================================================================
// Utility Functions
// ============================================================================

ByteVector uint32_to_bytes(uint32_t value) {
    ByteVector bytes(4);
    bytes[0] = (value >> 24) & 0xFF;
    bytes[1] = (value >> 16) & 0xFF;
    bytes[2] = (value >> 8) & 0xFF;
    bytes[3] = value & 0xFF;
    return bytes;
}

ByteVector serialize_client_data(int32_t data) {
    // 4-byte big-endian integer
    ByteVector payload(4);
    uint32_t udata = static_cast<uint32_t>(data);
    payload[0] = (udata >> 24) & 0xFF;
    payload[1] = (udata >> 16) & 0xFF;
    payload[2] = (udata >> 8) & 0xFF;
    payload[3] = udata & 0xFF;
    return payload;
}

int32_t deserialize_client_data(const ByteVector& payload) {
    if (payload.size() < 4) {
        throw std::runtime_error("Payload too short for client data");
    }
    uint32_t udata = ((uint32_t)payload[0] << 24) |
                     ((uint32_t)payload[1] << 16) |
                     ((uint32_t)payload[2] << 8) |
                     (uint32_t)payload[3];
    return static_cast<int32_t>(udata);
}

ByteVector serialize_aggregation(int32_t count, int32_t sum, uint32_t status_code) {
    // 4-byte count || 4-byte sum || 4-byte status_code
    ByteVector payload(12);
    
    // Count
    uint32_t ucount = static_cast<uint32_t>(count);
    payload[0] = (ucount >> 24) & 0xFF;
    payload[1] = (ucount >> 16) & 0xFF;
    payload[2] = (ucount >> 8) & 0xFF;
    payload[3] = ucount & 0xFF;
    
    // Sum
    uint32_t usum = static_cast<uint32_t>(sum);
    payload[4] = (usum >> 24) & 0xFF;
    payload[5] = (usum >> 16) & 0xFF;
    payload[6] = (usum >> 8) & 0xFF;
    payload[7] = usum & 0xFF;
    
    // Status code
    payload[8] = (status_code >> 24) & 0xFF;
    payload[9] = (status_code >> 16) & 0xFF;
    payload[10] = (status_code >> 8) & 0xFF;
    payload[11] = status_code & 0xFF;
    
    return payload;
}

void deserialize_aggregation(const ByteVector& payload, int32_t& count,
                             int32_t& sum, uint32_t& status_code) {
    if (payload.size() < 12) {
        throw std::runtime_error("Payload too short for aggregation data");
    }
    
    // Count
    uint32_t ucount = ((uint32_t)payload[0] << 24) |
                      ((uint32_t)payload[1] << 16) |
                      ((uint32_t)payload[2] << 8) |
                      (uint32_t)payload[3];
    count = static_cast<int32_t>(ucount);
    
    // Sum
    uint32_t usum = ((uint32_t)payload[4] << 24) |
                    ((uint32_t)payload[5] << 16) |
                    ((uint32_t)payload[6] << 8) |
                    (uint32_t)payload[7];
    sum = static_cast<int32_t>(usum);
    
    // Status code
    status_code = ((uint32_t)payload[8] << 24) |
                  ((uint32_t)payload[9] << 16) |
                  ((uint32_t)payload[10] << 8) |
                  (uint32_t)payload[11];
}

ByteVector serialize_challenge(const ByteVector& challenge, uint32_t timestamp) {
    // 8-byte challenge || 4-byte timestamp
    ByteVector payload;
    payload.reserve(12);
    
    // Add challenge (pad or truncate to 8 bytes)
    for (size_t i = 0; i < 8; ++i) {
        if (i < challenge.size()) {
            payload.push_back(challenge[i]);
        } else {
            payload.push_back(0);
        }
    }
    
    // Add timestamp
    payload.push_back((timestamp >> 24) & 0xFF);
    payload.push_back((timestamp >> 16) & 0xFF);
    payload.push_back((timestamp >> 8) & 0xFF);
    payload.push_back(timestamp & 0xFF);
    
    return payload;
}

void deserialize_challenge(const ByteVector& payload, ByteVector& challenge,
                           uint32_t& timestamp) {
    if (payload.size() < 12) {
        throw std::runtime_error("Payload too short for challenge data");
    }
    
    // Extract 8-byte challenge
    challenge.assign(payload.begin(), payload.begin() + 8);
    
    // Extract timestamp
    timestamp = ((uint32_t)payload[8] << 24) |
                ((uint32_t)payload[9] << 16) |
                ((uint32_t)payload[10] << 8) |
                (uint32_t)payload[11];
}

} // namespace ProtocolFSM
