#ifndef PROTOCOL_FSM_HPP
#define PROTOCOL_FSM_HPP

#include "common.hpp"
#include "crypto_utils.hpp"
#include <functional>
#include <optional>

// ============================================================================
// Protocol Finite State Machine
// ============================================================================
// This module implements:
// - Protocol state management (INIT -> ACTIVE -> TERMINATED)
// - Message construction and parsing
// - Key initialization and evolution (ratcheting)
// - Opcode validation based on current phase
// - Round number tracking and validation
// ============================================================================

namespace ProtocolFSM {

// ============================================================================
// Error codes for protocol operations
// ============================================================================

enum class ProtocolError {
    SUCCESS = 0,
    INVALID_OPCODE,
    INVALID_ROUND,
    INVALID_DIRECTION,
    HMAC_VERIFICATION_FAILED,
    DECRYPTION_FAILED,
    INVALID_PADDING,
    INVALID_PAYLOAD,
    SESSION_TERMINATED,
    INVALID_STATE_TRANSITION,
    UNKNOWN_CLIENT,
    MESSAGE_TOO_SHORT,
    MESSAGE_TOO_LONG
};

// Convert error code to string
const char* error_to_string(ProtocolError err);

// ============================================================================
// Key Management
// ============================================================================

/**
 * Initialize session keys from master key.
 * Derives initial C2S and S2C encryption/MAC keys.
 * 
 * @param master_key Pre-shared master key
 * @return Initialized session keys
 */
SessionKeys initialize_keys(const ByteVector& master_key);

/**
 * Evolve client->server keys after successful message processing.
 * C2S_Enc_R+1 = H(C2S_Enc_R || Ciphertext_R)
 * C2S_Mac_R+1 = H(C2S_Mac_R || Nonce_R)
 * 
 * @param keys Current session keys (modified in place)
 * @param ciphertext Ciphertext from the message
 * @param nonce Nonce/IV from the message
 */
void evolve_c2s_keys(SessionKeys& keys, const ByteVector& ciphertext, const IV& nonce);

/**
 * Evolve server->client keys after successful response.
 * S2C_Enc_R+1 = H(S2C_Enc_R || AggregatedData_R)
 * S2C_Mac_R+1 = H(S2C_Mac_R || StatusCode_R)
 * 
 * @param keys Current session keys (modified in place)
 * @param aggregated_data Aggregated data from the response
 * @param status_code Status code bytes
 */
void evolve_s2c_keys(SessionKeys& keys, const ByteVector& aggregated_data, 
                     const ByteVector& status_code);

// ============================================================================
// Message Building
// ============================================================================

/**
 * Build a complete protocol message.
 * 
 * @param opcode Message opcode
 * @param client_id Client identifier
 * @param round Current round number
 * @param direction Message direction
 * @param payload Plaintext payload to encrypt
 * @param enc_key Encryption key
 * @param mac_key MAC key
 * @return Complete message bytes (header || ciphertext || HMAC)
 */
ByteVector build_message(Opcode opcode, uint8_t client_id, uint32_t round,
                         Direction direction, const ByteVector& payload,
                         const AESKey& enc_key, const MACKey& mac_key);

/**
 * Build an unencrypted message (for CLIENT_HELLO which has no payload encryption).
 * 
 * @param opcode Message opcode
 * @param client_id Client identifier
 * @param round Round number
 * @param direction Message direction
 * @param mac_key MAC key
 * @return Complete message bytes
 */
ByteVector build_hello_message(uint8_t client_id, uint32_t round,
                               const MACKey& mac_key);

/**
 * Build an error/termination message.
 */
ByteVector build_error_message(Opcode opcode, uint8_t client_id, uint32_t round,
                               Direction direction, const MACKey& mac_key);

// ============================================================================
// Message Parsing and Verification
// ============================================================================

/**
 * Parse and verify a received message.
 * IMPORTANT: Verifies HMACTag before any decryption (as per assignment).
 * 
 * @param raw_message Raw received message bytes
 * @param expected_round Expected round number
 * @param expected_direction Expected direction
 * @param mac_key MAC key for verification
 * @param enc_key Encryption key for decryption (optional for unencrypted messages)
 * @return ParsedMessage with validation result
 */
ParsedMessage parse_and_verify(const ByteVector& raw_message,
                               uint32_t expected_round,
                               Direction expected_direction,
                               const MACKey& mac_key,
                               const AESKey* enc_key = nullptr);

/**
 * Parse message header only (for initial inspection).
 * Does NOT verify HMACTag or decrypt.
 * 
 * @param raw_message Raw received message bytes
 * @return ParsedMessage with header fields only
 */
ParsedMessage parse_header(const ByteVector& raw_message);

// ============================================================================
// State Machine Operations
// ============================================================================

/**
 * Validate that an opcode is valid for the current protocol phase.
 * 
 * @param phase Current protocol phase
 * @param opcode Received opcode
 * @param direction Message direction
 * @return true if opcode is valid, false otherwise
 */
bool is_valid_opcode(ProtocolPhase phase, Opcode opcode, Direction direction);

/**
 * Get next protocol phase after processing a message.
 * 
 * @param current_phase Current phase
 * @param opcode Processed opcode
 * @param direction Message direction
 * @return Next protocol phase
 */
ProtocolPhase get_next_phase(ProtocolPhase current_phase, Opcode opcode, 
                             Direction direction);

/**
 * Initialize a new session state for a client.
 * 
 * @param client_id Client identifier
 * @param master_key Pre-shared master key
 * @return Initialized session state
 */
SessionState initialize_session(uint8_t client_id, const ByteVector& master_key);

/**
 * Process a received message and update session state.
 * Performs all validations (round, opcode, HMAC) and decryption.
 * On failure, session is terminated.
 * 
 * @param state Session state (modified on success or failure)
 * @param raw_message Raw received message
 * @param expected_direction Expected direction of the message
 * @return Parsed message with result
 */
ParsedMessage process_message(SessionState& state, const ByteVector& raw_message,
                              Direction expected_direction);

/**
 * Terminate a session immediately.
 * 
 * @param state Session state to terminate
 */
void terminate_session(SessionState& state);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Serialize a 32-bit value into bytes for key evolution.
 */
ByteVector uint32_to_bytes(uint32_t value);

/**
 * Serialize a payload for CLIENT_DATA (numeric data).
 * Format: 4-byte big-endian integer
 */
ByteVector serialize_client_data(int32_t data);

/**
 * Deserialize CLIENT_DATA payload.
 */
int32_t deserialize_client_data(const ByteVector& payload);

/**
 * Serialize SERVER_AGGR_RESPONSE payload.
 * Format: 4-byte count || 4-byte sum || 4-byte status_code
 */
ByteVector serialize_aggregation(int32_t count, int32_t sum, uint32_t status_code);

/**
 * Deserialize SERVER_AGGR_RESPONSE payload.
 */
void deserialize_aggregation(const ByteVector& payload, int32_t& count, 
                             int32_t& sum, uint32_t& status_code);

/**
 * Serialize challenge payload for SERVER_CHALLENGE.
 * Format: 8-byte random challenge || 4-byte timestamp
 */
ByteVector serialize_challenge(const ByteVector& challenge, uint32_t timestamp);

/**
 * Deserialize SERVER_CHALLENGE payload.
 */
void deserialize_challenge(const ByteVector& payload, ByteVector& challenge, 
                           uint32_t& timestamp);

} // namespace ProtocolFSM

#endif // PROTOCOL_FSM_HPP
