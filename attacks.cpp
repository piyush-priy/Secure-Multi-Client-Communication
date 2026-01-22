/**
 * Attack Demonstration Module
 * 
 * This module demonstrates various attack scenarios against the secure
 * communication protocol and shows how the protocol defends against them.
 * 
 * Attack Scenarios:
 * 1. Replay Attack - Resending a captured message
 * 2. HMACTag Tampering - Modifying ciphertext without updating HMAC
 * 3. Message Reordering - Sending messages out of sequence
 * 4. Reflection Attack - Sending C2S message back to client
 * 5. Key Desynchronization - Forcing key mismatch
 */

#include "protocol_fsm.hpp"
#include <iostream>
#include <iomanip>
#include <cstring>

// POSIX networking
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

// ============================================================================
// Utility Functions
// ============================================================================

void print_header(const std::string& title) {
    std::cout << "\n";
    std::cout << "============================================================\n";
    std::cout << "  " << title << "\n";
    std::cout << "============================================================\n";
}

void print_result(const std::string& attack_name, bool success) {
    std::cout << "\n[RESULT] " << attack_name << ": ";
    if (success) {
        std::cout << "\033[32mPROTOCOL DEFENDED SUCCESSFULLY\033[0m\n";
    } else {
        std::cout << "\033[31mATTACK SUCCEEDED (VULNERABILITY!)\033[0m\n";
    }
}

void print_bytes(const std::string& label, const ByteVector& data, size_t max_len = 32) {
    std::cout << label << ": ";
    size_t len = std::min(data.size(), max_len);
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << (int)data[i];
    }
    if (data.size() > max_len) {
        std::cout << "... (" << std::dec << data.size() << " bytes total)";
    }
    std::cout << std::dec << "\n";
}

// Network helper (same as client)
bool send_message(int sock, const ByteVector& message) {
    ByteVector data;
    data.reserve(4 + message.size());
    
    uint32_t len = static_cast<uint32_t>(message.size());
    data.push_back((len >> 24) & 0xFF);
    data.push_back((len >> 16) & 0xFF);
    data.push_back((len >> 8) & 0xFF);
    data.push_back(len & 0xFF);
    
    data.insert(data.end(), message.begin(), message.end());
    
    size_t total_sent = 0;
    while (total_sent < data.size()) {
        ssize_t sent = send(sock, data.data() + total_sent, 
                           data.size() - total_sent, 0);
        if (sent <= 0) return false;
        total_sent += sent;
    }
    return true;
}

ByteVector receive_message(int sock) {
    uint8_t len_buf[4];
    size_t received = 0;
    while (received < 4) {
        ssize_t r = recv(sock, len_buf + received, 4 - received, 0);
        if (r <= 0) return {};
        received += r;
    }
    
    uint32_t msg_len = ((uint32_t)len_buf[0] << 24) |
                       ((uint32_t)len_buf[1] << 16) |
                       ((uint32_t)len_buf[2] << 8) |
                       (uint32_t)len_buf[3];
    
    if (msg_len > MAX_PAYLOAD_SIZE) return {};
    
    ByteVector message(msg_len);
    received = 0;
    while (received < msg_len) {
        ssize_t r = recv(sock, message.data() + received, msg_len - received, 0);
        if (r <= 0) return {};
        received += r;
    }
    
    return message;
}

int connect_to_server(const std::string& host, uint16_t port) {
    struct hostent* server = gethostbyname(host.c_str());
    if (!server) return -1;
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    std::memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    
    return sock;
}

// ============================================================================
// Attack 1: Replay Attack
// ============================================================================

bool test_replay_attack(const std::string& host, uint16_t port, 
                        uint8_t client_id, const ByteVector& master_key) {
    print_header("ATTACK 1: Replay Attack");
    std::cout << "Description: Capture a valid message and replay it later.\n";
    std::cout << "Expected: Server should reject due to round number mismatch.\n\n";
    
    // First connection - establish session and capture a message
    int sock1 = connect_to_server(host, port);
    if (sock1 < 0) {
        std::cout << "Failed to connect for initial session\n";
        return false;
    }
    
    SessionState session = ProtocolFSM::initialize_session(client_id, master_key);
    
    // Send legitimate HELLO
    ByteVector hello_msg = ProtocolFSM::build_hello_message(
        client_id, session.round, session.keys.c2s_mac_key);
    
    std::cout << "Step 1: Establishing legitimate session...\n";
    print_bytes("Captured HELLO message", hello_msg);
    
    send_message(sock1, hello_msg);
    
    // Receive challenge
    ByteVector challenge = receive_message(sock1);
    if (challenge.empty()) {
        std::cout << "Failed to receive challenge\n";
        close(sock1);
        return false;
    }
    std::cout << "Step 2: Received SERVER_CHALLENGE\n";
    
    close(sock1);
    
    // Now try to replay the captured HELLO
    std::cout << "\nStep 3: Attempting replay attack with captured HELLO...\n";
    
    int sock2 = connect_to_server(host, port);
    if (sock2 < 0) {
        std::cout << "Failed to connect for replay\n";
        return false;
    }
    
    // Replay the same HELLO message
    std::cout << "Replaying exact same message to server...\n";
    send_message(sock2, hello_msg);
    
    // Try to receive response
    ByteVector response = receive_message(sock2);
    close(sock2);
    
    // The server should accept the first HELLO (same round 0)
    // But if we try to replay AFTER the first session, the server
    // should reject because the session exists or is in wrong state
    
    // Actually, for a proper replay test, we need to replay a DATA message
    // Let me implement a more complete test
    
    std::cout << "\n--- Testing DATA message replay ---\n";
    
    // New connection
    int sock3 = connect_to_server(host, port);
    if (sock3 < 0) return false;
    
    SessionState session2 = ProtocolFSM::initialize_session(client_id + 10, master_key);
    
    // Complete handshake
    ByteVector hello2 = ProtocolFSM::build_hello_message(
        client_id + 10, session2.round, session2.keys.c2s_mac_key);
    send_message(sock3, hello2);
    
    ByteVector chal2 = receive_message(sock3);
    if (chal2.empty()) {
        close(sock3);
        return false;
    }
    
    // Update state after challenge
    ByteVector status = ProtocolFSM::uint32_to_bytes(0);
    ProtocolFSM::evolve_s2c_keys(session2.keys, 
                                  ByteVector(chal2.begin() + HEADER_SIZE, chal2.end() - HMAC_SIZE),
                                  status);
    session2.round++;
    session2.phase = ProtocolPhase::ACTIVE;
    
    // Send legitimate DATA for round 1
    ByteVector payload = ProtocolFSM::serialize_client_data(42);
    ByteVector data_msg = ProtocolFSM::build_message(
        Opcode::CLIENT_DATA,
        client_id + 10,
        session2.round,
        Direction::CLIENT_TO_SERVER,
        payload,
        session2.keys.c2s_enc_key,
        session2.keys.c2s_mac_key
    );
    
    print_bytes("Captured DATA message (round 1)", data_msg);
    send_message(sock3, data_msg);
    
    // Get response (this should succeed)
    ByteVector resp = receive_message(sock3);
    
    // Update keys
    ByteVector ct(data_msg.begin() + HEADER_SIZE, data_msg.end() - HMAC_SIZE);
    IV iv;
    std::copy(data_msg.begin() + 7, data_msg.begin() + 7 + IV_SIZE, iv.begin());
    ProtocolFSM::evolve_c2s_keys(session2.keys, ct, iv);
    
    if (!resp.empty()) {
        ByteVector resp_payload(resp.begin() + HEADER_SIZE, resp.end() - HMAC_SIZE);
        ProtocolFSM::evolve_s2c_keys(session2.keys, resp_payload, status);
    }
    session2.round++;
    
    // Now try to replay the same DATA message (round 1) when we're at round 2
    std::cout << "\nStep 4: Replaying old DATA message (round 1) at round 2...\n";
    send_message(sock3, data_msg);
    
    // The server should reject this
    ByteVector replay_resp = receive_message(sock3);
    close(sock3);
    
    // Check if replay was rejected
    if (replay_resp.empty()) {
        std::cout << "Server closed connection (rejected replay)\n";
        return true;  // Attack defended
    }
    
    ParsedMessage parsed = ProtocolFSM::parse_header(replay_resp);
    if (parsed.opcode == Opcode::KEY_DESYNC_ERROR || 
        parsed.opcode == Opcode::TERMINATE) {
        std::cout << "Server sent error/terminate (rejected replay)\n";
        return true;  // Attack defended
    }
    
    return false;  // Attack succeeded (bad)
}

// ============================================================================
// Attack 2: HMACTag Tampering
// ============================================================================

bool test_hmac_tampering(const std::string& host, uint16_t port,
                         uint8_t client_id, const ByteVector& master_key) {
    print_header("ATTACK 2: HMACTag Tampering");
    std::cout << "Description: Modify ciphertext without updating HMAC.\n";
    std::cout << "Expected: Server should reject due to HMACTag verification failure.\n\n";
    
    int sock = connect_to_server(host, port);
    if (sock < 0) {
        std::cout << "Failed to connect\n";
        return false;
    }
    
    SessionState session = ProtocolFSM::initialize_session(client_id, master_key);
    
    // Send legitimate HELLO
    ByteVector hello = ProtocolFSM::build_hello_message(
        client_id, session.round, session.keys.c2s_mac_key);
    send_message(sock, hello);
    
    ByteVector challenge = receive_message(sock);
    if (challenge.empty()) {
        close(sock);
        return false;
    }
    
    // Update state
    ByteVector status = ProtocolFSM::uint32_to_bytes(0);
    ParsedMessage chal_parsed = ProtocolFSM::parse_and_verify(
        challenge, session.round, Direction::SERVER_TO_CLIENT,
        session.keys.s2c_mac_key, &session.keys.s2c_enc_key);
    
    if (chal_parsed.valid) {
        ProtocolFSM::evolve_s2c_keys(session.keys, chal_parsed.decrypted_payload, status);
    }
    session.round++;
    session.phase = ProtocolPhase::ACTIVE;
    
    // Build legitimate DATA message
    ByteVector payload = ProtocolFSM::serialize_client_data(100);
    ByteVector data_msg = ProtocolFSM::build_message(
        Opcode::CLIENT_DATA,
        client_id,
        session.round,
        Direction::CLIENT_TO_SERVER,
        payload,
        session.keys.c2s_enc_key,
        session.keys.c2s_mac_key
    );
    
    std::cout << "Original message:\n";
    print_bytes("  Ciphertext", ByteVector(data_msg.begin() + HEADER_SIZE, 
                                            data_msg.end() - HMAC_SIZE));
    
    // Tamper with the ciphertext (flip some bits)
    ByteVector tampered = data_msg;
    if (tampered.size() > HEADER_SIZE + 5) {
        tampered[HEADER_SIZE + 0] ^= 0xFF;  // Flip bits in ciphertext
        tampered[HEADER_SIZE + 1] ^= 0xAA;
        tampered[HEADER_SIZE + 2] ^= 0x55;
    }
    
    std::cout << "\nTampered message (modified ciphertext, same HMAC):\n";
    print_bytes("  Ciphertext", ByteVector(tampered.begin() + HEADER_SIZE,
                                            tampered.end() - HMAC_SIZE));
    
    std::cout << "\nSending tampered message...\n";
    send_message(sock, tampered);
    
    ByteVector response = receive_message(sock);
    close(sock);
    
    // Check if tampering was detected
    if (response.empty()) {
        std::cout << "Server closed connection (detected tampering)\n";
        return true;
    }
    
    ParsedMessage parsed = ProtocolFSM::parse_header(response);
    if (parsed.opcode == Opcode::KEY_DESYNC_ERROR) {
        std::cout << "Server sent KEY_DESYNC_ERROR (detected tampering)\n";
        return true;
    }
    
    return false;
}

// ============================================================================
// Attack 3: Message Reordering
// ============================================================================

bool test_message_reordering(const std::string& host, uint16_t port,
                             uint8_t client_id, const ByteVector& master_key) {
    print_header("ATTACK 3: Message Reordering");
    std::cout << "Description: Send messages with incorrect round numbers.\n";
    std::cout << "Expected: Server should reject due to round mismatch.\n\n";
    
    int sock = connect_to_server(host, port);
    if (sock < 0) {
        std::cout << "Failed to connect\n";
        return false;
    }
    
    SessionState session = ProtocolFSM::initialize_session(client_id, master_key);
    
    // Complete handshake first
    ByteVector hello = ProtocolFSM::build_hello_message(
        client_id, session.round, session.keys.c2s_mac_key);
    send_message(sock, hello);
    
    ByteVector challenge = receive_message(sock);
    if (challenge.empty()) {
        close(sock);
        return false;
    }
    
    ByteVector status = ProtocolFSM::uint32_to_bytes(0);
    ParsedMessage chal = ProtocolFSM::parse_and_verify(
        challenge, session.round, Direction::SERVER_TO_CLIENT,
        session.keys.s2c_mac_key, &session.keys.s2c_enc_key);
    
    if (chal.valid) {
        ProtocolFSM::evolve_s2c_keys(session.keys, chal.decrypted_payload, status);
    }
    session.round++;  // Now at round 1
    session.phase = ProtocolPhase::ACTIVE;
    
    std::cout << "Current round: " << session.round << "\n";
    
    // Try to send a message with round 5 (skipping ahead)
    uint32_t future_round = 5;
    std::cout << "Attempting to send message with round " << future_round << " (skipping ahead)...\n";
    
    ByteVector payload = ProtocolFSM::serialize_client_data(999);
    ByteVector future_msg = ProtocolFSM::build_message(
        Opcode::CLIENT_DATA,
        client_id,
        future_round,  // Wrong round!
        Direction::CLIENT_TO_SERVER,
        payload,
        session.keys.c2s_enc_key,
        session.keys.c2s_mac_key
    );
    
    send_message(sock, future_msg);
    
    ByteVector response = receive_message(sock);
    close(sock);
    
    if (response.empty()) {
        std::cout << "Server closed connection (rejected out-of-order message)\n";
        return true;
    }
    
    ParsedMessage parsed = ProtocolFSM::parse_header(response);
    if (parsed.opcode == Opcode::KEY_DESYNC_ERROR ||
        parsed.opcode == Opcode::TERMINATE) {
        std::cout << "Server sent error (rejected out-of-order message)\n";
        return true;
    }
    
    return false;
}

// ============================================================================
// Attack 4: Reflection Attack
// ============================================================================

bool test_reflection_attack(const std::string& host, uint16_t port,
                            uint8_t client_id, const ByteVector& master_key) {
    print_header("ATTACK 4: Reflection Attack");
    std::cout << "Description: Send a S2C message back to server as if from client.\n";
    std::cout << "Expected: Server should reject due to direction mismatch.\n\n";
    
    int sock = connect_to_server(host, port);
    if (sock < 0) {
        std::cout << "Failed to connect\n";
        return false;
    }
    
    SessionState session = ProtocolFSM::initialize_session(client_id, master_key);
    
    // Complete handshake
    ByteVector hello = ProtocolFSM::build_hello_message(
        client_id, session.round, session.keys.c2s_mac_key);
    send_message(sock, hello);
    
    ByteVector challenge = receive_message(sock);
    if (challenge.empty()) {
        close(sock);
        return false;
    }
    
    std::cout << "Received SERVER_CHALLENGE (direction: S2C)\n";
    print_bytes("Challenge message", challenge);
    
    // Try to reflect the challenge back to server
    std::cout << "\nAttempting to reflect SERVER_CHALLENGE back to server...\n";
    send_message(sock, challenge);
    
    ByteVector response = receive_message(sock);
    close(sock);
    
    if (response.empty()) {
        std::cout << "Server closed connection (rejected reflected message)\n";
        return true;
    }
    
    ParsedMessage parsed = ProtocolFSM::parse_header(response);
    if (parsed.opcode == Opcode::KEY_DESYNC_ERROR ||
        parsed.opcode == Opcode::TERMINATE) {
        std::cout << "Server sent error (rejected reflected message)\n";
        return true;
    }
    
    return false;
}

// ============================================================================
// Attack 5: Invalid Opcode Attack
// ============================================================================

bool test_invalid_opcode(const std::string& host, uint16_t port,
                         uint8_t client_id, const ByteVector& master_key) {
    print_header("ATTACK 5: Invalid Opcode for State");
    std::cout << "Description: Send CLIENT_DATA before completing handshake.\n";
    std::cout << "Expected: Server should reject due to invalid opcode for INIT state.\n\n";
    
    int sock = connect_to_server(host, port);
    if (sock < 0) {
        std::cout << "Failed to connect\n";
        return false;
    }
    
    SessionState session = ProtocolFSM::initialize_session(client_id, master_key);
    
    // Try to send CLIENT_DATA without HELLO first
    std::cout << "Sending CLIENT_DATA without completing handshake...\n";
    
    ByteVector payload = ProtocolFSM::serialize_client_data(12345);
    ByteVector data_msg = ProtocolFSM::build_message(
        Opcode::CLIENT_DATA,  // Wrong opcode for INIT state!
        client_id,
        session.round,
        Direction::CLIENT_TO_SERVER,
        payload,
        session.keys.c2s_enc_key,
        session.keys.c2s_mac_key
    );
    
    send_message(sock, data_msg);
    
    ByteVector response = receive_message(sock);
    close(sock);
    
    if (response.empty()) {
        std::cout << "Server closed connection (rejected invalid opcode)\n";
        return true;
    }
    
    ParsedMessage parsed = ProtocolFSM::parse_header(response);
    if (parsed.opcode == Opcode::KEY_DESYNC_ERROR ||
        parsed.opcode == Opcode::TERMINATE) {
        std::cout << "Server sent error (rejected invalid opcode)\n";
        return true;
    }
    
    return false;
}

// ============================================================================
// Local Tests (No Server Required)
// ============================================================================

void test_crypto_primitives() {
    print_header("LOCAL TEST: Cryptographic Primitives");
    
    // Test PKCS#7 Padding
    std::cout << "Testing PKCS#7 Padding...\n";
    ByteVector test_data = {0x01, 0x02, 0x03, 0x04, 0x05};
    ByteVector padded = CryptoUtils::pkcs7_pad(test_data);
    std::cout << "  Original (" << test_data.size() << " bytes): ";
    print_bytes("", test_data);
    std::cout << "  Padded (" << padded.size() << " bytes): ";
    print_bytes("", padded);
    
    ByteVector unpadded = CryptoUtils::pkcs7_unpad(padded);
    std::cout << "  Unpadded (" << unpadded.size() << " bytes): ";
    print_bytes("", unpadded);
    std::cout << "  Padding test: " << (test_data == unpadded ? "PASSED" : "FAILED") << "\n\n";
    
    // Test AES-CBC
    std::cout << "Testing AES-128-CBC...\n";
    AESKey key = {};
    for (int i = 0; i < 16; i++) key[i] = i;
    IV iv = CryptoUtils::generate_random_iv();
    
    ByteVector plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    ByteVector padded_pt = CryptoUtils::pkcs7_pad(plaintext);
    ByteVector ciphertext = CryptoUtils::aes_cbc_encrypt(padded_pt, key, iv);
    ByteVector decrypted = CryptoUtils::aes_cbc_decrypt(ciphertext, key, iv);
    ByteVector final_pt = CryptoUtils::pkcs7_unpad(decrypted);
    
    std::cout << "  Plaintext: ";
    for (uint8_t c : plaintext) std::cout << (char)c;
    std::cout << "\n";
    print_bytes("  Ciphertext", ciphertext);
    std::cout << "  Decrypted: ";
    for (uint8_t c : final_pt) std::cout << (char)c;
    std::cout << "\n";
    std::cout << "  AES test: " << (plaintext == final_pt ? "PASSED" : "FAILED") << "\n\n";
    
    // Test HMAC
    std::cout << "Testing HMAC-SHA256...\n";
    MACKey mac_key = {};
    for (int i = 0; i < 32; i++) mac_key[i] = i;
    ByteVector data = {'T', 'e', 's', 't', ' ', 'D', 'a', 't', 'a'};
    HMACTag hmac1 = CryptoUtils::hmac_sha256(mac_key, data);
    HMACTag hmac2 = CryptoUtils::hmac_sha256(mac_key, data);
    print_bytes("  HMAC", ByteVector(hmac1.begin(), hmac1.end()));
    std::cout << "  HMACTag consistency: " << (hmac1 == hmac2 ? "PASSED" : "FAILED") << "\n";
    std::cout << "  HMACTag verify: " << (CryptoUtils::hmac_verify(mac_key, data, hmac1) ? "PASSED" : "FAILED") << "\n\n";
    
    // Test tampering detection
    std::cout << "Testing tamper detection...\n";
    ByteVector tampered_data = data;
    tampered_data[0] ^= 1;  // Flip one bit
    bool tamper_detected = !CryptoUtils::hmac_verify(mac_key, tampered_data, hmac1);
    std::cout << "  Tamper detection: " << (tamper_detected ? "PASSED" : "FAILED") << "\n";
}

void test_key_evolution() {
    print_header("LOCAL TEST: Key Evolution (Ratcheting)");
    
    ByteVector master_key = hex_to_bytes("0123456789abcdef0123456789abcdef");
    SessionKeys keys = ProtocolFSM::initialize_keys(master_key);
    
    std::cout << "Initial keys derived from master key:\n";
    print_bytes("  C2S Enc", ByteVector(keys.c2s_enc_key.begin(), keys.c2s_enc_key.end()));
    print_bytes("  C2S MAC", ByteVector(keys.c2s_mac_key.begin(), keys.c2s_mac_key.end()));
    print_bytes("  S2C Enc", ByteVector(keys.s2c_enc_key.begin(), keys.s2c_enc_key.end()));
    print_bytes("  S2C MAC", ByteVector(keys.s2c_mac_key.begin(), keys.s2c_mac_key.end()));
    
    // Evolve keys
    ByteVector ciphertext = {0xDE, 0xAD, 0xBE, 0xEF};
    IV nonce = {};
    ProtocolFSM::evolve_c2s_keys(keys, ciphertext, nonce);
    
    std::cout << "\nAfter key evolution (C2S):\n";
    print_bytes("  C2S Enc", ByteVector(keys.c2s_enc_key.begin(), keys.c2s_enc_key.end()));
    print_bytes("  C2S MAC", ByteVector(keys.c2s_mac_key.begin(), keys.c2s_mac_key.end()));
    
    std::cout << "\nKey evolution ensures forward secrecy - old keys cannot be\n";
    std::cout << "recovered even if current keys are compromised.\n";
}

// ============================================================================
// Main
// ============================================================================

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n";
    std::cout << "Options:\n";
    std::cout << "  -s HOST      Server hostname (default: localhost)\n";
    std::cout << "  -p PORT      Server port (default: " << DEFAULT_PORT << ")\n";
    std::cout << "  -i ID        Client ID for tests (default: 100)\n";
    std::cout << "  -k KEY       Master key (hex string)\n";
    std::cout << "  -l           Run local tests only (no server required)\n";
    std::cout << "  -a NUM       Run specific attack test (1-5)\n";
    std::cout << "  -h           Show this help\n";
}

int main(int argc, char* argv[]) {
    std::string host = "localhost";
    uint16_t port = DEFAULT_PORT;
    uint8_t client_id = 100;
    std::string key_hex = "0123456789abcdef0123456789abcdef";  // Default test key
    bool local_only = false;
    int specific_attack = 0;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-s" && i + 1 < argc) {
            host = argv[++i];
        } else if (arg == "-p" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "-i" && i + 1 < argc) {
            client_id = static_cast<uint8_t>(std::stoi(argv[++i]));
        } else if (arg == "-k" && i + 1 < argc) {
            key_hex = argv[++i];
        } else if (arg == "-l") {
            local_only = true;
        } else if (arg == "-a" && i + 1 < argc) {
            specific_attack = std::stoi(argv[++i]);
        } else if (arg == "-h") {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    std::cout << "======================================================\n";
    std::cout << "   SECURE PROTOCOL ATTACK DEMONSTRATION\n";
    std::cout << "======================================================\n";
    
    // Always run local tests
    test_crypto_primitives();
    test_key_evolution();
    
    if (local_only) {
        std::cout << "\nLocal tests completed. Use without -l to test against server.\n";
        return 0;
    }
    
    ByteVector master_key = hex_to_bytes(key_hex);
    
    std::cout << "\n\nConnecting to server at " << host << ":" << port << "\n";
    std::cout << "Using client ID: " << (int)client_id << "\n";
    std::cout << "Note: Make sure server has matching key for this client ID\n";
    
    int passed = 0;
    int total = 0;
    
    auto run_test = [&](int num, bool (*test_fn)(const std::string&, uint16_t, uint8_t, const ByteVector&), const char* name) {
        if (specific_attack == 0 || specific_attack == num) {
            total++;
            bool result = test_fn(host, port, client_id + num, master_key);
            print_result(name, result);
            if (result) passed++;
            sleep(1);  // Give server time to clean up
        }
    };
    
    run_test(1, test_replay_attack, "Replay Attack Defense");
    run_test(2, test_hmac_tampering, "HMAC Tampering Defense");
    run_test(3, test_message_reordering, "Message Reordering Defense");
    run_test(4, test_reflection_attack, "Reflection Attack Defense");
    run_test(5, test_invalid_opcode, "Invalid Opcode Defense");
    
    print_header("SUMMARY");
    std::cout << "Tests passed: " << passed << "/" << total << "\n";
    
    if (passed == total) {
        std::cout << "\n\033[32mAll attacks were successfully defended!\033[0m\n";
    } else {
        std::cout << "\n\033[31mSome vulnerabilities were found!\033[0m\n";
    }
    
    return (passed == total) ? 0 : 1;
}
