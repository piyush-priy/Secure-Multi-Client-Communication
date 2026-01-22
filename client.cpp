/**
 * Secure Communication Client
 * 
 * This client implements a stateful symmetric-key-based secure communication
 * protocol with:
 * - AES-128-CBC encryption with manual PKCS#7 padding
 * - HMAC-SHA256 authentication (verified before decryption)
 * - Key ratcheting (forward secrecy)
 * - Round-based synchronization
 */

#include "protocol_fsm.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <random>
#include <algorithm>

// POSIX networking
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>

// ============================================================================
// Global State
// ============================================================================

volatile sig_atomic_t g_running = 1;

// ============================================================================
// Utility Functions
// ============================================================================

void log_message(const std::string& msg) {
    std::time_t now = std::time(nullptr);
    char timestamp[32];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", 
                  std::localtime(&now));
    std::cout << "[" << timestamp << "] " << msg << std::endl;
}

void log_error(const std::string& msg) {
    std::cerr << "[ERROR] " << msg << std::endl;
}

// Load master key from file or command line
ByteVector load_master_key(const std::string& key_input) {
    // Check if it looks like a hex string
    if (key_input.length() >= 32) {
        bool is_hex = true;
        for (char c : key_input) {
            if (!std::isxdigit(c)) {
                is_hex = false;
                break;
            }
        }
        if (is_hex) {
            return hex_to_bytes(key_input);
        }
    }
    
    // Try to load from file
    std::ifstream file(key_input);
    if (file.is_open()) {
        std::string hex_key;
        std::getline(file, hex_key);
        // Remove whitespace
        hex_key.erase(std::remove_if(hex_key.begin(), hex_key.end(), ::isspace),
                     hex_key.end());
        return hex_to_bytes(hex_key);
    }
    
    log_error("Could not load key from: " + key_input);
    return {};
}

// ============================================================================
// Network Utility Functions
// ============================================================================

// Send all bytes (handles partial sends)
bool send_all(int sock, const ByteVector& data) {
    size_t total_sent = 0;
    while (total_sent < data.size()) {
        ssize_t sent = send(sock, data.data() + total_sent, 
                           data.size() - total_sent, 0);
        if (sent <= 0) {
            return false;
        }
        total_sent += sent;
    }
    return true;
}

// Receive message with length prefix
ByteVector receive_message(int sock) {
    // First, receive the length prefix
    uint8_t len_buf[4];
    size_t received = 0;
    while (received < 4) {
        ssize_t r = recv(sock, len_buf + received, 4 - received, 0);
        if (r <= 0) {
            return {};
        }
        received += r;
    }
    
    // Parse length
    uint32_t msg_len = ((uint32_t)len_buf[0] << 24) |
                       ((uint32_t)len_buf[1] << 16) |
                       ((uint32_t)len_buf[2] << 8) |
                       (uint32_t)len_buf[3];
    
    if (msg_len > MAX_PAYLOAD_SIZE) {
        log_error("Message too large: " + std::to_string(msg_len));
        return {};
    }
    
    // Receive the message
    ByteVector message(msg_len);
    received = 0;
    while (received < msg_len) {
        ssize_t r = recv(sock, message.data() + received, msg_len - received, 0);
        if (r <= 0) {
            return {};
        }
        received += r;
    }
    
    return message;
}

// Send message with length prefix
bool send_message(int sock, const ByteVector& message) {
    ByteVector data;
    data.reserve(4 + message.size());
    
    uint32_t len = static_cast<uint32_t>(message.size());
    data.push_back((len >> 24) & 0xFF);
    data.push_back((len >> 16) & 0xFF);
    data.push_back((len >> 8) & 0xFF);
    data.push_back(len & 0xFF);
    
    data.insert(data.end(), message.begin(), message.end());
    
    return send_all(sock, data);
}

// ============================================================================
// Signal Handler
// ============================================================================

void signal_handler(int signum) {
    (void)signum;
    g_running = 0;
}

// ============================================================================
// Main Client Logic
// ============================================================================

int run_client(const std::string& server_host, uint16_t server_port,
               uint8_t client_id, const ByteVector& master_key,
               int num_rounds, int data_value) {
    
    log_message("Client " + std::to_string(client_id) + " starting");
    log_message("Connecting to " + server_host + ":" + std::to_string(server_port));
    
    // Resolve hostname
    struct hostent* host = gethostbyname(server_host.c_str());
    if (!host) {
        log_error("Failed to resolve hostname: " + server_host);
        return 1;
    }
    
    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_error("Failed to create socket");
        return 1;
    }
    
    // Connect
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    std::memcpy(&server_addr.sin_addr.s_addr, host->h_addr, host->h_length);
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_error("Failed to connect to server");
        close(sock);
        return 1;
    }
    
    log_message("Connected to server");
    
    // Initialize session
    SessionState session = ProtocolFSM::initialize_session(client_id, master_key);
    
    try {
        // ====================================================================
        // Phase 1: Send CLIENT_HELLO
        // ====================================================================
        
        ByteVector hello_msg = ProtocolFSM::build_hello_message(
            client_id, session.round, session.keys.c2s_mac_key);
        
        if (!send_message(sock, hello_msg)) {
            log_error("Failed to send CLIENT_HELLO");
            close(sock);
            return 1;
        }
        
        log_message("Sent CLIENT_HELLO (round " + std::to_string(session.round) + ")");
        
        // ====================================================================
        // Phase 2: Receive SERVER_CHALLENGE
        // ====================================================================
        
        ByteVector challenge_msg = receive_message(sock);
        if (challenge_msg.empty()) {
            log_error("Failed to receive SERVER_CHALLENGE");
            close(sock);
            return 1;
        }
        
        // Parse and verify challenge
        ParsedMessage challenge = ProtocolFSM::parse_and_verify(
            challenge_msg,
            session.round,
            Direction::SERVER_TO_CLIENT,
            session.keys.s2c_mac_key,
            &session.keys.s2c_enc_key
        );
        
        if (!challenge.valid) {
            log_error("SERVER_CHALLENGE verification failed: " + challenge.error_message);
            close(sock);
            return 1;
        }
        
        if (challenge.opcode != Opcode::SERVER_CHALLENGE) {
            log_error("Expected SERVER_CHALLENGE, got " + 
                     std::string(opcode_to_string(challenge.opcode)));
            close(sock);
            return 1;
        }
        
        // Extract challenge data
        ByteVector server_challenge;
        uint32_t timestamp;
        ProtocolFSM::deserialize_challenge(challenge.decrypted_payload, 
                                           server_challenge, timestamp);
        
        log_message("Received SERVER_CHALLENGE (timestamp: " + 
                   std::to_string(timestamp) + ")");
        
        // Evolve S2C keys
        ByteVector status_code = ProtocolFSM::uint32_to_bytes(0);
        ProtocolFSM::evolve_s2c_keys(session.keys, challenge.decrypted_payload, status_code);
        
        // Transition to ACTIVE
        session.phase = ProtocolPhase::ACTIVE;
        session.round++;
        
        // ====================================================================
        // Phase 3: Main communication loop
        // ====================================================================
        
        // Random number generator for varying data
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int32_t> dist(-100, 100);
        
        int rounds_completed = 0;
        while (g_running && rounds_completed < num_rounds) {
            // Generate data to send (use provided value or random)
            int32_t client_data = (data_value != 0) ? data_value : dist(gen);
            
            log_message("Sending data: " + std::to_string(client_data) + 
                       " for round " + std::to_string(session.round));
            
            // Build CLIENT_DATA message
            ByteVector payload = ProtocolFSM::serialize_client_data(client_data);
            ByteVector data_msg = ProtocolFSM::build_message(
                Opcode::CLIENT_DATA,
                client_id,
                session.round,
                Direction::CLIENT_TO_SERVER,
                payload,
                session.keys.c2s_enc_key,
                session.keys.c2s_mac_key
            );
            
            if (!send_message(sock, data_msg)) {
                log_error("Failed to send CLIENT_DATA");
                break;
            }
            
            // Evolve C2S keys
            // Extract ciphertext from the message
            ByteVector ciphertext(data_msg.begin() + HEADER_SIZE,
                                 data_msg.end() - HMAC_SIZE);
            // Extract IV
            IV iv;
            std::copy(data_msg.begin() + 7, data_msg.begin() + 7 + IV_SIZE, iv.begin());
            ProtocolFSM::evolve_c2s_keys(session.keys, ciphertext, iv);
            
            // Receive SERVER_AGGR_RESPONSE
            ByteVector response_msg = receive_message(sock);
            if (response_msg.empty()) {
                log_error("Failed to receive SERVER_AGGR_RESPONSE");
                break;
            }
            
            // Parse and verify response
            ParsedMessage response = ProtocolFSM::parse_and_verify(
                response_msg,
                session.round,
                Direction::SERVER_TO_CLIENT,
                session.keys.s2c_mac_key,
                &session.keys.s2c_enc_key
            );
            
            if (!response.valid) {
                log_error("SERVER_AGGR_RESPONSE verification failed: " + 
                         response.error_message);
                break;
            }
            
            if (response.opcode == Opcode::KEY_DESYNC_ERROR) {
                log_error("Server reported key desynchronization");
                break;
            }
            
            if (response.opcode == Opcode::TERMINATE) {
                log_message("Server requested termination");
                break;
            }
            
            if (response.opcode != Opcode::SERVER_AGGR_RESPONSE) {
                log_error("Unexpected opcode: " + 
                         std::string(opcode_to_string(response.opcode)));
                break;
            }
            
            // Extract aggregation data
            int32_t count, sum;
            uint32_t agg_status;
            ProtocolFSM::deserialize_aggregation(response.decrypted_payload,
                                                 count, sum, agg_status);
            
            log_message("Round " + std::to_string(session.round) + " complete:");
            log_message("  Aggregation: sum=" + std::to_string(sum) + 
                       ", count=" + std::to_string(count) +
                       ", status=" + std::to_string(agg_status));
            
            // Evolve S2C keys
            ByteVector status = ProtocolFSM::uint32_to_bytes(agg_status);
            ProtocolFSM::evolve_s2c_keys(session.keys, response.decrypted_payload, status);
            
            // Increment round
            session.round++;
            rounds_completed++;
            
            // Small delay between rounds
            if (rounds_completed < num_rounds) {
                usleep(100000);  // 100ms
            }
        }
        
        // ====================================================================
        // Phase 4: Termination
        // ====================================================================
        
        log_message("Sending TERMINATE");
        ByteVector terminate_msg = ProtocolFSM::build_error_message(
            Opcode::TERMINATE,
            client_id,
            session.round,
            Direction::CLIENT_TO_SERVER,
            session.keys.c2s_mac_key
        );
        send_message(sock, terminate_msg);
        
    } catch (const std::exception& e) {
        log_error("Exception: " + std::string(e.what()));
    }
    
    close(sock);
    log_message("Client " + std::to_string(client_id) + " finished");
    
    return 0;
}

// ============================================================================
// Main
// ============================================================================

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -s HOST      Server hostname (default: localhost)" << std::endl;
    std::cout << "  -p PORT      Server port (default: " << DEFAULT_PORT << ")" << std::endl;
    std::cout << "  -i ID        Client ID (required, 1-255)" << std::endl;
    std::cout << "  -k KEY       Master key (hex string or file path)" << std::endl;
    std::cout << "  -r ROUNDS    Number of rounds (default: 5)" << std::endl;
    std::cout << "  -d VALUE     Data value to send (default: random)" << std::endl;
    std::cout << "  -h           Show this help" << std::endl;
}

int main(int argc, char* argv[]) {
    std::string server_host = "localhost";
    uint16_t server_port = DEFAULT_PORT;
    int client_id = -1;
    std::string key_input;
    int num_rounds = 5;
    int data_value = 0;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-s" && i + 1 < argc) {
            server_host = argv[++i];
        } else if (arg == "-p" && i + 1 < argc) {
            server_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "-i" && i + 1 < argc) {
            client_id = std::stoi(argv[++i]);
        } else if (arg == "-k" && i + 1 < argc) {
            key_input = argv[++i];
        } else if (arg == "-r" && i + 1 < argc) {
            num_rounds = std::stoi(argv[++i]);
        } else if (arg == "-d" && i + 1 < argc) {
            data_value = std::stoi(argv[++i]);
        } else if (arg == "-h") {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    // Validate required arguments
    if (client_id < 1 || client_id > 255) {
        log_error("Client ID must be between 1 and 255");
        print_usage(argv[0]);
        return 1;
    }
    
    if (key_input.empty()) {
        log_error("Master key is required");
        print_usage(argv[0]);
        return 1;
    }
    
    // Load master key
    ByteVector master_key = load_master_key(key_input);
    if (master_key.empty()) {
        log_error("Failed to load master key");
        return 1;
    }
    
    log_message("Loaded master key (" + std::to_string(master_key.size()) + " bytes)");
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Run client
    return run_client(server_host, server_port, 
                     static_cast<uint8_t>(client_id), 
                     master_key, num_rounds, data_value);
}
