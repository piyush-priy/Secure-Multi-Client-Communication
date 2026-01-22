/**
 * Secure Multi-Client Communication Server
 * 
 * This server implements a stateful symmetric-key-based secure communication
 * protocol supporting multiple concurrent clients with:
 * - AES-128-CBC encryption with manual PKCS#7 padding
 * - HMAC-SHA256 authentication (verified before decryption)
 * - Key ratcheting (forward secrecy)
 * - Round-based synchronization
 * - Per-round data aggregation
 */

#include "protocol_fsm.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <ctime>
#include <algorithm>

// POSIX networking
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

// ============================================================================
// Global State
// ============================================================================

// Master keys: client_id -> master_key
std::map<uint8_t, ByteVector> g_master_keys;

// Active sessions: client_id -> session_state
std::map<uint8_t, SessionState> g_sessions;
std::mutex g_sessions_mutex;

// Aggregation state per round
struct AggregationState {
    uint32_t round;
    int32_t sum;
    int32_t count;
    std::map<uint8_t, int32_t> client_data;  // Which clients have submitted data
    bool complete;
    
    AggregationState() : round(0), sum(0), count(0), complete(false) {}
};

std::map<uint32_t, AggregationState> g_aggregations;
std::mutex g_aggregation_mutex;
std::condition_variable g_aggregation_cv;

// Expected number of clients for aggregation
std::atomic<int> g_expected_clients(3);

// Server running flag
std::atomic<bool> g_running(true);

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

// Load master keys from file
// Format: client_id:hex_key (one per line)
bool load_master_keys(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        log_error("Could not open key file: " + filename);
        return false;
    }
    
    std::string line;
    int line_num = 0;
    while (std::getline(file, line)) {
        line_num++;
        
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;
        
        // Parse client_id:hex_key
        size_t colon_pos = line.find(':');
        if (colon_pos == std::string::npos) {
            log_error("Invalid key format at line " + std::to_string(line_num));
            continue;
        }
        
        try {
            uint8_t client_id = static_cast<uint8_t>(std::stoi(line.substr(0, colon_pos)));
            std::string hex_key = line.substr(colon_pos + 1);
            
            // Remove whitespace
            hex_key.erase(std::remove_if(hex_key.begin(), hex_key.end(), ::isspace),
                         hex_key.end());
            
            ByteVector master_key = hex_to_bytes(hex_key);
            
            if (master_key.size() < 16) {
                log_error("Key too short for client " + std::to_string(client_id));
                continue;
            }
            
            g_master_keys[client_id] = master_key;
            log_message("Loaded key for client " + std::to_string(client_id));
            
        } catch (const std::exception& e) {
            log_error("Error parsing line " + std::to_string(line_num) + ": " + e.what());
        }
    }
    
    return !g_master_keys.empty();
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

// Receive message with length prefix (4-byte big-endian length)
ByteVector receive_message(int sock) {
    // First, receive the length prefix
    uint8_t len_buf[4];
    size_t received = 0;
    while (received < 4) {
        ssize_t r = recv(sock, len_buf + received, 4 - received, 0);
        if (r <= 0) {
            return {};  // Connection closed or error
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
    // Prepend length
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
// Session Management
// ============================================================================

SessionState* get_or_create_session(uint8_t client_id) {
    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    
    auto it = g_sessions.find(client_id);
    if (it != g_sessions.end()) {
        return &it->second;
    }
    
    // Check if we have a master key for this client
    auto key_it = g_master_keys.find(client_id);
    if (key_it == g_master_keys.end()) {
        return nullptr;
    }
    
    // Create new session
    g_sessions[client_id] = ProtocolFSM::initialize_session(client_id, key_it->second);
    return &g_sessions[client_id];
}

void remove_session(uint8_t client_id) {
    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    g_sessions.erase(client_id);
}

// ============================================================================
// Aggregation Management
// ============================================================================

void submit_client_data(uint8_t client_id, uint32_t round, int32_t data) {
    std::lock_guard<std::mutex> lock(g_aggregation_mutex);
    
    auto& agg = g_aggregations[round];
    agg.round = round;
    
    // Check if this client already submitted for this round
    if (agg.client_data.find(client_id) != agg.client_data.end()) {
        log_message("Client " + std::to_string(client_id) + 
                   " already submitted for round " + std::to_string(round));
        return;
    }
    
    agg.client_data[client_id] = data;
    agg.sum += data;
    agg.count++;
    
    log_message("Client " + std::to_string(client_id) + " submitted data " +
               std::to_string(data) + " for round " + std::to_string(round) +
               " (count: " + std::to_string(agg.count) + "/" +
               std::to_string(g_expected_clients.load()) + ")");
    
    // Check if aggregation is complete
    if (agg.count >= g_expected_clients.load()) {
        agg.complete = true;
        g_aggregation_cv.notify_all();
    }
}

bool wait_for_aggregation(uint32_t round, int timeout_seconds = 30) {
    std::unique_lock<std::mutex> lock(g_aggregation_mutex);
    
    auto deadline = std::chrono::steady_clock::now() + 
                    std::chrono::seconds(timeout_seconds);
    
    while (!g_aggregations[round].complete && g_running.load()) {
        if (g_aggregation_cv.wait_until(lock, deadline) == std::cv_status::timeout) {
            // Timeout - proceed with partial aggregation
            log_message("Aggregation timeout for round " + std::to_string(round) +
                       " - proceeding with " + std::to_string(g_aggregations[round].count) +
                       " submissions");
            g_aggregations[round].complete = true;
            return true;
        }
    }
    
    return g_running.load();
}

AggregationState get_aggregation(uint32_t round) {
    std::lock_guard<std::mutex> lock(g_aggregation_mutex);
    return g_aggregations[round];
}

// ============================================================================
// Client Handler
// ============================================================================

void handle_client(int client_sock, struct sockaddr_in client_addr) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    
    log_message("New connection from " + std::string(client_ip) + ":" + 
               std::to_string(ntohs(client_addr.sin_port)));
    
    SessionState* session = nullptr;
    uint8_t client_id = 0;
    
    try {
        // ====================================================================
        // Phase 1: Receive CLIENT_HELLO
        // ====================================================================
        ByteVector hello_msg = receive_message(client_sock);
        if (hello_msg.empty()) {
            log_error("Failed to receive CLIENT_HELLO");
            close(client_sock);
            return;
        }
        
        // Parse header to get client ID
        ParsedMessage hello = ProtocolFSM::parse_header(hello_msg);
        if (!hello.valid || hello.opcode != Opcode::CLIENT_HELLO) {
            log_error("Invalid CLIENT_HELLO");
            close(client_sock);
            return;
        }
        
        client_id = hello.client_id;
        log_message("Received CLIENT_HELLO from client " + std::to_string(client_id));
        
        // Get or create session
        session = get_or_create_session(client_id);
        if (!session) {
            log_error("Unknown client ID: " + std::to_string(client_id));
            close(client_sock);
            return;
        }
        
        session->socket_fd = client_sock;
        
        // Verify HELLO message
        ParsedMessage verified_hello = ProtocolFSM::process_message(
            *session, hello_msg, Direction::CLIENT_TO_SERVER);
        
        if (!verified_hello.valid) {
            log_error("CLIENT_HELLO verification failed: " + verified_hello.error_message);
            close(client_sock);
            remove_session(client_id);
            return;
        }
        
        // ====================================================================
        // Phase 2: Send SERVER_CHALLENGE
        // ====================================================================
        
        // Generate challenge
        ByteVector challenge = CryptoUtils::generate_random_bytes(8);
        uint32_t timestamp = static_cast<uint32_t>(std::time(nullptr));
        ByteVector challenge_payload = ProtocolFSM::serialize_challenge(challenge, timestamp);
        
        // Build and send challenge
        ByteVector challenge_msg = ProtocolFSM::build_message(
            Opcode::SERVER_CHALLENGE,
            client_id,
            session->round,
            Direction::SERVER_TO_CLIENT,
            challenge_payload,
            session->keys.s2c_enc_key,
            session->keys.s2c_mac_key
        );
        
        if (!send_message(client_sock, challenge_msg)) {
            log_error("Failed to send SERVER_CHALLENGE");
            close(client_sock);
            remove_session(client_id);
            return;
        }
        
        log_message("Sent SERVER_CHALLENGE to client " + std::to_string(client_id));
        
        // Evolve S2C keys after sending challenge
        ByteVector status_code = ProtocolFSM::uint32_to_bytes(0);  // Status OK
        ProtocolFSM::evolve_s2c_keys(session->keys, challenge_payload, status_code);
        
        // Transition to ACTIVE phase
        session->phase = ProtocolPhase::ACTIVE;
        session->round++;
        
        // ====================================================================
        // Phase 3: Main communication loop
        // ====================================================================
        
        while (g_running.load() && session->phase == ProtocolPhase::ACTIVE) {
            // Receive CLIENT_DATA
            ByteVector data_msg = receive_message(client_sock);
            if (data_msg.empty()) {
                log_message("Client " + std::to_string(client_id) + " disconnected");
                break;
            }
            
            // Process message
            ParsedMessage data = ProtocolFSM::process_message(
                *session, data_msg, Direction::CLIENT_TO_SERVER);
            
            if (!data.valid) {
                log_error("CLIENT_DATA verification failed for client " + 
                         std::to_string(client_id) + ": " + data.error_message);
                
                // Send KEY_DESYNC_ERROR
                ByteVector error_msg = ProtocolFSM::build_error_message(
                    Opcode::KEY_DESYNC_ERROR,
                    client_id,
                    session->round,
                    Direction::SERVER_TO_CLIENT,
                    session->keys.s2c_mac_key
                );
                send_message(client_sock, error_msg);
                break;
            }
            
            if (data.opcode == Opcode::TERMINATE) {
                log_message("Client " + std::to_string(client_id) + " requested termination");
                break;
            }
            
            // Extract client data
            int32_t client_value = ProtocolFSM::deserialize_client_data(data.decrypted_payload);
            log_message("Client " + std::to_string(client_id) + " sent data: " + 
                       std::to_string(client_value) + " for round " + 
                       std::to_string(session->round));
            
            // Evolve C2S keys
            // Extract ciphertext from the message (after header, before HMAC)
            ByteVector ciphertext(data_msg.begin() + HEADER_SIZE, 
                                 data_msg.end() - HMAC_SIZE);
            ProtocolFSM::evolve_c2s_keys(session->keys, ciphertext, data.iv);
            
            // Submit to aggregation
            submit_client_data(client_id, session->round, client_value);
            
            // Wait for aggregation to complete
            wait_for_aggregation(session->round);
            
            // Get aggregation result
            AggregationState agg = get_aggregation(session->round);
            
            // Build aggregation response
            ByteVector agg_payload = ProtocolFSM::serialize_aggregation(
                agg.count, agg.sum, 0);  // Status 0 = OK
            
            ByteVector response_msg = ProtocolFSM::build_message(
                Opcode::SERVER_AGGR_RESPONSE,
                client_id,
                session->round,
                Direction::SERVER_TO_CLIENT,
                agg_payload,
                session->keys.s2c_enc_key,
                session->keys.s2c_mac_key
            );
            
            if (!send_message(client_sock, response_msg)) {
                log_error("Failed to send SERVER_AGGR_RESPONSE");
                break;
            }
            
            log_message("Sent aggregation response to client " + std::to_string(client_id) +
                       ": sum=" + std::to_string(agg.sum) + ", count=" + std::to_string(agg.count));
            
            // Evolve S2C keys
            ByteVector status = ProtocolFSM::uint32_to_bytes(0);
            ProtocolFSM::evolve_s2c_keys(session->keys, agg_payload, status);
            
            // Increment round
            session->round++;
        }
        
    } catch (const std::exception& e) {
        log_error("Exception handling client " + std::to_string(client_id) + ": " + e.what());
    }
    
    // Cleanup
    close(client_sock);
    if (client_id != 0) {
        remove_session(client_id);
        log_message("Session ended for client " + std::to_string(client_id));
    }
}

// ============================================================================
// Signal Handler
// ============================================================================

void signal_handler(int signum) {
    log_message("Received signal " + std::to_string(signum) + ", shutting down...");
    g_running.store(false);
    g_aggregation_cv.notify_all();
}

// ============================================================================
// Main
// ============================================================================

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -p PORT      Port to listen on (default: " << DEFAULT_PORT << ")" << std::endl;
    std::cout << "  -k KEYFILE   Key file path (default: keys.txt)" << std::endl;
    std::cout << "  -n CLIENTS   Expected number of clients (default: 3)" << std::endl;
    std::cout << "  -h           Show this help" << std::endl;
}

int main(int argc, char* argv[]) {
    uint16_t port = DEFAULT_PORT;
    std::string key_file = "keys.txt";
    int expected_clients = 3;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-p" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "-k" && i + 1 < argc) {
            key_file = argv[++i];
        } else if (arg == "-n" && i + 1 < argc) {
            expected_clients = std::stoi(argv[++i]);
        } else if (arg == "-h") {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    g_expected_clients.store(expected_clients);
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Load master keys
    log_message("Loading master keys from " + key_file);
    if (!load_master_keys(key_file)) {
        log_error("Failed to load master keys");
        return 1;
    }
    log_message("Loaded " + std::to_string(g_master_keys.size()) + " master keys");
    
    // Create server socket
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        log_error("Failed to create socket");
        return 1;
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Bind
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_error("Failed to bind to port " + std::to_string(port));
        close(server_sock);
        return 1;
    }
    
    // Listen
    if (listen(server_sock, 10) < 0) {
        log_error("Failed to listen");
        close(server_sock);
        return 1;
    }
    
    log_message("Server listening on port " + std::to_string(port));
    log_message("Expecting " + std::to_string(expected_clients) + " clients per round");
    
    // Accept loop
    std::vector<std::thread> client_threads;
    
    while (g_running.load()) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addr_len);
        if (client_sock < 0) {
            if (g_running.load()) {
                log_error("Failed to accept connection");
            }
            continue;
        }
        
        // Handle client in new thread
        client_threads.emplace_back(handle_client, client_sock, client_addr);
    }
    
    // Wait for all client threads to finish
    for (auto& t : client_threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    
    close(server_sock);
    log_message("Server shutdown complete");
    
    return 0;
}
