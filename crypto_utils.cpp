#include "crypto_utils.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>
#include <stdexcept>

namespace CryptoUtils {

// ============================================================================
// PKCS#7 Padding Implementation
// ============================================================================

ByteVector pkcs7_pad(const ByteVector& data, size_t block_size) {
    if (block_size == 0 || block_size > 255) {
        throw std::invalid_argument("Block size must be between 1 and 255");
    }
    
    // Calculate padding length
    size_t padding_len = block_size - (data.size() % block_size);
    
    // Create padded output
    ByteVector padded = data;
    padded.reserve(data.size() + padding_len);
    
    // Append padding bytes (each byte equals padding length)
    for (size_t i = 0; i < padding_len; ++i) {
        padded.push_back(static_cast<uint8_t>(padding_len));
    }
    
    return padded;
}

ByteVector pkcs7_unpad(const ByteVector& data, size_t block_size) {
    if (data.empty()) {
        throw std::runtime_error("Cannot unpad empty data");
    }
    
    if (data.size() % block_size != 0) {
        throw std::runtime_error("Data size is not a multiple of block size - potential tampering");
    }
    
    // Get padding length from last byte
    uint8_t padding_len = data.back();
    
    // Validate padding length
    if (padding_len == 0 || padding_len > block_size) {
        throw std::runtime_error("Invalid padding length - potential tampering");
    }
    
    if (padding_len > data.size()) {
        throw std::runtime_error("Padding length exceeds data size - potential tampering");
    }
    
    // Validate all padding bytes
    size_t data_len = data.size();
    for (size_t i = 0; i < padding_len; ++i) {
        if (data[data_len - 1 - i] != padding_len) {
            throw std::runtime_error("Invalid padding bytes - potential tampering");
        }
    }
    
    // Return unpadded data
    return ByteVector(data.begin(), data.end() - padding_len);
}

// ============================================================================
// AES-128-CBC Implementation
// ============================================================================

ByteVector aes_cbc_encrypt(const ByteVector& plaintext, const AESKey& key, const IV& iv) {
    if (plaintext.empty()) {
        throw std::invalid_argument("Plaintext cannot be empty");
    }
    
    if (plaintext.size() % AES_BLOCK_SIZE != 0) {
        throw std::invalid_argument("Plaintext must be padded to block size before encryption");
    }
    
    // Create and initialize the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    
    // Initialize encryption operation - AES-128-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }
    
    // Disable automatic padding (we do manual PKCS#7)
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    // Allocate output buffer
    ByteVector ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0;
    int ciphertext_len = 0;
    
    // Encrypt
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed");
    }
    ciphertext_len = len;
    
    // Finalize (should not add anything with padding disabled)
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption finalization failed");
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Resize to actual ciphertext length
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

ByteVector aes_cbc_decrypt(const ByteVector& ciphertext, const AESKey& key, const IV& iv) {
    if (ciphertext.empty()) {
        throw std::invalid_argument("Ciphertext cannot be empty");
    }
    
    if (ciphertext.size() % AES_BLOCK_SIZE != 0) {
        throw std::invalid_argument("Ciphertext size must be a multiple of block size");
    }
    
    // Create and initialize the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    
    // Initialize decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }
    
    // Disable automatic padding (we do manual PKCS#7)
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    // Allocate output buffer
    ByteVector plaintext(ciphertext.size() + AES_BLOCK_SIZE);
    int len = 0;
    int plaintext_len = 0;
    
    // Decrypt
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                          ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed");
    }
    plaintext_len = len;
    
    // Finalize
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption finalization failed");
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Resize to actual plaintext length
    plaintext.resize(plaintext_len);
    return plaintext;
}

// ============================================================================
// HMAC-SHA256 Implementation
// ============================================================================

HMACTag hmac_sha256(const MACKey& key, const ByteVector& data) {
    HMACTag result;
    unsigned int result_len = 0;
    
    uint8_t* ret = ::HMAC(EVP_sha256(),
                          key.data(), static_cast<int>(key.size()),
                          data.data(), data.size(),
                          result.data(), &result_len);
    
    if (!ret || result_len != HMAC_SIZE) {
        throw std::runtime_error("HMAC computation failed");
    }
    
    return result;
}

HMACTag hmac_sha256(const MACKey& key, const std::vector<ByteVector>& data_parts) {
    // Concatenate all parts
    size_t total_size = 0;
    for (const auto& part : data_parts) {
        total_size += part.size();
    }
    
    ByteVector combined;
    combined.reserve(total_size);
    for (const auto& part : data_parts) {
        combined.insert(combined.end(), part.begin(), part.end());
    }
    
    return hmac_sha256(key, combined);
}

bool hmac_verify(const MACKey& key, const ByteVector& data, const HMACTag& expected) {
    HMACTag computed = hmac_sha256(key, data);
    return constant_time_compare(computed.data(), expected.data(), HMAC_SIZE);
}

// ============================================================================
// SHA-256 Implementation
// ============================================================================

std::array<uint8_t, 32> sha256(const ByteVector& data) {
    std::array<uint8_t, 32> hash;
    
    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx)) {
        throw std::runtime_error("SHA256 init failed");
    }
    if (!SHA256_Update(&ctx, data.data(), data.size())) {
        throw std::runtime_error("SHA256 update failed");
    }
    if (!SHA256_Final(hash.data(), &ctx)) {
        throw std::runtime_error("SHA256 final failed");
    }
    
    return hash;
}

std::array<uint8_t, 32> sha256(const std::vector<ByteVector>& data_parts) {
    std::array<uint8_t, 32> hash;
    
    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx)) {
        throw std::runtime_error("SHA256 init failed");
    }
    
    for (const auto& part : data_parts) {
        if (!SHA256_Update(&ctx, part.data(), part.size())) {
            throw std::runtime_error("SHA256 update failed");
        }
    }
    
    if (!SHA256_Final(hash.data(), &ctx)) {
        throw std::runtime_error("SHA256 final failed");
    }
    
    return hash;
}

// ============================================================================
// Key Derivation Implementation
// ============================================================================

AESKey derive_aes_key(const ByteVector& master_key, const std::string& label) {
    // Concatenate master_key || label
    ByteVector input = master_key;
    input.insert(input.end(), label.begin(), label.end());
    
    // Compute SHA-256 hash
    auto hash = sha256(input);
    
    // Take first 16 bytes for AES-128 key
    AESKey key;
    std::copy(hash.begin(), hash.begin() + AES_KEY_SIZE, key.begin());
    
    return key;
}

MACKey derive_mac_key(const ByteVector& master_key, const std::string& label) {
    // Concatenate master_key || label
    ByteVector input = master_key;
    input.insert(input.end(), label.begin(), label.end());
    
    // Compute SHA-256 hash
    auto hash = sha256(input);
    
    // Use full 32 bytes for MAC key
    MACKey key;
    std::copy(hash.begin(), hash.end(), key.begin());
    
    return key;
}

// ============================================================================
// Key Evolution Implementation
// ============================================================================

AESKey evolve_aes_key(const AESKey& current_key, const ByteVector& ratchet_data) {
    // Concatenate current_key || ratchet_data
    ByteVector input(current_key.begin(), current_key.end());
    input.insert(input.end(), ratchet_data.begin(), ratchet_data.end());
    
    // Compute SHA-256 hash
    auto hash = sha256(input);
    
    // Take first 16 bytes for AES-128 key
    AESKey new_key;
    std::copy(hash.begin(), hash.begin() + AES_KEY_SIZE, new_key.begin());
    
    return new_key;
}

MACKey evolve_mac_key(const MACKey& current_key, const ByteVector& ratchet_data) {
    // Concatenate current_key || ratchet_data
    ByteVector input(current_key.begin(), current_key.end());
    input.insert(input.end(), ratchet_data.begin(), ratchet_data.end());
    
    // Compute SHA-256 hash
    auto hash = sha256(input);
    
    // Use full 32 bytes for MAC key
    MACKey new_key;
    std::copy(hash.begin(), hash.end(), new_key.begin());
    
    return new_key;
}

// ============================================================================
// Random Number Generation
// ============================================================================

ByteVector generate_random_bytes(size_t length) {
    ByteVector random_data(length);
    
    if (RAND_bytes(random_data.data(), static_cast<int>(length)) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    
    return random_data;
}

IV generate_random_iv() {
    IV iv;
    
    if (RAND_bytes(iv.data(), IV_SIZE) != 1) {
        throw std::runtime_error("Failed to generate random IV");
    }
    
    return iv;
}

// ============================================================================
// Constant-Time Comparison
// ============================================================================

bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t result = 0;
    
    for (size_t i = 0; i < len; ++i) {
        result |= a[i] ^ b[i];
    }
    
    return result == 0;
}

} // namespace CryptoUtils
