#ifndef CRYPTO_UTILS_HPP
#define CRYPTO_UTILS_HPP

#include "common.hpp"
#include <stdexcept>

// ============================================================================
// Cryptographic Utility Functions
// ============================================================================
// This module provides:
// - Manual PKCS#7 Padding (add/remove)
// - AES-128-CBC Encryption/Decryption (using OpenSSL)
// - HMAC-SHA256 (using OpenSSL)
// - SHA-256 Hash for key derivation
// - Secure random number generation
// ============================================================================

namespace CryptoUtils {

// ============================================================================
// PKCS#7 Padding
// ============================================================================

/**
 * Apply PKCS#7 padding to data.
 * Padding is always applied - if data is already block-aligned,
 * a full block of padding is added.
 * 
 * @param data Input data to pad
 * @param block_size Block size (default 16 for AES)
 * @return Padded data
 */
ByteVector pkcs7_pad(const ByteVector& data, size_t block_size = AES_BLOCK_SIZE);

/**
 * Remove and validate PKCS#7 padding.
 * Throws std::runtime_error if padding is invalid (potential tampering).
 * 
 * @param data Padded data
 * @param block_size Block size (default 16 for AES)
 * @return Unpadded data
 * @throws std::runtime_error on invalid padding
 */
ByteVector pkcs7_unpad(const ByteVector& data, size_t block_size = AES_BLOCK_SIZE);

// ============================================================================
// AES-128-CBC Encryption/Decryption
// ============================================================================

/**
 * Encrypt plaintext using AES-128-CBC.
 * NOTE: This function does NOT apply padding - use pkcs7_pad first!
 * 
 * @param plaintext Padded plaintext (must be multiple of block size)
 * @param key 16-byte AES key
 * @param iv 16-byte initialization vector
 * @return Ciphertext
 * @throws std::runtime_error on encryption failure
 */
ByteVector aes_cbc_encrypt(const ByteVector& plaintext, const AESKey& key, const IV& iv);

/**
 * Decrypt ciphertext using AES-128-CBC.
 * NOTE: This function does NOT remove padding - use pkcs7_unpad after!
 * 
 * @param ciphertext Ciphertext to decrypt
 * @param key 16-byte AES key
 * @param iv 16-byte initialization vector
 * @return Decrypted data (still padded)
 * @throws std::runtime_error on decryption failure
 */
ByteVector aes_cbc_decrypt(const ByteVector& ciphertext, const AESKey& key, const IV& iv);

// ============================================================================
// HMAC-SHA256
// ============================================================================

/**
 * Compute HMAC-SHA256 of data.
 * 
 * @param key MAC key (can be any length, typically 32 bytes)
 * @param data Data to authenticate
 * @return 32-byte HMAC
 */
HMACTag hmac_sha256(const MACKey& key, const ByteVector& data);

/**
 * Compute HMAC-SHA256 over multiple data segments.
 * 
 * @param key MAC key
 * @param data_parts Vector of data segments to concatenate and authenticate
 * @return 32-byte HMAC
 */
HMACTag hmac_sha256(const MACKey& key, const std::vector<ByteVector>& data_parts);

/**
 * Verify HMACTag in constant time (to prevent timing attacks).
 * 
 * @param key MAC key
 * @param data Data that was authenticated
 * @param expected Expected HMACTag value
 * @return true if HMACTag matches, false otherwise
 */
bool hmac_verify(const MACKey& key, const ByteVector& data, const HMACTag& expected);

// ============================================================================
// SHA-256 Hash (for key derivation)
// ============================================================================

/**
 * Compute SHA-256 hash of data.
 * 
 * @param data Input data
 * @return 32-byte hash
 */
std::array<uint8_t, 32> sha256(const ByteVector& data);

/**
 * Compute SHA-256 hash of concatenated data.
 * 
 * @param data_parts Vector of data segments to concatenate
 * @return 32-byte hash
 */
std::array<uint8_t, 32> sha256(const std::vector<ByteVector>& data_parts);

// ============================================================================
// Key Derivation
// ============================================================================

/**
 * Derive an AES key from master key and label.
 * key = first 16 bytes of SHA256(master_key || label)
 * 
 * @param master_key The pre-shared master key
 * @param label Label string (e.g., "C2S-ENC")
 * @return 16-byte derived AES key
 */
AESKey derive_aes_key(const ByteVector& master_key, const std::string& label);

/**
 * Derive a MAC key from master key and label.
 * key = SHA256(master_key || label)
 * 
 * @param master_key The pre-shared master key
 * @param label Label string (e.g., "C2S-MAC")
 * @return 32-byte derived MAC key
 */
MACKey derive_mac_key(const ByteVector& master_key, const std::string& label);

// ============================================================================
// Key Evolution (Ratcheting)
// ============================================================================

/**
 * Evolve an AES encryption key.
 * new_key = first 16 bytes of SHA256(old_key || ratchet_data)
 * 
 * @param current_key Current encryption key
 * @param ratchet_data Data to mix in (e.g., ciphertext for C2S, aggregated data for S2C)
 * @return New evolved key
 */
AESKey evolve_aes_key(const AESKey& current_key, const ByteVector& ratchet_data);

/**
 * Evolve a MAC key.
 * new_key = SHA256(old_key || ratchet_data)
 * 
 * @param current_key Current MAC key
 * @param ratchet_data Data to mix in (e.g., nonce for C2S, status code for S2C)
 * @return New evolved key
 */
MACKey evolve_mac_key(const MACKey& current_key, const ByteVector& ratchet_data);

// ============================================================================
// Random Number Generation
// ============================================================================

/**
 * Generate cryptographically secure random bytes.
 * Uses OS-level secure RNG via OpenSSL.
 * 
 * @param length Number of random bytes to generate
 * @return Random bytes
 * @throws std::runtime_error on RNG failure
 */
ByteVector generate_random_bytes(size_t length);

/**
 * Generate a random IV for AES-CBC.
 * 
 * @return 16-byte random IV
 */
IV generate_random_iv();

// ============================================================================
// Constant-Time Comparison
// ============================================================================

/**
 * Compare two byte arrays in constant time.
 * Prevents timing side-channel attacks.
 * 
 * @param a First array
 * @param b Second array
 * @param len Length to compare
 * @return true if equal, false otherwise
 */
bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len);

} // namespace CryptoUtils

#endif // CRYPTO_UTILS_HPP
