# Security Analysis

## SNS Lab 1: Secure Multi-Client Communication Protocol

This document analyzes the security properties of the implemented protocol and explains how it defends against various attack scenarios.

---

## 1. Threat Model

The protocol assumes an **active network adversary** (Dolev-Yao model) who can:

- **Intercept** all network traffic
- **Replay** previously captured messages
- **Modify** message contents (ciphertext, headers, MACs)
- **Drop** or **reorder** packets
- **Inject** arbitrary messages
- **Reflect** messages back to sender

The adversary **cannot**:
- Break AES-128 encryption (computationally secure)
- Forge HMAC-SHA256 without the key (computationally secure)
- Compromise the pre-shared master keys (assumption)

---

## 2. Security Properties

### 2.1 Confidentiality

**Mechanism:** AES-128-CBC encryption with random IVs

**Protection:**
- All sensitive data (client data, aggregation results, challenges) is encrypted
- Each message uses a fresh random 16-byte IV
- Keys evolve after each message (ratcheting) limiting damage from key compromise

**Analysis:**
- AES-128 provides 128-bit security against brute force
- CBC mode with random IVs is IND-CPA secure
- Even if an attacker captures all ciphertext, they cannot recover plaintext without keys

### 2.2 Integrity

**Mechanism:** HMAC-SHA256 (Encrypt-then-MAC)

**Protection:**
- HMAC covers the entire message: Header || Ciphertext
- HMAC is verified **before** decryption (critical for security)
- Any modification to header or ciphertext is detected

**Analysis:**
- HMAC-SHA256 provides 256-bit security
- Encrypt-then-MAC construction prevents padding oracle attacks
- Constant-time comparison prevents timing attacks on MAC verification

### 2.3 Authentication

**Mechanism:** Pre-shared symmetric keys + HMAC

**Protection:**
- Only parties with the correct master key can derive session keys
- HMAC verification authenticates message origin
- CLIENT_HELLO initiates authenticated session

**Analysis:**
- Each client has a unique master key
- Server can identify clients by client_id field
- Messages from unknown clients are rejected

### 2.4 Freshness / Replay Protection

**Mechanism:** Monotonically increasing round numbers

**Protection:**
- Each message includes a 32-bit round number
- Messages with incorrect round numbers are rejected
- Round numbers must match expected value exactly

**Analysis:**
- Replaying an old message fails because round numbers don't match
- Forward replay (using future round number) fails because keys won't match
- Round 0 -> 1 -> 2 -> ... provides strict ordering

### 2.5 Forward Secrecy (Key Ratcheting)

**Mechanism:** Key evolution after each successful message

**Key Evolution:**
```
C2S_Enc[R+1] = SHA256(C2S_Enc[R] || Ciphertext[R])[:16]
C2S_Mac[R+1] = SHA256(C2S_Mac[R] || Nonce[R])
S2C_Enc[R+1] = SHA256(S2C_Enc[R] || AggregatedData[R])[:16]
S2C_Mac[R+1] = SHA256(S2C_Mac[R] || StatusCode[R])
```

**Protection:**
- Old keys cannot be recovered from new keys (one-way hash)
- Compromising current keys doesn't reveal past communications
- Each session has unique derived keys

**Analysis:**
- Even if an attacker obtains keys at round R, they cannot:
  - Decrypt messages from rounds < R (forward secrecy)
  - Predict keys for rounds > R without seeing the messages

---

## 3. Attack Resistance Analysis

### 3.1 Replay Attack

**Attack:** Capture a valid message and retransmit it later.

**Defense:**
- Round number validation
- Keys evolve after each message

**Example:**
```
Attacker captures: CLIENT_DATA (round=1, data=100)
Attacker replays at round=2:
  - Server expects round=2
  - Message has round=1
  - REJECTED: Round mismatch
```

**Additionally:** Even if round numbers matched, the MAC key has evolved, so HMAC verification would fail.

### 3.2 Message Modification (HMAC Tampering)

**Attack:** Modify ciphertext to alter the decrypted value.

**Defense:**
- HMAC covers all message fields
- HMAC verified before decryption
- Any modification invalidates HMAC

**Example:**
```
Original: Enc(data=100), HMAC valid
Attacker: Modify Enc(data) -> Enc(data')
Server verification:
  - Compute HMAC(Header || Modified_Ciphertext)
  - Compare with received HMAC
  - REJECTED: HMAC mismatch
```

### 3.3 Message Reordering

**Attack:** Deliver messages out of sequence to confuse state.

**Defense:**
- Strict round number checking
- State machine validates message sequence

**Example:**
```
Client sends: HELLO(R=0), DATA(R=1), DATA(R=2)
Attacker delivers: HELLO(R=0), DATA(R=2), DATA(R=1)

Server processing:
  - HELLO(R=0): Accept, expect R=1
  - DATA(R=2): REJECT - expected R=1
  - Session terminated
```

### 3.4 Reflection Attack

**Attack:** Send a server-to-client message back to the server.

**Defense:**
- Direction field in header (0=C2S, 1=S2C)
- Different keys for each direction

**Example:**
```
Server sends: SERVER_CHALLENGE (direction=1, S2C keys)
Attacker reflects to server as C2S message
Server expects:
  - direction=0 (C2S)
  - MAC with C2S_Mac key
Server receives:
  - direction=1 (S2C)
  - MAC with S2C_Mac key
REJECTED: Direction mismatch OR MAC verification fails
```

### 3.5 Key Desynchronization Attack

**Attack:** Cause client and server to have different keys by disrupting message delivery.

**Defense:**
- Keys only evolve after successful verification
- Failed verification terminates session
- No partial state updates

**Example:**
```
Client sends: DATA(R=1)
Attacker drops message (server never receives)

Client state: Evolved keys for R=2
Server state: Still at R=1

Next message from client:
  - Uses R=2 keys
  - Server expects R=1 keys
  - MAC verification fails
  - Session terminated (clean failure)
```

**Mitigation:** The protocol fails securely - it terminates rather than entering an inconsistent state.

### 3.6 Padding Oracle Attack

**Attack:** Use error messages to decrypt ciphertext by probing padding validity.

**Defense:**
- HMAC verified BEFORE decryption
- Padding errors treated same as MAC errors
- Session terminates on any verification failure

**Analysis:**
```
Traditional attack flow:
  1. Modify ciphertext
  2. Server decrypts
  3. Padding error vs. valid - reveals information
  
Our protocol:
  1. Modify ciphertext
  2. HMAC verification fails BEFORE decryption
  3. No padding check occurs
  4. Attacker learns nothing about padding
```

### 3.7 Protocol State Machine Attacks

**Attack:** Send unexpected opcodes to trigger undefined behavior.

**Defense:**
- Finite state machine with explicit valid transitions
- Invalid opcodes for current state cause termination

**Valid Transitions:**
```
INIT:
  - C2S: Only CLIENT_HELLO allowed
  - S2C: Only SERVER_CHALLENGE allowed

ACTIVE:
  - C2S: CLIENT_DATA, TERMINATE
  - S2C: SERVER_AGGR_RESPONSE, KEY_DESYNC_ERROR, TERMINATE

Any other opcode -> Session terminated
```

---

## 4. Cryptographic Choices Justification

### Why AES-128-CBC?

- **Assignment requirement:** AES-128 in CBC mode
- **Security:** 128-bit key provides adequate security margin
- **CBC mode:** Standard, well-analyzed mode
- **Random IV:** Required for IND-CPA security

### Why HMAC-SHA256?

- **Assignment requirement:** HMAC-SHA256
- **Security:** 256-bit output prevents collision attacks
- **Performance:** Efficient on modern processors

### Why Manual PKCS#7 Padding?

- **Assignment requirement:** Manual padding implementation
- **Security:** Ensures padding errors are treated as tampering
- **Control:** Full visibility into padding operation

### Why Encrypt-then-MAC?

- **Security:** Most secure authenticated encryption pattern
- **Order:** Verify MAC first prevents padding oracle attacks
- **Standard:** Recommended by cryptographic best practices

### Why Key Ratcheting?

- **Forward Secrecy:** Compromised keys don't reveal past messages
- **Binding:** Keys depend on previous message content
- **Assignment requirement:** Key evolution specified

---

## 5. Limitations and Future Work

### Current Limitations

1. **No Perfect Forward Secrecy:** Without public-key crypto, we cannot achieve true PFS. Key ratcheting provides partial forward secrecy.

2. **Single Point of Failure:** Master key compromise reveals all derived keys. Real systems would use hardware security modules.

3. **No Key Refresh:** Master keys are never updated. Long-term deployments should implement key rotation.

4. **Denial of Service:** An attacker can terminate sessions by sending invalid messages. Rate limiting could mitigate this.

5. **No Client Authentication:** Clients are identified by client_id only. A stolen master key allows impersonation.

### Potential Improvements

1. **Add timestamps** to messages to detect very old replays
2. **Implement session resumption** to handle transient failures
3. **Add sequence numbers within rounds** for multi-message exchanges
4. **Use authenticated encryption** (AES-GCM) when allowed

---

## 6. Conclusion

The implemented protocol provides strong security guarantees against the specified threat model:

| Property | Mechanism | Status |
|----------|-----------|--------|
| Confidentiality | AES-128-CBC | Achieved |
| Integrity | HMAC-SHA256 | Achieved |
| Authentication | Pre-shared keys | Achieved |
| Replay Protection | Round numbers | Achieved |
| Reordering Protection | Round numbers | Achieved |
| Reflection Protection | Direction field | Achieved |
| Forward Secrecy | Key ratcheting | Partial |

The protocol is secure against all attacks specified in the assignment, with clean failure modes that terminate sessions rather than entering vulnerable states.
