# BBS+ Signatures: Deep Dive into Verifiable Presentations

This document details the mathematical and technical implementation of Verifiable Presentations (VPs) using BBS+ signatures. It specifically focuses on how hidden attributes are handled, how the Fiat-Shamir challenge is computed, and how to inspect the raw Schnorr responses within the proof.

## 1. Mathematical Foundation of BBS+ Signatures

A basic BBS+ signature over a set of messages $\{m_1, \dots, m_n\}$ is a tuple $(A, e, s)$ where:
- $A \in \mathbb{G}_1$ (a curve point)
- $e, s \in \mathbb{Z}_p$ (scalar values)

It satisfies the pairing equation:
$e(A, W \cdot g_1^e \cdot h_0^s \cdot \prod_{i=1}^n h_i^{m_i}) = e(g_1, g_2)$

Where $W, g_1, h_0, \dots, h_n \in \mathbb{G}_1$ and $g_2 \in \mathbb{G}_2$ are public parameters derived from the Public Key.

## 2. Presenting a Proof: Hidden vs. Disclosed Attributes

When a holder generates a Verifiable Presentation, they perform a **Signature Proof of Knowledge** (a $\Sigma$-protocol made non-interactive via Fiat-Shamir). 

The holder randomizes the signature to prevent correlation:
1. Chooses random scalars $r_1, r_2 \in \mathbb{Z}_p$.
2. Computes the randomized representation:
   - $A' = A \cdot g_1^{r_1}$
   - $\bar{A} = A'^{-e} \cdot b^{r_1}$ (where $b$ is the combined message commitment)
   - $d = r_1 \cdot e - r_2$

### What is provided for a hidden attribute?
For any attribute $m_i$ that is **disclosed**, the actual plaintext message (or its hash) is provided in the proof natively.
For any attribute $m_j$ that is **hidden**, the holder generates a random blinding scalar $r_{m_j}$. During the $\Sigma$-protocol:
- The holder commits to $r_{m_j}$ in an initial commitment point $T$.
- After the challenge $c$ is determined, the holder provides a **Schnorr response**:
  $$\hat{m}_j = r_{m_j} - c \cdot m_j \pmod p$$

**Thus, for a hidden attribute, the only data exposed in the final serialized proof is its index $j$ and its 32-byte Schnorr scalar response $\hat{m}_j$.**

## 3. The Challenge $c$ (Fiat-Shamir Heuristic)

The protocol is made non-interactive by replacing the verifier with a cryptographic hash function. 

### How is the challenge determined?
The challenge $c$ is a 32-byte scalar derived by hashing the entire transcript of the proof up to that point. Typically, the hashing engine (like `BLAKE2b` or `SHA-256`, defined by the Ursa library) digests the following:
1. The **Public Key** ($W, h_0, \dots, h_n$).
2. The randomized signature components ($A'$, $\bar{A}$, $d$).
3. The **Revealed Messages** (their indices and raw byte values).
4. The **Zero-Knowledge Commitments** (points like $T$ generated using the $r$ blinding scalars).
5. The **Nonce** (a random 32-byte value provided by the verifier to ensure freshness).

$$c = \text{Hash}(PK \parallel A' \parallel \bar{A} \parallel d \parallel \text{Revealed Messages} \parallel T \parallel \text{Nonce})$$

### Is it possible to force a specific challenge?
**No, it is cryptographically infeasible.**
Because $c$ is the output of a cryptographic hash function, forcing $c$ to equal a specific scalar would require finding a pre-image for the hash function. The only degree of freedom you have is the `nonce` and blinding scalars ($r_i$); you could theoretically mine (brute-force) different nonces until the hash output starts with a few zeros, but you cannot dictate the exact 32 bytes of $c$.

## 4. Extracting Schnorr Responses from the Proof Bytes

The raw `proof` output of `bbs.create_proof()` is a highly structured byte array containing the serialized points and scalars. **Importantly, the challenge $c$ is NOT explicitly included in the proof.** In a Fiat-Shamir non-interactive proof, appending the challenge is redundant because the verifier must recompute it independently to ensure it was derived correctly. 

For `ursa_bbs_signatures`, the serialization follows the `ffi-bbs-signatures` Rust crate wrapper, which prepends a header to the underlying `bbs` crate proof:
1. **Total Messages (2 bytes)**: A big-endian `u16` indicating the total number of attributes.
2. **Revealed Bitvector**: A dynamically sized bit-array where bits correspond to the indices of the revealed messages.
3. **Points (G1)**: $A', \bar{A}, d$ are 48 bytes each (compressed BLS12-381 G1 points).
4. **Proof of Relation 1 (Subproof 1)**: This "subproof" is an announcement (commitment) and an array of responses to prove the first relation:
   $\bar{A} / d == (A')^{-e} \cdot h_0^{r_2}$
   It proves knowledge of the random scalars and the original signature's $e$ component. It contains a 4-byte length prefix (usually 2, because there are two scalars: $e$ and $r_2$) followed by the two 32-byte Schnorr responses.
5. **Proof of Relation 2 (Subproof 2)**: This is another announcement & array of responses to prove the much longer second relation:
   $g_1 \dots == d^{-r_3} \cdot h_0^{s'} \cdot \dots \cdot h_j^{m_j}$ (for undisclosed messages)
   It proves knowledge of the original signature's $s$ component along with the actual hidden messages $m_j$. It contains a 4-byte length prefix followed by the 32-byte Schnorr responses for the signature parts ($r_3$, $s'$) and all the hidden messages.

### Code Snippet: Structure of the Proof
If you want to parse the bytes and retrieve the Schnorr response for a hidden message, you can scan the proof structure. Since scalars are 32 bytes and BLS12-381 G1 points are 48 bytes, the offsets can be calculated based on the number of hidden values and the bit-vector length.

```python
import struct

def parse_hidden_response(proof_bytes: bytes, num_hidden: int):
    """
    Given the raw proof bytes from bbs.create_proof(),
    extract the response scalars for the hidden values.
    """
    # Note: Exact offsets depend on the Ursa version's precise serialization layout.
    # Typically, the hidden messages are appended at the very end of the array.
    
    # Each hidden message serializes as: [Index (4 bytes)] + [Response (32 bytes)]
    hidden_block_size = 36
    
    # Calculate where the hidden messages block starts
    offset = len(proof_bytes) - (num_hidden * hidden_block_size)
    
    results = {}
    for i in range(num_hidden):
        idx_bytes = proof_bytes[offset : offset+4]
        # In Ursa, usually little-endian format
        msg_idx = struct.unpack("<I", idx_bytes)[0] 
        
        response_bytes = proof_bytes[offset+4 : offset+36]
        results[msg_idx] = response_bytes
        
        offset += hidden_block_size
        
    return results

# Example Usage:
# proof_bytes = bbs.create_proof(...)
# responses = parse_hidden_response(proof_bytes, num_hidden=1)
# print(f"Response for hidden msg index {list(responses.keys())[0]} is {responses[0].hex()}")
```

This structural layout allows advanced implementations to manually inspect the bytes, verify specific properties, or implement Range Proofs by extracting $\hat{m}_j$ and binding it to an external Bulletproof.
