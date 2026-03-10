# BBS+ Blinded Signature Issuance and Unblinding Mathematics

This document details the underlying mathematics of the 2-party blind signature issuance and unblinding process as implemented in the Rust `bbs` crate (`ursa-bbs-signatures`).

## 1. Prover's Blinding and Commitment
When a prover (user) wants to obtain a signature where some messages are hidden from the issuer, they first generate a blind commitment.

The implementation for this is found in `crate::prover::Prover::new_blind_signature_context`.
The prover generates a random scalar called the **blinding factor** (often denoted as $\tilde{s}$ or $s'$ in literature):
```rust
let blinding_factor = Signature::generate_blinding(); // Let's call this s~
```

The prover then forms a cryptographic commitment $C$ over the hidden messages $m_i$ for $i \in \text{hidden}$:
$$C = h_0^{\tilde{s}} \cdot \prod_{i \in \text{hidden}} h_i^{m_i}$$

*In code:*
```rust
builder.add(&verkey.h0, &blinding_factor);
for (i, m) in messages {
    builder.add(&verkey.h[*i], &m);
}
let commitment = builder.finalize();
```
The prover sends this commitment $C$ to the issuer, alongside a zero-knowledge proof of knowledge of the hidden messages and the blinding factor $\tilde{s}$.

## 2. Issuer's Blind Signature Generation
The issuer verifies the zero-knowledge proof to ensure $C$ was formed correctly. Then, they generate a **Blind Signature** using the commitment and any known messages.

The implementation for this is `crate::signature::BlindSignature::new`.
The issuer generates two random scalars $e \leftarrow \mathbb{Z}_r^*$ and $s'' \leftarrow \mathbb{Z}_r^*$ (in the code, $s''$ is just called `s`):
```rust
let e = Fr::random(&mut rng);
let s = Fr::random(&mut rng); // This is s''
```

Next, the issuer computes the base $B$ for the signature. In standard BBS+, the base $B$ for a set of messages $\{m_1, \dots, m_n\}$ is:
$$B = g_1 \cdot h_0^s \cdot \prod_{i=1}^n h_i^{m_i}$$

Since the issuer does not know the hidden messages, they substitute the hidden portion with the prover's commitment $C$. The issuer calculates:
$$B = C \cdot g_1 \cdot h_0^{s''} \cdot \prod_{j \in \text{known}} h_j^{m_j}$$

*In code:*
```rust
points.push(commitment.0); // C
scalars.push(1);
points.push(G1::one());    // g_1
scalars.push(1);
points.push(verkey.h0.0.clone()); // h_0
scalars.push(s.clone());          // s''
for (i, m) in messages.iter() {
    points.push(verkey.h[*i].0.clone()); // h_j
    scalars.push(m.0.clone());           // m_j
}
let mut b = multi_scalar_mul_const_time_g1(&points, &scalars);
```

If we substitute the prover's formula for $C$ into the issuer's equation for $B$, we mathematically get:
$$B = \left( h_0^{\tilde{s}} \cdot \prod_{i \in \text{hidden}} h_i^{m_i} \right) \cdot g_1 \cdot h_0^{s''} \cdot \prod_{j \in \text{known}} h_j^{m_j}$$
$$B = g_1 \cdot h_0^{\tilde{s} + s''} \cdot \prod_{k \in \text{all}} h_k^{m_k}$$

Finally, the issuer signs this base $B$ using their secret key $x$ (`signkey`):
$$A = B^{\frac{1}{x + e}}$$

*In code:*
```rust
let mut exp = signkey.0;
exp.add_assign(&e);
b.mul_assign(exp.inverse().unwrap());
```

The issuer sends the tuple $(A, e, s'')$ back to the prover as the `BlindSignature`.

## 3. Prover's Unblinding
The prover receives the blind signature $(A, e, s'')$. To convert this into a standard, valid BBS+ signature, the prover must "unblind" it.

The implementation is `crate::signature::BlindSignature::to_unblinded`.
Because $B$ inherently contained $h_0^{\tilde{s} + s''}$, the true $s$ scalar for the complete signature must be the sum of the prover's blinding factor and the issuer's random $s''$:
$$s_{\text{unblinded}} = s'' + \tilde{s}$$

*In code:*
```rust
pub fn to_unblinded(&self, blinding: &SignatureBlinding) -> Signature {
    let mut s = self.s;
    s.add_assign(&blinding.0); // s'' + s~
    Signature {
        a: self.a,
        s,
        e: self.e,
    }
}
```

The final unblinded signature is $(A, e, s_{\text{unblinded}})$. This is exactly identical in structure and mathematical validity to a standard signature generated natively by the issuer. The issuer does not learn $m_i$ for $i \in \text{hidden}$, yet the resulting signature perfectly binds to those messages via the commitment and the $s_{\text{unblinded}}$ factor!
