# Mathematical Proof: `ursa-bbs-signatures` Implements BBS+

Based on an analysis of the underlying Rust crate `bbs` (version `0.4.1`) which the `ursa-bbs-signatures` Python wrapper relies on, the library implements the **BBS+** signature scheme, not the original BBS scheme.

## Source Code Evidence

By examining the Rust source code in `src/signature.rs`, we find the explicit definition of the signature:

```rust
/// A BBS+ signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// A
    pub(crate) a: G1,
    /// e
    pub(crate) e: Fr,
    /// s
    pub(crate) s: Fr,
}

// https://eprint.iacr.org/2016/663.pdf Section 4.3
```

This perfectly maps to the mathematical differences between BBS and BBS+:

### 1. Original BBS (Boneh-Boyen-Shacham 2004)
The original BBS signature produces a tuple of two elements: $(A, e)$, where $A \in \mathbb{G}_1$ and $e \in \mathbb{Z}_p$.
The signature generation satisfies:
$$A = (g_1 \cdot \prod h_i^{m_i})^{\frac{1}{x+e}}$$
*(where $x$ is the secret key, $m_i$ are the messages, and $g_1, h_i$ are public generators).*

### 2. BBS+ (Au-Susilo-Mu 2006 / Camenisch et al. 2016)
To make the signature a stronger randomized signature (especially useful for zero-knowledge proofs and blind signatures), BBS+ injects a random blinding scalar into the signature itself.

The Rust code implements exactly this. It signs messages by generating **two random scalars** ($e$ and $s$) instead of one, resulting in a three-element tuple: $(A, e, s)$.

Let's look at the Rust function `compute_b` which computes the base, and then how `A` is computed:
```rust
        // g1*h0^blinding_factor*hi^mi.....
        bases.push(G1::one()); // g1
        scalars.push(Fr::from_repr(FrRepr::from(1)).unwrap());
        bases.push(verkey.h0.0.clone()); // h0
        scalars.push((*s).clone()); // s (blinding factor)
        ...
        // Mapped to:  b = g1 * h0^s * \prod h_i^{m_i}

        // Then it applies the secret key `x` and scalar `e`:
        let mut exp = signkey.0; // x
        exp.add_assign(&e); // x+e
        b.mul_assign(exp.inverse().unwrap()); // b^(1/(x+e))
```

Mathematically, this translates perfectly to:
$$A = (g_1 \cdot h_0^s \cdot \prod_{i=1}^L h_i^{m_i})^{\frac{1}{x+e}}$$

This proves that the library dynamically introduces the blinding scalar $s$ as part of the signature structure, making it a definitive **BBS+ implementation** according to the schema presented in "Anonymous Credentials Light" (Camenisch et al. 2016), which the source code explicitly references in its comments.
