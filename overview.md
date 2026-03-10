# Notes Overview

This document provides a summary of the markdown notes available in the `./notes` directory.

### [bbs_plus_proof.md](./notes/bbs_plus_proof.md)
Provides a mathematical proof that the `ursa-bbs-signatures` Python wrapper and its underlying `bbs` Rust crate implement the **BBS+** signature scheme rather than the original BBS scheme. It highlights the use of an explicit blinding scalar $s$ within the source code to support this claim.

### [bbs_vs_bbs_plus_blinding.md](./notes/bbs_vs_bbs_plus_blinding.md)
Compares the blinding mechanism between original BBS and BBS+. Explains that the original BBS signatures lack the $s$ scalar needed for a prover to introduce a blinding factor natively, a problem that BBS+ solves by allowing the signature to "absorb" the blinding factor securely.

### [blind_issuance_math.md](./notes/blind_issuance_math.md)
A comprehensive mathematical breakdown of the 2-party blind signature issuance and unblinding process. It walks through the prover's initial blinding and commitment, the issuer's blind signature generation, and the final unblinding step performed by the prover to construct a valid BBS+ signature.

### [ffi_architecture.md](./notes/ffi_architecture.md)
An architectural overview of how the Python `ursa-bbs-signatures` library interacts with the underlying Rust cryptography implementation. It explains the Foreign Function Interface (FFI) layer, the use of `ctypes` for loading compiled Rust binaries, data marshalling between Python and C/Rust, and how memory management is handled.
