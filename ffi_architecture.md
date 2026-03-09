# `ursa-bbs-signatures`: Python FFI Architecture

The `ursa-bbs-signatures` library does **not** implement complex cryptography (like elliptic curve pairings) directly in Python.

Python is notoriously slow for heavy cryptographic operations, and writing cryptography from scratch in Python is generally discouraged due to the high risk of side-channel attacks and implementation bugs. 

Instead, the Python library acts strictly as a **Foreign Function Interface (FFI) wrapper** around a highly optimized, compiled **Rust** library.

Here is exactly how the architecture works:

### 1. The Core Cryptography (Rust Crate)
At the very bottom layer is the pure Rust crate `bbs`. This crate uses another Rust crate called `pairing-plus` to perform the actual BLS12-381 elliptic curve operations and pairing mathematics required for BBS+ signatures.

### 2. The Bridge (Rust C-API / FFI)
The `bbs` Rust crate is wrapped by another Rust project called `ffi-bbs-signatures`. This project's sole purpose is to take the complex Rust structs (like `Signature`, `BlindedCommitment`, etc.) and expose them as a flat **C-compatible API**. 
When compiled, this Rust project produces a shared library file:
- `libbbs.so` (on Linux)
- `libbbs.dylib` (on macOS)
- `bbs.dll` (on Windows)

### 3. The Python Intermediary Loaders (`ctypes`)
In the Python code, specifically inside `ursa_bbs_signatures/_ffi/ffi_util.py`, the library uses Python's built-in `ctypes` module to load this shared C-library into the Python runtime memory. 

```python
# From _ffi_util.py
from ctypes import CDLL

# It figures out your OS and loads the compiled Rust library
lib_path = os.path.join(os.path.dirname(__file__), '..', "libbbs.so")
return CDLL(lib_path)
```

### 4. The Data Marshalling Layer
Python objects and C/Rust objects don't share identical memory layouts. The Python wrapper has to "marshal" (convert) data back and forth. 

For example, when you pass a string message to be signed, the Python wrapper intercepts it in `_ffi/bindings/bbs_sign.py`:
```python
def bbs_sign_context_add_message_string(handle: int, message: str) -> None:
    # 1. Takes the Python string and encodes it to UTF-8 bytes
    # 2. Creates a C-compatible character pointer (c_char_p)
    # 3. Passes it across the FFI boundary to the Rust function
    func(handle, encode_str(message), byref(err))
```

### 5. Memory Management (The `ByteBuffer`)
One tricky part of FFI is memory management. Who frees the memory for the signature bytes? Python's garbage collector, or Rust?
To handle this safely, the library uses a custom struct called a `ByteBuffer`. When Rust creates a signature, it allocates memory and returns a pointer to Python. Python wraps this in a `ByteBuffer` class:
```python
class ByteBuffer(Structure):
    # ... fields ...
    def __del__(self):
        # When Python garbage collects this object, it explicitly calls 
        # a Rust function `bbs_byte_buffer_free` to tell Rust to free the memory!
        get_library().bbs_byte_buffer_free(self)
```

### Summary of the Flow:
When you run `bbs.blind_sign(req)` in your code:
1. **Python API**: You call the nice Python object-oriented method.
2. **Data Conversion**: Python converts your strings and objects into raw bytes and C-pointers.
3. **FFI Call**: Python executes the compiled C-function inside the `libbbs.so` binary.
4. **Rust Execution**: The Rust code executes the fast, secure math on the BLS12-381 curve.
5. **Return**: Rust passes a pointer to the result back out.
6. **Python Translation**: Python turns that pointer back into a nice Python `bytes` object for you to print or use.
