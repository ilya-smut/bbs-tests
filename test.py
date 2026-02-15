
# Import the ursa_bbs_signatures library, which provides BBS+ signature primitives
import ursa_bbs_signatures as bbs
# Import os for random number generation and file operations
import os



def generate_keypair(seed: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Generate a BLS12-381 G2 keypair for BBS+ signatures.
    Returns (public_key, secret_key) as raw bytes.
    If no seed is provided, generates a random 32-byte seed for entropy.
    """
    if seed is None:
        # 32 bytes of entropy; you can derive this from user material if you want determinism
        seed = os.urandom(32)

    try:
        # Generate the keypair using the provided or random seed
        key_pair = bbs.BlsKeyPair.generate_g2(seed)
        return key_pair.public_key, key_pair.secret_key
    except Exception as e:
        raise RuntimeError("Unable to create BLS12-381 G2 keypair") from e


def sign_messages(messages: list[str], secret_key: bytes) -> bytes:
    """
    Sign an ordered list of messages (strings) with a BBS+ signature using the provided secret key.
    Returns the signature as bytes.
    """
    try:
        # Reconstruct the keypair from the secret key
        key_pair = bbs.BlsKeyPair.from_secret_key(secret_key)
        # Create a signing request with the keypair and messages
        sign_request = bbs.SignRequest(key_pair=key_pair, messages=messages)
        # Generate the BBS+ signature
        signature = bbs.sign(sign_request)
        return signature
    except (bbs.FfiException, bbs.BbsException) as e:
        raise RuntimeError("Unable to sign messages") from e
    

def verify_signature(messages: list[str], signature: bytes, public_key: bytes) -> bool:
    """
    Verify a BBS+ signature for the given messages and public key.
    Returns True if the signature is valid, False otherwise.
    """
    try:
        # Construct a keypair object from the public key
        key_pair = bbs.BlsKeyPair(public_key=public_key)
        # Create a verification request with the keypair, signature, and messages
        verify_request = bbs.VerifyRequest(
            key_pair=key_pair,
            signature=signature,
            messages=messages,
        )
        # Verify the signature
        return bbs.verify(verify_request)
    except (bbs.FfiException, bbs.BbsException) as e:
        raise RuntimeError("Unable to verify BBS+ signature") from e
    


# --- BBS+ Signature Workflow Example ---

# 1. Generate a BLS12-381 G2 keypair (public and secret keys)
public, secret = generate_keypair()

# 2. Define the messages to be signed
messages = ["NOTLOL", "KING"]
# For selective disclosure, define subsets of messages
only_first_message = ["NOTLOL"]
incorrect_first_message = ["BIMBIM"]

# 3. Sign the messages with the secret key
signature = sign_messages(messages=messages, secret_key=secret)
print("Signature (bytes):", signature)

# 4. Verify the signature using the public key and original messages
is_valid = verify_signature(messages=messages, signature=signature, public_key=public)
print("Signature valid?", is_valid)

# 5. Prepare messages for zero-knowledge proof (ZKP) of knowledge of signature
#    - The first message will be revealed, the second will be hidden
parsed_messages = []
for index, message in enumerate(messages):
    if index == 0:
        # Reveal the first message in the proof
        parsed_messages.append(bbs.ProofMessage(message=message, proof_type=bbs.ProofMessageType.Revealed))
    else:
        # Hide the second message with proof-specific blinding
        parsed_messages.append(bbs.ProofMessage(message=message, proof_type=bbs.ProofMessageType.HiddenProofSpecificBlinding))

# 6. Generate a random nonce for the proof
nonce = os.urandom(32)

# 7. Derive the BBS+ public key for the number of messages
#key_pair = bbs.BlsKeyPair.from_secret_key(secret)
#pub_key = key_pair.get_bbs_key(2)  # 2 = number of messages

# 7.1 Derving public key without using the secret key
public_key_obj = bbs.BlsKeyPair(public_key=public)
pub_key_derived = public_key_obj.get_bbs_key(2)

# 8. Create a zero-knowledge proof that proves knowledge of a valid signature
#    - Only the first message is revealed, the second remains hidden
proof_request = bbs.CreateProofRequest(public_key=pub_key_derived, messages=parsed_messages, signature=signature, nonce=nonce)
proof = bbs.create_proof(proof_request)

# 9. Verify the zero-knowledge proof using only the revealed message and nonce
ver_pr_request = bbs.VerifyProofRequest(public_key=pub_key_derived, proof=proof, messages=only_first_message, nonce=nonce)
is_valid_proof = bbs.verify_proof(ver_pr_request)
print("Proof (bytes):", proof)
print("Proof valid?", is_valid_proof)

# 10. Print the length of the proof (for informational purposes)
print("Proof length (bytes):", len(proof))
print("Public key length (bytes):", len(pub_key_derived.public_key))
print("Signature length (bytes):", len(signature))
print("nonce length (bytes):", len(nonce))
print("length of disclosed message (bytes):", len(only_first_message[0].encode("utf-8")))

# 11. Encode the proof as base64 and generate a QR code for easy sharing
import qrcode
import base64

raw = proof
b64 = base64.b64encode(raw).decode("ascii")  # convert bytes → base64 string

# Create a QR code with medium error correction
qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M)
qr.add_data(b64)
qr.make(fit=True)

# Render the QR code as an image and save to file
img = qr.make_image()
img.save("my_bytes_b64_qr.png")

