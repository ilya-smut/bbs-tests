import os
import ursa_bbs_signatures as bbs

def main():
    # 1. Signer Setup
    seed = os.urandom(32)
    key_pair = bbs.BlsKeyPair.generate_g2(seed)
    
    # We will sign 3 messages:
    # Index 0: "Known Message 1" (Known to signer)
    # Index 1: "Blinded Message 1" (Hidden from signer)
    # Index 2: "Known Message 2" (Known to signer)
    total_messages = 3
    # pub_key has to be derived for the total number of messages
    pub_key = key_pair.get_bbs_key(total_messages)
    
    # 2. Prover creates blinded commitment for the blinded messages
    blinded_str = "Blinded Message 1"
    blinded_index = 1
    nonce = os.urandom(32)
    
    blinded_messages = [bbs.IndexedMessage(index=blinded_index, message=blinded_str)]
    
    commit_req = bbs.CreateBlindedCommitmentRequest(
        public_key=pub_key,
        messages=blinded_messages,
        nonce=nonce
    )
    
    commitment_out = bbs.create_blinded_commitment(commit_req)
    
    print("Commitment created!")
    
    # 3. Signer creates blind signature
    known_msg_1 = "Known Message 1"
    known_msg_2 = "Known Message 2"
    known_messages = [
        bbs.IndexedMessage(index=0, message=known_msg_1),
        bbs.IndexedMessage(index=2, message=known_msg_2)
    ]
    
    blind_sign_req = bbs.BlindSignRequest(
        secret_key=key_pair, # Note: using key_pair which has secret_key
        public_key=pub_key,
        commitment=commitment_out.commitment,
        messages=known_messages
    )
    
    blinded_sig = bbs.blind_sign(blind_sign_req)
    print("Blinded signature created!")
    
    # 4. Prover unblinds the signature
    unblind_req = bbs.UnblindSignatureRequest(
        blinded_signature=blinded_sig,
        blinding_factor=commitment_out.blinding_factor
    )
    
    final_sig = bbs.unblind_signature(unblind_req)
    print("Signature unblinded!")
    
    # 5. Prover verifies the signature using the regular verify function
    # It requires ALL messages in the correct order
    all_messages = [known_msg_1, blinded_str, known_msg_2]
    
    verify_req = bbs.VerifyRequest(
        key_pair=bbs.BlsKeyPair(public_key=key_pair.public_key),
        signature=final_sig,
        messages=all_messages
    )
    
    is_valid = bbs.verify(verify_req)
    print("Final Signature Valid?", is_valid)

if __name__ == "__main__":
    main()
