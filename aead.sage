# lib/crypto/aead.sage
# Pure SageLang implementation of ChaCha20-Poly1305 AEAD (RFC 8439)

import crypto.chacha20
import crypto.poly1305

proc to_byte_list(data):
    if type(data) == "string":
        let out = []
        for i in range(len(data)):
            push(out, ord(data[i]))
        return out
    end
    if type(data) == "unknown":
        let out = []
        for i in range(len(data)):
            push(out, data[i])
        return out
    end
    return data

proc le64(val):
    let b = []
    let temp = val
    for i in range(8):
        push(b, temp & 255)
        temp = temp >> 8
    return b

proc pad16(b):
    let pad_len = (16 - (len(b) % 16)) % 16
    let padded = []
    for i in range(len(b)):
        push(padded, b[i])
    for i in range(pad_len):
        push(padded, 0)
    return padded

proc chacha20_poly1305_encrypt(key, nonce, plaintext, aad):
    let k_bytes = to_byte_list(key)
    let n_bytes = to_byte_list(nonce)
    let p_bytes = to_byte_list(plaintext)
    let aad_bytes = to_byte_list(aad)

    # 1. Generate Poly1305 otk
    let block0 = chacha20.chacha20_block(k_bytes, 0, n_bytes)
    let otk = []
    for i in range(32):
        push(otk, block0[i])

    # 2. Encrypt plaintext
    let ciphertext = chacha20.chacha20_encrypt(k_bytes, 1, n_bytes, p_bytes)

    # 3. Build Poly1305 input message
    let poly_msg = []
    
    # AAD + padding
    let padded_aad = pad16(aad_bytes)
    for i in range(len(padded_aad)):
        push(poly_msg, padded_aad[i])

    # Ciphertext + padding
    let padded_ct = pad16(ciphertext)
    for i in range(len(padded_ct)):
        push(poly_msg, padded_ct[i])

    # AAD length (64-bit LE)
    let aad_len_bytes = le64(len(aad_bytes))
    for i in range(8):
        push(poly_msg, aad_len_bytes[i])

    # Ciphertext length (64-bit LE)
    let ct_len_bytes = le64(len(ciphertext))
    for i in range(8):
        push(poly_msg, ct_len_bytes[i])

    # 4. Generate tag
    let tag = poly1305.poly1305_mac(otk, poly_msg)

    return {"ciphertext": ciphertext, "tag": tag}

proc chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, aad):
    let k_bytes = to_byte_list(key)
    let n_bytes = to_byte_list(nonce)
    let ct_bytes = to_byte_list(ciphertext)
    let t_bytes = to_byte_list(tag)
    let aad_bytes = to_byte_list(aad)

    # 1. Generate Poly1305 otk
    let block0 = chacha20.chacha20_block(k_bytes, 0, n_bytes)
    let otk = []
    for i in range(32):
        push(otk, block0[i])

    # 2. Build Poly1305 input message
    let poly_msg = []
    
    let padded_aad = pad16(aad_bytes)
    for i in range(len(padded_aad)):
        push(poly_msg, padded_aad[i])

    let padded_ct = pad16(ct_bytes)
    for i in range(len(padded_ct)):
        push(poly_msg, padded_ct[i])

    let aad_len_bytes = le64(len(aad_bytes))
    for i in range(8):
        push(poly_msg, aad_len_bytes[i])

    let ct_len_bytes = le64(len(ct_bytes))
    for i in range(8):
        push(poly_msg, ct_len_bytes[i])

    # 3. Verify tag
    let computed_tag = poly1305.poly1305_mac(otk, poly_msg)
    
    let verified = 1
    for i in range(16):
        if computed_tag[i] != t_bytes[i]:
            verified = 0

    if verified == 0:
        return nil

    # 4. Decrypt ciphertext
    return chacha20.chacha20_decrypt(k_bytes, 1, n_bytes, ct_bytes)
