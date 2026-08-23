gc_disable()
# Symmetric cipher utilities
# XOR cipher, RC4 stream cipher, and block cipher mode helpers

proc u32(x):
    return x & 4294967295

proc str_to_bytes(s):
    let bytes = []
    for i in range(len(s)):
        push(bytes, ord(s[i]))
    return bytes

# ============================================================================
# AES Constants & Tables
# ============================================================================
let AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

let AES_INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

let AES_RCON = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]

# ============================================================================
# XOR Cipher (repeating key)
# ============================================================================

proc xor_encrypt(data, key):
    let d = data
    if type(data) == "string":
        d = str_to_bytes(data)
    let k = key
    if type(key) == "string":
        k = str_to_bytes(key)
    let klen = len(k)
    let result = []
    for i in range(len(d)):
        push(result, d[i] ^ k[i % klen])
    return result

# XOR decrypt is identical to encrypt
proc xor_decrypt(data, key):
    return xor_encrypt(data, key)

# ============================================================================
# RC4 Stream Cipher
# ============================================================================

# Initialize RC4 key schedule (KSA)
proc rc4_init(key):
    let k = key
    if type(key) == "string":
        k = str_to_bytes(key)
    let s = []
    for i in range(256):
        push(s, i)
    let klen = len(k)
    if klen == 0:
        raise "rc4: empty key"
    let j = 0
    for i in range(256):
        j = (j + s[i] + k[i % klen]) & 255
        let temp = s[i]
        s[i] = s[j]
        s[j] = temp
    let state = {}
    state["s"] = s
    state["i"] = 0
    state["j"] = 0
    return state

# Generate next RC4 keystream byte
proc rc4_next(state):
    let s = state["s"]
    state["i"] = (state["i"] + 1) & 255
    let i = state["i"]
    state["j"] = (state["j"] + s[i]) & 255
    let j = state["j"]
    let temp = s[i]
    s[i] = s[j]
    s[j] = temp
    return s[(s[i] + s[j]) & 255]

# Encrypt/decrypt data using RC4
proc rc4(key, data):
    let d = data
    if type(data) == "string":
        d = str_to_bytes(data)
    let state = rc4_init(key)
    let result = []
    for i in range(len(d)):
        push(result, d[i] ^ rc4_next(state))
    return result

# ============================================================================
# Block Cipher Mode Helpers (for use with external block ciphers)
# ============================================================================

# PKCS#7 padding
proc pkcs7_pad(data, block_size):
    let d = data
    if type(data) == "string":
        d = str_to_bytes(data)
    let pad_len = block_size - (len(d) & (block_size - 1))
    if pad_len == 0:
        pad_len = block_size
    let result = []
    for i in range(len(d)):
        push(result, d[i])
    for i in range(pad_len):
        push(result, pad_len)
    return result

# Remove PKCS#7 padding
proc pkcs7_unpad(data):
    if len(data) == 0:
        return data
    let pad_len = data[len(data) - 1]
    if pad_len > len(data) or pad_len == 0:
        return data
    # Verify all padding bytes
    let valid = true
    for i in range(pad_len):
        if data[len(data) - 1 - i] != pad_len:
            valid = false
    if not valid:
        return data
    let result = []
    for i in range(len(data) - pad_len):
        push(result, data[i])
    return result

# XOR two blocks of equal length
proc xor_blocks(a, b):
    let result = []
    for i in range(len(a)):
        push(result, a[i] ^ b[i])
    return result

# CBC mode encrypt (takes a block encrypt function, IV, and padded data)
# block_encrypt_fn: proc(block, key) -> encrypted block (byte arrays)
proc cbc_encrypt(block_encrypt_fn, key, iv, data):
    let block_size = len(iv)
    let result = []
    let prev = iv
    let i = 0
    while i < len(data):
        let block = []
        for j in range(block_size):
            if i + j < len(data):
                push(block, data[i + j])
            else:
                push(block, 0)
        let xored = xor_blocks(block, prev)
        let encrypted = block_encrypt_fn(xored, key)
        for j in range(len(encrypted)):
            push(result, encrypted[j])
        prev = encrypted
        i = i + block_size
    return result

# CBC mode decrypt
proc cbc_decrypt(block_decrypt_fn, key, iv, data):
    let block_size = len(iv)
    let result = []
    let prev = iv
    let i = 0
    while i < len(data):
        let block = []
        for j in range(block_size):
            if i + j < len(data):
                push(block, data[i + j])
            else:
                push(block, 0)
        let decrypted = block_decrypt_fn(block, key)
        let xored = xor_blocks(decrypted, prev)
        for j in range(len(xored)):
            push(result, xored[j])
        prev = block
        i = i + block_size
    return result

# CTR mode (encrypt and decrypt are identical)
proc ctr(block_encrypt_fn, key, nonce, data):
    let block_size = len(nonce)
    let result = []
    let counter = 0
    let i = 0
    while i < len(data):
        # Build counter block: nonce + counter (big-endian in last 4 bytes)
        let ctr_block = []
        for j in range(len(nonce)):
            push(ctr_block, nonce[j])
        # Overwrite last 4 bytes with counter
        let ctr_off = len(ctr_block) - 4
        if ctr_off < 0:
            ctr_off = 0
        ctr_block[ctr_off] = (counter >> 24) & 255
        ctr_block[ctr_off + 1] = (counter >> 16) & 255
        ctr_block[ctr_off + 2] = (counter >> 8) & 255
        ctr_block[ctr_off + 3] = counter & 255
        let keystream = block_encrypt_fn(ctr_block, key)
        for j in range(block_size):
            if i + j < len(data):
                push(result, data[i + j] ^ keystream[j])
        counter = counter + 1
        i = i + block_size
    return result

# ============================================================================
# AES block and high-level encryption/decryption
# ============================================================================

proc g2(x):
    let res = x << 1
    if (x & 128) != 0:
        res = res ^ 27
    return res & 255

proc aes_key_expansion(key):
    let key_len = len(key)
    if key_len != 16 and key_len != 32:
        raise "aes: key must be 16 bytes (AES-128) or 32 bytes (AES-256)"
    let expanded = []
    for i in range(key_len):
        push(expanded, key[i])
    
    let size = 176
    if key_len == 32:
        size = 240
    
    let bytes_generated = key_len
    let rcon_iteration = 1
    
    while bytes_generated < size:
        let temp = [
            expanded[bytes_generated - 4],
            expanded[bytes_generated - 3],
            expanded[bytes_generated - 2],
            expanded[bytes_generated - 1]
        ]
        
        if bytes_generated % key_len == 0:
            let t = temp[0]
            temp[0] = temp[1]
            temp[1] = temp[2]
            temp[2] = temp[3]
            temp[3] = t
            
            temp[0] = AES_SBOX[temp[0]]
            temp[1] = AES_SBOX[temp[1]]
            temp[2] = AES_SBOX[temp[2]]
            temp[3] = AES_SBOX[temp[3]]
            
            temp[0] = temp[0] ^ AES_RCON[rcon_iteration]
            rcon_iteration = rcon_iteration + 1
        elif key_len == 32 and bytes_generated % 32 == 16:
            temp[0] = AES_SBOX[temp[0]]
            temp[1] = AES_SBOX[temp[1]]
            temp[2] = AES_SBOX[temp[2]]
            temp[3] = AES_SBOX[temp[3]]
        
        for i in range(4):
            push(expanded, expanded[bytes_generated - key_len] ^ temp[i])
            bytes_generated = bytes_generated + 1
            
    return expanded

proc aes_block_encrypt(block, key):
    let key_len = len(key)
    let rounds = 10
    if key_len == 32:
        rounds = 14
    let w = aes_key_expansion(key)
    
    let state = []
    for i in range(16):
        push(state, block[i])
    
    for i in range(16):
        state[i] = state[i] ^ w[i]
    
    for r in range(1, rounds):
        for i in range(16):
            state[i] = AES_SBOX[state[i]]
        
        let t = []
        for i in range(16):
            push(t, state[i])
        state[1] = t[5]
        state[5] = t[9]
        state[9] = t[13]
        state[13] = t[1]
        
        state[2] = t[10]
        state[6] = t[14]
        state[10] = t[2]
        state[14] = t[6]
        
        state[3] = t[15]
        state[7] = t[3]
        state[11] = t[7]
        state[15] = t[11]
        
        let tc = []
        for i in range(16):
            push(tc, state[i])
        
        for c in range(4):
            let col = c * 4
            let s0 = tc[col]
            let s1 = tc[col + 1]
            let s2 = tc[col + 2]
            let s3 = tc[col + 3]
            
            let g2_0 = g2(s0)
            let g2_1 = g2(s1)
            let g2_2 = g2(s2)
            let g2_3 = g2(s3)
            
            state[col]     = g2_0 ^ (g2_1 ^ s1) ^ s2 ^ s3
            state[col + 1] = s0 ^ g2_1 ^ (g2_2 ^ s2) ^ s3
            state[col + 2] = s0 ^ s1 ^ g2_2 ^ (g2_3 ^ s3)
            state[col + 3] = (g2_0 ^ s0) ^ s1 ^ s2 ^ g2_3
        
        let key_off = r * 16
        for i in range(16):
            state[i] = state[i] ^ w[key_off + i]
            
    for i in range(16):
        state[i] = AES_SBOX[state[i]]
    
    let t_f = []
    for i in range(16):
        push(t_f, state[i])
    state[1] = t_f[5]
    state[5] = t_f[9]
    state[9] = t_f[13]
    state[13] = t_f[1]
    
    state[2] = t_f[10]
    state[6] = t_f[14]
    state[10] = t_f[2]
    state[14] = t_f[6]
    
    state[3] = t_f[15]
    state[7] = t_f[3]
    state[11] = t_f[7]
    state[15] = t_f[11]
    
    let final_key_off = rounds * 16
    for i in range(16):
        state[i] = state[i] ^ w[final_key_off + i]
    
    return state

proc aes_block_decrypt(block, key):
    let key_len = len(key)
    let rounds = 10
    if key_len == 32:
        rounds = 14
    let w = aes_key_expansion(key)
    
    let state = []
    for i in range(16):
        push(state, block[i])
    
    let final_key_off = rounds * 16
    for i in range(16):
        state[i] = state[i] ^ w[final_key_off + i]
    
    let r = rounds - 1
    while r >= 1:
        let t = []
        for i in range(16):
            push(t, state[i])
        state[1] = t[13]
        state[5] = t[1]
        state[9] = t[5]
        state[13] = t[9]
        
        state[2] = t[10]
        state[6] = t[14]
        state[10] = t[2]
        state[14] = t[6]
        
        state[3] = t[7]
        state[7] = t[11]
        state[11] = t[15]
        state[15] = t[3]
        
        for i in range(16):
            state[i] = AES_INV_SBOX[state[i]]
        
        let key_off = r * 16
        for i in range(16):
            state[i] = state[i] ^ w[key_off + i]
        
        let tc = []
        for i in range(16):
            push(tc, state[i])
        
        for c in range(4):
            let col = c * 4
            let s0 = tc[col]
            let s1 = tc[col + 1]
            let s2 = tc[col + 2]
            let s3 = tc[col + 3]
            
            let g2_0 = g2(s0)
            let g4_0 = g2(g2_0)
            let g8_0 = g2(g4_0)
            
            let g2_1 = g2(s1)
            let g4_1 = g2(g2_1)
            let g8_1 = g2(g4_1)
            
            let g2_2 = g2(s2)
            let g4_2 = g2(g2_2)
            let g8_2 = g2(g4_2)
            
            let g2_3 = g2(s3)
            let g4_3 = g2(g2_3)
            let g8_3 = g2(g4_3)
            
            state[col] = (g8_0 ^ g4_0 ^ g2_0) ^ (g8_1 ^ g2_1 ^ s1) ^ (g8_2 ^ g4_2 ^ s2) ^ (g8_3 ^ s3)
            state[col + 1] = (g8_0 ^ s0) ^ (g8_1 ^ g4_1 ^ g2_1) ^ (g8_2 ^ g2_2 ^ s2) ^ (g8_3 ^ g4_3 ^ s3)
            state[col + 2] = (g8_0 ^ g4_0 ^ s0) ^ (g8_1 ^ s1) ^ (g8_2 ^ g4_2 ^ g2_2) ^ (g8_3 ^ g2_3 ^ s3)
            state[col + 3] = (g8_0 ^ g2_0 ^ s0) ^ (g8_1 ^ g4_1 ^ s1) ^ (g8_2 ^ s2) ^ (g8_3 ^ g4_3 ^ g2_3)
        
        r = r - 1
    
    let t_f = []
    for i in range(16):
        push(t_f, state[i])
    state[1] = t_f[13]
    state[5] = t_f[1]
    state[9] = t_f[5]
    state[13] = t_f[9]
    
    state[2] = t_f[10]
    state[6] = t_f[14]
    state[10] = t_f[2]
    state[14] = t_f[6]
    
    state[3] = t_f[7]
    state[7] = t_f[11]
    state[11] = t_f[15]
    state[15] = t_f[3]
    
    for i in range(16):
        state[i] = AES_INV_SBOX[state[i]]
    
    for i in range(16):
        state[i] = state[i] ^ w[i]
    
    return state

proc aes_encrypt(data, key):
    let iv = []
    for i in range(16):
        push(iv, 0)
    if type(data) == "string":
        data = str_to_bytes(data)
    if type(key) == "string":
        key = str_to_bytes(key)
    let padded = pkcs7_pad(data, 16)
    return cbc_encrypt(aes_block_encrypt, key, iv, padded)

proc aes_decrypt(data, key):
    let iv = []
    for i in range(16):
        push(iv, 0)
    if type(data) == "string":
        data = str_to_bytes(data)
    if type(key) == "string":
        key = str_to_bytes(key)
    let decrypted = cbc_decrypt(aes_block_decrypt, key, iv, data)
    return pkcs7_unpad(decrypted)
