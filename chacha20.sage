# lib/crypto/chacha20.sage
# Pure SageLang implementation of ChaCha20 (RFC 8439)

proc u32(x):
    return x & 4294967295

proc rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 4294967295

proc quarter_round(state, a, b, c, d):
    state[a] = u32(state[a] + state[b])
    state[d] = state[d] ^ state[a]
    state[d] = rotl32(state[d], 16)

    state[c] = u32(state[c] + state[d])
    state[b] = state[b] ^ state[c]
    state[b] = rotl32(state[b], 12)

    state[a] = u32(state[a] + state[b])
    state[d] = state[d] ^ state[a]
    state[d] = rotl32(state[d], 8)

    state[c] = u32(state[c] + state[d])
    state[b] = state[b] ^ state[c]
    state[b] = rotl32(state[b], 7)

proc chacha20_block(key, counter, nonce):
    # key: 8-word list or 32-byte list/string
    # counter: 32-bit int
    # nonce: 3-word list or 12-byte list/string
    let state = []
    
    # Constants "expand 32-byte k"
    push(state, 0x61707865)
    push(state, 0x3320646e)
    push(state, 0x79622d32)
    push(state, 0x6b206574)

    # Key (8 words)
    let k = []
    if type(key) == "string":
        for i in range(8):
            let offset = i * 4
            let w = ord(key[offset]) | (ord(key[offset+1]) << 8) | (ord(key[offset+2]) << 16) | (ord(key[offset+3]) << 24)
            push(k, u32(w))
    elif len(key) == 32:
        for i in range(8):
            let offset = i * 4
            let w = key[offset] | (key[offset+1] << 8) | (key[offset+2] << 16) | (key[offset+3] << 24)
            push(k, u32(w))
    else:
        k = key

    for i in range(8):
        push(state, k[i])

    # Counter
    push(state, u32(counter))

    # Nonce (3 words)
    let n = []
    if type(nonce) == "string":
        for i in range(3):
            let offset = i * 4
            let w = ord(nonce[offset]) | (ord(nonce[offset+1]) << 8) | (ord(nonce[offset+2]) << 16) | (ord(nonce[offset+3]) << 24)
            push(n, u32(w))
    elif len(nonce) == 12:
        for i in range(3):
            let offset = i * 4
            let w = nonce[offset] | (nonce[offset+1] << 8) | (nonce[offset+2] << 16) | (nonce[offset+3] << 24)
            push(n, u32(w))
    else:
        n = nonce

    for i in range(3):
        push(state, n[i])

    # Copy initial state
    let initial = []
    for i in range(16):
        push(initial, state[i])

    # 20 rounds (10 iterations of column/diagonal rounds)
    for i in range(10):
        # Column rounds
        quarter_round(state, 0, 4, 8, 12)
        quarter_round(state, 1, 5, 9, 13)
        quarter_round(state, 2, 6, 10, 14)
        quarter_round(state, 3, 7, 11, 15)
        # Diagonal rounds
        quarter_round(state, 0, 5, 10, 15)
        quarter_round(state, 1, 6, 11, 12)
        quarter_round(state, 2, 7, 8, 13)
        quarter_round(state, 3, 4, 9, 14)

    # Add initial state to mixed state
    let out_bytes = []
    for i in range(16):
        let val = u32(state[i] + initial[i])
        push(out_bytes, val & 255)
        push(out_bytes, (val >> 8) & 255)
        push(out_bytes, (val >> 16) & 255)
        push(out_bytes, (val >> 24) & 255)

    return out_bytes

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

proc chacha20_encrypt(key, counter, nonce, plaintext):
    let p = to_byte_list(plaintext)
    let key_bytes = to_byte_list(key)
    let nonce_bytes = to_byte_list(nonce)
    
    let ciphertext = []
    let p_len = len(p)
    let block_idx = counter
    let i = 0

    while i < p_len:
        let key_stream = chacha20_block(key_bytes, block_idx, nonce_bytes)
        let chunk_size = 64
        if p_len - i < 64:
            chunk_size = p_len - i
        
        for j in range(chunk_size):
            push(ciphertext, p[i + j] ^ key_stream[j])
        
        i = i + chunk_size
        block_idx = block_idx + 1

    return ciphertext

proc chacha20_decrypt(key, counter, nonce, ciphertext):
    return chacha20_encrypt(key, counter, nonce, ciphertext)
