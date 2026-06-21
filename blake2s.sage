# lib/crypto/blake2s.sage
# Pure SageLang implementation of BLAKE2s (RFC 7693)

proc u32(x):
    return x & 4294967295

proc rotr32(x, n):
    let shift_right = x >> n
    let shift_left = x
    let k = 32 - n
    for i in range(k):
        shift_left = shift_left + shift_left
        if shift_left >= 4294967296:
            shift_left = shift_left - 4294967296
    return (shift_right | shift_left) & 4294967295

let BLAKE2S_IV = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

let BLAKE2S_SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
]

proc blake2s_G(r, i, v, a, b, c, d, m):
    let s_row = BLAKE2S_SIGMA[r]
    v[a] = u32(v[a] + v[b] + m[s_row[2 * i]])
    v[d] = rotr32(v[d] ^ v[a], 16)
    
    v[c] = u32(v[c] + v[d])
    v[b] = rotr32(v[b] ^ v[c], 12)
    
    v[a] = u32(v[a] + v[b] + m[s_row[2 * i + 1]])
    v[d] = rotr32(v[d] ^ v[a], 8)
    
    v[c] = u32(v[c] + v[d])
    v[b] = rotr32(v[b] ^ v[c], 7)

proc blake2s_compress(h, m, t, f):
    let v = []
    # Initialize v[0..7] = h[0..7]
    for i in range(8):
        push(v, h[i])
    # Initialize v[8..15] = IV[0..7]
    for i in range(8):
        push(v, BLAKE2S_IV[i])
        
    # Mix offset and flags
    v[12] = v[12] ^ t[0]
    v[13] = v[13] ^ t[1]
    v[14] = v[14] ^ f[0]
    v[15] = v[15] ^ f[1]

    # 10 rounds of mixing
    for r in range(10):
        blake2s_G(r, 0, v, 0, 4, 8, 12, m)
        blake2s_G(r, 1, v, 1, 5, 9, 13, m)
        blake2s_G(r, 2, v, 2, 6, 10, 14, m)
        blake2s_G(r, 3, v, 3, 7, 11, 15, m)
        blake2s_G(r, 4, v, 0, 5, 10, 15, m)
        blake2s_G(r, 5, v, 1, 6, 11, 12, m)
        blake2s_G(r, 6, v, 2, 7, 8, 13, m)
        blake2s_G(r, 7, v, 3, 4, 9, 14, m)

    # Update state h
    for i in range(8):
        h[i] = h[i] ^ v[i] ^ v[i + 8]

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

proc blake2s(msg, key = nil):
    # key: optional key (byte list or string, max 32 bytes)
    let m_bytes = to_byte_list(msg)
    let k_bytes = []
    if key != nil:
        k_bytes = to_byte_list(key)

    # State initialization
    let h = []
    for i in range(8):
        push(h, BLAKE2S_IV[i])

    let k_len = len(k_bytes)
    # Param block: fanout=1, depth=1, leaf_size=0, node_offset=0, node_depth=0, inner_len=0
    # digest_len=32, key_len = k_len
    h[0] = h[0] ^ (0x01010000 | (k_len << 8) | 32)

    let bytes_processed = 0
    let block_bytes = []
    
    # Process key block if present
    if k_len > 0:
        for i in range(k_len):
            push(block_bytes, k_bytes[i])
        while len(block_bytes) < 64:
            push(block_bytes, 0)
        bytes_processed = 64
        
        # If message is empty, this is the final block
        let f0 = 0
        if len(m_bytes) == 0:
            f0 = 0xffffffff
            
        let m_words = []
        for i in range(16):
            let offset = i * 4
            let w = block_bytes[offset] | (block_bytes[offset+1] << 8) | (block_bytes[offset+2] << 16) | (block_bytes[offset+3] << 24)
            push(m_words, u32(w))
            
        blake2s_compress(h, m_words, [bytes_processed, 0], [f0, 0])
        block_bytes = []

    let msg_len = len(m_bytes)
    let idx = 0
    
    # Loop over message blocks
    while idx < msg_len:
        let chunk_len = msg_len - idx
        if chunk_len > 64:
            chunk_len = 64
            
        for i in range(chunk_len):
            push(block_bytes, m_bytes[idx + i])
            
        bytes_processed = bytes_processed + chunk_len
        
        let f0 = 0
        if idx + chunk_len == msg_len:
            f0 = 0xffffffff
            # Pad final block
            while len(block_bytes) < 64:
                push(block_bytes, 0)
                
        let m_words = []
        for i in range(16):
            let offset = i * 4
            let w = block_bytes[offset] | (block_bytes[offset+1] << 8) | (block_bytes[offset+2] << 16) | (block_bytes[offset+3] << 24)
            push(m_words, u32(w))
            
        blake2s_compress(h, m_words, [bytes_processed, 0], [f0, 0])
        block_bytes = []
        idx = idx + chunk_len

    # If key was empty and message was empty, process one empty block
    if k_len == 0 and msg_len == 0:
        let m_words = []
        for i in range(16):
            push(m_words, 0)
        blake2s_compress(h, m_words, [0, 0], [0xffffffff, 0])

    # Convert state to bytes (little-endian)
    let out_bytes = []
    for i in range(8):
        let val = h[i]
        push(out_bytes, val & 255)
        push(out_bytes, (val >> 8) & 255)
        push(out_bytes, (val >> 16) & 255)
        push(out_bytes, (val >> 24) & 255)
        
    return out_bytes
