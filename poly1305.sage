# lib/crypto/poly1305.sage
# Pure SageLang implementation of Poly1305 (RFC 8439)

proc u32(x):
    return x & 4294967295

proc bytes_to_words13(b):
    let words = []
    let bit_buf = 0
    let bit_cnt = 0
    let byte_idx = 0
    for i in range(10):
        while bit_cnt < 13:
            let val = 0
            if byte_idx < len(b):
                val = b[byte_idx]
                byte_idx = byte_idx + 1
            let shifted = val
            for k in range(bit_cnt):
                shifted = shifted + shifted
            bit_buf = bit_buf + shifted
            bit_cnt = bit_cnt + 8
        
        let word = bit_buf % 8192
        push(words, word)
        bit_buf = (bit_buf - word) / 8192
        bit_cnt = bit_cnt - 13
    return words

proc words13_to_bytes(words):
    let b = []
    let bit_buf = 0
    let bit_cnt = 0
    for i in range(len(words)):
        let shifted = words[i]
        for k in range(bit_cnt):
            shifted = shifted + shifted
        bit_buf = bit_buf + shifted
        bit_cnt = bit_cnt + 13
        while bit_cnt >= 8:
            let byte_val = bit_buf % 256
            push(b, byte_val)
            bit_buf = (bit_buf - byte_val) / 256
            bit_cnt = bit_cnt - 8
    return b

proc poly1305_clamp(r):
    let clamped = []
    for i in range(16):
        push(clamped, r[i])
    clamped[3] = clamped[3] & 15
    clamped[7] = clamped[7] & 15
    clamped[11] = clamped[11] & 15
    clamped[15] = clamped[15] & 15
    clamped[4] = clamped[4] & 252
    clamped[8] = clamped[8] & 252
    clamped[12] = clamped[12] & 252
    return clamped

proc mul26(x, y):
    let y_low = y & 63
    let y_high = y >> 6
    let p1 = x * y_low
    let p2 = x * y_high
    let p2_shifted = p2
    for i in range(6):
        p2_shifted = p2_shifted + p2_shifted
    return p1 + p2_shifted

proc mul5(x):
    let x2 = x + x
    let x4 = x2 + x2
    return x4 + x

proc poly1305_mul(a, r):
    let c = []
    for i in range(10):
        push(c, 0)

    for i in range(10):
        let sum = 0
        for j in range(i + 1):
            sum = sum + mul26(a[j], r[i - j])
        for j in range(i + 1, 10):
            sum = sum + mul5(mul26(a[j], r[10 + i - j]))
        c[i] = sum

    let carry = 0
    for i in range(10):
        let val = c[i] + carry
        c[i] = val % 8192
        carry = (val - c[i]) / 8192

    c[0] = c[0] + carry * 5

    let carry2 = 0
    for i in range(10):
        let val = c[i] + carry2
        c[i] = val % 8192
        carry2 = (val - c[i]) / 8192
    c[0] = c[0] + carry2 * 5

    return c

proc poly1305_add(a, b):
    let res = []
    let carry = 0
    for i in range(10):
        let val = a[i] + b[i] + carry
        push(res, val % 8192)
        carry = (val - (val % 8192)) / 8192
    
    if carry > 0:
        let val = res[0] + carry * 5
        res[0] = val % 8192
        let c2 = (val - res[0]) / 8192
        let idx = 1
        while c2 > 0 and idx < 10:
            let val2 = res[idx] + c2
            res[idx] = val2 % 8192
            c2 = (val2 - res[idx]) / 8192
            idx = idx + 1
    return res

proc poly1305_sub_p(a):
    let res = []
    let borrow = 0
    
    let diff = a[0] - 8187 - borrow
    let w = diff
    if diff < 0:
        w = diff + 8192
        borrow = 1
    else:
        borrow = 0
    push(res, w)

    for i in range(1, 10):
        let diff = a[i] - 8191 - borrow
        let w = diff
        if diff < 0:
            w = diff + 8192
            borrow = 1
        else:
            borrow = 0
        push(res, w)
            
    return {"res": res, "borrow": borrow}

proc poly1305_tag(a, s_words):
    let sub = poly1305_sub_p(a)
    let reduced = a
    if sub["borrow"] == 0:
        reduced = sub["res"]
    
    let sub2 = poly1305_sub_p(reduced)
    if sub2["borrow"] == 0:
        reduced = sub2["res"]

    let tag_words = poly1305_add(reduced, s_words)
    let tag_bytes = words13_to_bytes(tag_words)
    
    let final_tag = []
    for i in range(16):
        push(final_tag, tag_bytes[i])
    return final_tag

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

proc poly1305_mac(key, msg):
    let k_bytes = to_byte_list(key)
    let m_bytes = to_byte_list(msg)

    let r_bytes = []
    let s_bytes = []
    for i in range(16):
        push(r_bytes, k_bytes[i])
        push(s_bytes, k_bytes[16 + i])

    let r_clamped = poly1305_clamp(r_bytes)
    let r_words = bytes_to_words13(r_clamped)
    let s_words = bytes_to_words13(s_bytes)

    let a_words = []
    for i in range(10):
        push(a_words, 0)

    let msg_len = len(m_bytes)
    let idx = 0
    while idx < msg_len:
        let block_len = 16
        if msg_len - idx < 16:
            block_len = msg_len - idx
        
        let block_bytes = []
        for i in range(block_len):
            push(block_bytes, m_bytes[idx + i])
        
        push(block_bytes, 1)

        let block_words = bytes_to_words13(block_bytes)
        
        a_words = poly1305_add(a_words, block_words)
        a_words = poly1305_mul(a_words, r_words)
        
        idx = idx + block_len

    return poly1305_tag(a_words, s_words)
