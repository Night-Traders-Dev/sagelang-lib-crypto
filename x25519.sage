# lib/crypto/x25519.sage
# Pure SageLang implementation of Curve25519 DH (RFC 7748)

proc u32(x):
    return x & 4294967295

proc bytes_to_words16(b):
    let w = []
    for i in range(16):
        let offset = i * 2
        push(w, b[offset] | (b[offset+1] << 8))
    return w

proc words16_to_bytes(w):
    let b = []
    for i in range(16):
        push(b, w[i] & 255)
        push(b, (w[i] >> 8) & 255)
    return b

proc fe_from_int(val):
    let fe = []
    let temp = val
    for i in range(16):
        push(fe, temp & 0xffff)
        temp = temp >> 16
    return fe

proc fe_carry(c):
    let carry = 0
    for i in range(16):
        let val = c[i] + carry
        let rem = val % 65536
        c[i] = rem
        carry = (val - rem) / 65536
    c[0] = c[0] + carry * 38
    
    let carry2 = 0
    for i in range(16):
        let val = c[i] + carry2
        let rem = val % 65536
        c[i] = rem
        carry2 = (val - rem) / 65536
    c[0] = c[0] + carry2 * 38
    return c

proc fe_add(a, b):
    let c = []
    for i in range(16):
        push(c, a[i] + b[i])
    return fe_carry(c)

proc fe_sub(a, b):
    let c = []
    push(c, a[0] + 131034 - b[0])
    for i in range(1, 15):
        push(c, a[i] + 131070 - b[i])
    push(c, a[15] + 65534 - b[15])
    return fe_carry(c)

proc mul32(x, y):
    return x * y

proc mul_38(v):
    return v * 38

proc fe_mul(a, b):
    let c = []
    for i in range(16):
        push(c, 0)
    for i in range(16):
        let sum = 0
        for j in range(i + 1):
            sum = sum + mul32(a[j], b[i - j])
        for j in range(i + 1, 16):
            sum = sum + mul_38(mul32(a[j], b[16 + i - j]))
        c[i] = sum
    return fe_carry(c)

proc fe_sub_p(a):
    let res = []
    let borrow = 0
    
    let diff = a[0] - 65517 - borrow
    let w = diff
    if diff < 0:
        w = diff + 65536
        borrow = 1
    else:
        borrow = 0
    push(res, w)

    for i in range(1, 15):
        let diff = a[i] - 65535 - borrow
        let w = diff
        if diff < 0:
            w = diff + 65536
            borrow = 1
        else:
            borrow = 0
        push(res, w)
            
    let diff2 = a[15] - 32767 - borrow
    let w2 = diff2
    if diff2 < 0:
        w2 = diff2 + 65536
        borrow = 1
    else:
        borrow = 0
    push(res, w2)
        
    return {"res": res, "borrow": borrow}

proc fe_reduce(a):
    let reduced = a
    for i in range(3):
        let sub = fe_sub_p(reduced)
        if sub["borrow"] == 0:
            reduced = sub["res"]
    return reduced

proc fe_invert(z):
    let res = fe_from_int(1)
    let temp = z
    for bit in range(255):
        let bit_set = 1
        if bit == 2 or bit == 4:
            bit_set = 0
        if bit_set == 1:
            res = fe_mul(res, temp)
        temp = fe_mul(temp, temp)
    return res

proc fe_cswap(swap, x, y):
    if swap == 1:
        for i in range(16):
            let temp = x[i]
            x[i] = y[i]
            y[i] = temp

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

proc x25519(scalar, u_coord):
    let k_bytes = to_byte_list(scalar)
    let u_bytes = to_byte_list(u_coord)

    # Clamp k
    let k = []
    for i in range(32):
        push(k, k_bytes[i])
    k[0] = k[0] & 248
    k[31] = k[31] & 127
    k[31] = k[31] | 64

    let x_1 = bytes_to_words16(u_bytes)
    let x_2 = fe_from_int(1)
    let z_2 = fe_from_int(0)
    let x_3 = []
    for i in range(16):
        push(x_3, x_1[i])
    let z_3 = fe_from_int(1)
    
    let swap = 0
    let a24 = fe_from_int(121665)

    for t in range(255):
        let bit_idx = 254 - t
        let byte_pos = bit_idx >> 3
        let bit_pos = bit_idx & 7
        let k_t = (k[byte_pos] >> bit_pos) & 1
        
        swap = swap ^ k_t
        fe_cswap(swap, x_2, x_3)
        fe_cswap(swap, z_2, z_3)
        swap = k_t

        let A = fe_add(x_2, z_2)
        let AA = fe_mul(A, A)
        let B = fe_sub(x_2, z_2)
        let BB = fe_mul(B, B)
        let E = fe_sub(AA, BB)
        let C = fe_add(x_3, z_3)
        let D = fe_sub(x_3, z_3)
        let DA = fe_mul(D, A)
        let CB = fe_mul(C, B)
        
        let sum_da_cb = fe_add(DA, CB)
        x_3 = fe_mul(sum_da_cb, sum_da_cb)
        
        let diff_da_cb = fe_sub(DA, CB)
        let diff_sq = fe_mul(diff_da_cb, diff_da_cb)
        z_3 = fe_mul(x_1, diff_sq)
        
        x_2 = fe_mul(AA, BB)
        
        let a24_e = fe_mul(a24, E)
        let sum_aa_a24e = fe_add(AA, a24_e)
        z_2 = fe_mul(E, sum_aa_a24e)

    fe_cswap(swap, x_2, x_3)
    fe_cswap(swap, z_2, z_3)

    let z_inv = fe_invert(z_2)
    let out_words = fe_mul(x_2, z_inv)
    let reduced_out = fe_reduce(out_words)
    
    return words16_to_bytes(reduced_out)
