# lib/crypto/hash.sage
# Cryptographic hash functions
# Pure Sage implementations of SHA-256, SHA-1 and CRC-32 (IEEE 802.3)

# ============================================================================
# Utility functions
#
# NOTE ON 32-BIT ROTATES: Sage numbers are IEEE doubles, so any intermediate
# >= 2^53 silently loses low bits. Rotates therefore mask each shifted half
# to < 2^32 BEFORE combining so every intermediate stays exactly representable.
# ============================================================================

proc u32(val):
    return val & 4294967295

proc u32_not(val):
    return 4294967295 ^ val

proc rotate_right(val, bits):
    bits = bits & 31
    if bits == 0:
        return u32(val)
    let v = u32(val)
    let low_keep = u32((1 << bits) - 1)
    return ((v >> bits) | ((v & low_keep) << (32 - bits))) & 4294967295

proc rotate_left(val, bits):
    bits = bits & 31
    if bits == 0:
        return u32(val)
    let v = u32(val)
    let high_keep = u32((1 << (32 - bits)) - 1)
    return (((v & high_keep) << bits) | (v >> (32 - bits))) & 4294967295

proc to_hex(bytes):
    let hex_chars = "0123456789abcdef"

    # Build into an array and join once to avoid O(N²)
    let out = []

    for b in bytes:
        push(out, hex_chars[(b >> 4) & 15])
        push(out, hex_chars[b & 15])

    return join(out, "")

proc hex_byte(b):
    let hex_chars = "0123456789abcdef"
    return hex_chars[(b >> 4) & 15] + hex_chars[b & 15]

proc string_to_bytes(str):
    let bytes = []
    for i in range(len(str)):
        push(bytes, ord(str[i]))
    return bytes

proc copy_bytes(src):
    let dst = []
    for b in src:
        push(dst, b)
    return dst

# ============================================================================
# SHA-256
# ============================================================================

# Normalise any accepted input type to a list of byte values.
#
# sha256() and sha1() used to do `for b in input` for the non-string case. The
# for loop only accepts array, tuple and dict, so passing a `bytes` object -- what
# io.readbytes() returns, and what SageLink hashes file contents from -- raised
# "for loop iterable must be an array, tuple, or dict" and left the buffer empty.
# The hash of the empty string was then returned with no error, so a file
# integrity check silently verified nothing.
proc to_byte_list(data):
    if type(data) == "string":
        let out = []
        for i in range(len(data)):
            push(out, ord(data[i]))
        return out
    if type(data) == "bytes" or type(data) == "unknown":
        let out = []
        for i in range(len(data)):
            push(out, data[i])
        return out
    return data

proc sha256(input):
    # Never mutate caller-owned input
    let bytes = []

    for b in to_byte_list(input):
        push(bytes, b)

    let msg_len = len(bytes)
    let bit_len = msg_len * 8

    # Append 0x80
    push(bytes, 128)

    # Pad with zeros until message length ≡ 56 mod 64
    while (len(bytes) + 8) % 64 != 0:
        push(bytes, 0)

    # Append original length as 64-bit big-endian integer
    for i in range(8):
        push(bytes, (bit_len >> (56 - i * 8)) & 255)

    let h0 = 1779033703
    let h1 = 3144134277
    let h2 = 1013904242
    let h3 = 2773480762
    let h4 = 1359893119
    let h5 = 2600822924
    let h6 = 528734635
    let h7 = 1541459225

    let k = [
        1116352408, 1899447441, 3049323471, 3921009573,
        961987163, 1508970993, 2453635748, 2870763221,
        3624381080, 310598401, 607225278, 1426881987,
        1925078388, 2162078206, 2614888103, 3248222580,
        3835390401, 4022224774, 264347078, 604807628,
        770255983, 1249150122, 1555081692, 1996064986,
        2554220882, 2821834349, 2952996808, 3210313671,
        3336571891, 3584528711, 113926993, 338241895,
        666307205, 773529912, 1294757372, 1396182291,
        1695183700, 1986661051, 2177026350, 2456956037,
        2730485921, 2820302411, 3259730800, 3345764771,
        3516065817, 3600352804, 4094571909, 275423344,
        430227734, 506948616, 659060556, 883997877,
        958139571, 1322822218, 1537002063, 1747873779,
        1955562222, 2024104815, 2227730452, 2361852424,
        2428436474, 2756734187, 3204031479, 3329325298
    ]

    for chunk_idx in range(len(bytes) / 64):
        let w = []

        for i in range(16):
            let offset = chunk_idx * 64 + i * 4

            let val = (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]

            push(w, u32(val))

        for i in range(16, 64):
            let s0 = rotate_right(w[i - 15], 7) ^ rotate_right(w[i - 15], 18) ^ (w[i - 15] >> 3)

            let s1 = rotate_right(w[i - 2], 17) ^ rotate_right(w[i - 2], 19) ^ (w[i - 2] >> 10)

            push(
                w,
                u32(w[i - 16] + s0 + w[i - 7] + s1)
            )

        let a = h0
        let b = h1
        let c = h2
        let d = h3
        let e = h4
        let f = h5
        let g = h6
        let h = h7

        for i in range(64):
            let S1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25)

            let ch = (e & f) ^ (u32_not(e) & g)

            let temp1 = u32(h + S1 + ch + k[i] + w[i])

            let S0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22)

            let maj = (a & b) ^ (a & c) ^ (b & c)

            let temp2 = u32(S0 + maj)

            h = g
            g = f
            f = e
            e = u32(d + temp1)
            d = c
            c = b
            b = a
            a = u32(temp1 + temp2)

        h0 = u32(h0 + a)
        h1 = u32(h1 + b)
        h2 = u32(h2 + c)
        h3 = u32(h3 + d)
        h4 = u32(h4 + e)
        h5 = u32(h5 + f)
        h6 = u32(h6 + g)
        h7 = u32(h7 + h)

    let result = []

    for val in [h0, h1, h2, h3, h4, h5, h6, h7]:
        for i in range(4):
            push(result, (val >> (24 - i * 8)) & 255)

    return result

proc sha256_hex(input):
    return to_hex(sha256(input))

# ============================================================================
# SHA-1
# ============================================================================

proc sha1(input):
    let bytes = []
    for b in to_byte_list(input):
        push(bytes, b)

    let msg_len = len(bytes)
    let bit_len = msg_len * 8

    push(bytes, 128)

    while (len(bytes) + 8) % 64 != 0:
        push(bytes, 0)

    for i in range(8):
        push(bytes, (bit_len >> (56 - i * 8)) & 255)

    let h0 = 1732584193
    let h1 = 4023233417
    let h2 = 2562383102
    let h3 = 271733878
    let h4 = 3285377520

    for chunk_idx in range(len(bytes) / 64):
        let w = []
        for i in range(16):
            let offset = chunk_idx * 64 + i * 4
            let val = (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]
            push(w, u32(val))
        for i in range(16, 80):
            let n = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
            push(w, rotate_left(n, 1))

        let a = h0
        let b = h1
        let c = h2
        let d = h3
        let e = h4

        for i in range(80):
            let f = 0
            let k = 0
            if i < 20:
                f = (b & c) | (u32_not(b) & d)
                k = 1518500249
            elif i < 40:
                f = b ^ c ^ d
                k = 1859775393
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 2400959708
            else:
                f = b ^ c ^ d
                k = 3395469782

            let temp = u32(rotate_left(a, 5) + f + e + k + w[i])
            e = d
            d = c
            c = rotate_left(b, 30)
            b = a
            a = temp

        h0 = u32(h0 + a)
        h1 = u32(h1 + b)
        h2 = u32(h2 + c)
        h3 = u32(h3 + d)
        h4 = u32(h4 + e)

    let result = []
    for val in [h0, h1, h2, h3, h4]:
        for i in range(4):
            push(result, (val >> (24 - i * 8)) & 255)
    return result

proc sha1_hex(input):
    return to_hex(sha1(input))

# CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320 — zlib/PNG compatible)
proc crc32(input):
    let bytes = string_to_bytes(input)
    let crc = 4294967295
    for b in bytes:
        # bitwise reflected table lookup (entry for low byte)
        let x = (crc ^ b) & 255
        for i in range(8):
            if x & 1:
                x = (x >> 1) ^ 3988292384
            else:
                x = x >> 1
        crc = (crc >> 8) ^ x
    return crc ^ 4294967295

proc crc32_hex(input):
    let c = crc32(input)
    return to_hex([(c >> 24) & 255, (c >> 16) & 255, (c >> 8) & 255, c & 255])
