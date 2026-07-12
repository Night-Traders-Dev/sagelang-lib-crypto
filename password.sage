gc_disable()
# Password hashing and verification utilities
# PBKDF2-HMAC key derivation and password storage

# ============================================================================
# Utility Functions
# ============================================================================

proc str_to_bytes(s):
    let bytes = []
    for i in range(len(s)):
        push(bytes, ord(s[i]))
    return bytes

proc copy_bytes(src):
    let dst = []
    for b in src:
        push(dst, b)
    return dst

proc to_hex(bytes):
    let digits = "0123456789abcdef"
    let out = []

    for b in bytes:
        push(out, digits[(b >> 4) & 15])
        push(out, digits[b & 15])

    return join(out, "")

proc hex_val(c):
    let code = ord(c)

    if code >= 48 and code <= 57:
        return code - 48

    if code >= 65 and code <= 70:
        return code - 55

    if code >= 97 and code <= 102:
        return code - 87

    return -1

proc hex_decode(encoded):
    let result = []
    let i = 0

    while i + 1 < len(encoded):
        let hi = hex_val(encoded[i])
        let lo = hex_val(encoded[i + 1])

        if hi >= 0 and lo >= 0:
            push(result, hi * 16 + lo)

        i = i + 2

    return result

proc split_colon(s):
    let parts = []
    let current = []

    for i in range(len(s)):
        if s[i] == ":":
            push(parts, join(current, ""))
            current = []
        else:
            push(current, s[i])

    push(parts, join(current, ""))

    return parts

# Constant-time comparison
proc secure_compare(a, b):
    if len(a) != len(b):
        return false

    let result = 0

    for i in range(len(a)):
        result = result | (a[i] ^ b[i])

    return result == 0

# ============================================================================
# Internal HMAC
# ============================================================================

proc hmac_raw(hash_fn, key, message, block_size):
    let k = []

    for b in key:
        push(k, b)

    if len(k) > block_size:
        k = hash_fn(k)

    let padded_key = []

    for b in k:
        push(padded_key, b)

    while len(padded_key) < block_size:
        push(padded_key, 0)

    let i_key_pad = []
    let o_key_pad = []

    for i in range(block_size):
        push(i_key_pad, padded_key[i] ^ 54)
        push(o_key_pad, padded_key[i] ^ 92)

    let inner_input = []

    for b in i_key_pad:
        push(inner_input, b)

    for b in message:
        push(inner_input, b)

    let inner_hash = hash_fn(inner_input)

    let outer_input = []

    for b in o_key_pad:
        push(outer_input, b)

    for b in inner_hash:
        push(outer_input, b)

    return hash_fn(outer_input)

# ============================================================================
# PBKDF2
# ============================================================================

proc pbkdf2(hash_fn, password, salt, iterations, key_length, block_size):
    let pwd = []

    if type(password) == "string":
        pwd = str_to_bytes(password)
    else:
        pwd = copy_bytes(password)

    let s = []

    if type(salt) == "string":
        s = str_to_bytes(salt)
    else:
        s = copy_bytes(salt)

    let result = []
    let block_num = 1
    let hash_len = len(hash_fn([]))

    while len(result) < key_length:
        let salt_block = []

        for b in s:
            push(salt_block, b)

        push(salt_block, (block_num >> 24) & 255)
        push(salt_block, (block_num >> 16) & 255)
        push(salt_block, (block_num >> 8) & 255)
        push(salt_block, block_num & 255)

        let u = hmac_raw(
            hash_fn,
            pwd,
            salt_block,
            block_size
        )

        let dk = []

        for b in u:
            push(dk, b)

        for iter in range(iterations - 1):
            u = hmac_raw(
                hash_fn,
                pwd,
                u,
                block_size
            )

            for i in range(len(dk)):
                dk[i] = dk[i] ^ u[i]

        for i in range(len(dk)):
            if len(result) < key_length:
                push(result, dk[i])

        block_num = block_num + 1

    return result

# ============================================================================
# Password Storage
# ============================================================================

# Returns:
# "pbkdf2:iterations:salt_hex:hash_hex"

proc hash_password(
    hash_fn,
    password,
    salt_bytes,
    iterations,
    block_size
):
    let key = pbkdf2(
        hash_fn,
        password,
        salt_bytes,
        iterations,
        32,
        block_size
    )

    let salt_hex = to_hex(salt_bytes)
    let key_hex = to_hex(key)

    let parts = [
        "pbkdf2",
        str(iterations),
        salt_hex,
        key_hex
    ]

    return join(parts, ":")

proc verify_password(
    hash_fn,
    password,
    hash_string,
    block_size
):
    let parts = split_colon(hash_string)

    if len(parts) != 4:
        return false

    if parts[0] != "pbkdf2":
        return false

    let iterations = tonumber(parts[1])

    if iterations <= 0:
        return false

    let salt_bytes = hex_decode(parts[2])
    let expected = hex_decode(parts[3])

    if len(expected) == 0:
        return false

    let derived = pbkdf2(
        hash_fn,
        password,
        salt_bytes,
        iterations,
        len(expected),
        block_size
    )

    return secure_compare(
        derived,
        expected
    )
