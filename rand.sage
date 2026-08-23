# Pseudorandom number generators for cryptographic and general use
# Implements xoshiro256** (fast, high-quality PRNG) and utilities

proc u32(x):
    return x & 4294967295

proc u64(x):
    return x & 18446744073709551615

proc rotl64(x, k):
    return u64((x << k) | (x >> (64 - k)))

# ============================================================================
# xoshiro256** PRNG (period 2^256 - 1)
# ============================================================================

# Create a PRNG state from a 64-bit seed
proc create(seed):
    let state = {}

    # SplitMix64 to initialize 4 state words from single seed
    let s = seed

    let r0 = splitmix64_next(s)
    s = r0["state"]

    let r1 = splitmix64_next(s)
    s = r1["state"]

    let r2 = splitmix64_next(s)
    s = r2["state"]

    let r3 = splitmix64_next(s)

    state["s0"] = r0["value"]
    state["s1"] = r1["value"]
    state["s2"] = r2["value"]
    state["s3"] = r3["value"]

    return state

proc splitmix64_next(state):
    let z = u64(state + 11400714819323198485)
    z = u64((z ^ (z >> 30)) * 13787848793156543929)
    z = u64((z ^ (z >> 27)) * 10723151780598845931)
    z = u64(z ^ (z >> 31))

    let result = {}
    result["value"] = z
    result["state"] = u64(state + 11400714819323198485)

    return result

# ============================================================================
# xoshiro256**
# ============================================================================

proc next_u64(state):
    let s0 = state["s0"]
    let s1 = state["s1"]
    let s2 = state["s2"]
    let s3 = state["s3"]

    let result = u64(rotl64(u64(s1 * 5), 7) * 9)

    let t = u64(s1 << 17)

    s2 = u64(s2 ^ s0)
    s3 = u64(s3 ^ s1)
    s1 = u64(s1 ^ s2)
    s0 = u64(s0 ^ s3)
    s2 = u64(s2 ^ t)
    s3 = rotl64(s3, 45)

    state["s0"] = s0
    state["s1"] = s1
    state["s2"] = s2
    state["s3"] = s3

    return result

proc next_u32(state):
    return u32(next_u64(state))

# Generate random number in [0, bound)
proc next_bounded(state, bound):
    if bound <= 1:
        return 0

    let r = next_u64(state)

    if r < 0:
        r = 0 - r

    return r - ((r / bound) | 0) * bound

# Generate random float in [0.0, 1.0)
proc next_float(state):
    let r = next_u64(state) & 4503599627370495
    return r / 4503599627370496

# ============================================================================
# Random Data
# ============================================================================

proc random_bytes(state, count):
    let result = []

    for i in range(count):
        push(result, next_u32(state) & 255)

    return result

# Generate a random hex string of given byte length
# Fixed: O(N) instead of O(N²)
proc random_hex(state, byte_count):
    let digits = "0123456789abcdef"
    let bytes = random_bytes(state, byte_count)
    let out = []

    for b in bytes:
        push(out, digits[(b >> 4) & 15])
        push(out, digits[b & 15])

    return join(out, "")

# Generate a random alphanumeric string
# Fixed: O(N) instead of O(N²)
proc random_string(state, length):
    let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

    let out = []

    for i in range(length):
        let idx = next_bounded(state, 62)
        push(out, chars[idx])

    return join(out, "")

# Generate a UUID v4 (RFC 4122)
# Fixed: O(N) instead of O(N²)
proc uuid4(state):
    let bytes = random_bytes(state, 16)

    # Version 4
    bytes[6] = (bytes[6] & 15) | 64

    # Variant 1 (RFC 4122)
    bytes[8] = (bytes[8] & 63) | 128

    let digits = "0123456789abcdef"
    let out = []

    for i in range(16):
        push(out, digits[(bytes[i] >> 4) & 15])
        push(out, digits[bytes[i] & 15])

        if i == 3 or i == 5 or i == 7 or i == 9:
            push(out, "-")

    return join(out, "")

# ============================================================================
# Linear Congruential Generator
# ============================================================================

proc lcg_create(seed):
    let state = {}
    state["value"] = seed
    return state

proc lcg_next(state):
    state["value"] = u32(
        state["value"] * 1664525 + 1013904223
    )
    return state["value"]

proc lcg_bounded(state, bound):
    if bound <= 1:
        return 0

    let r = lcg_next(state)
    return r - ((r / bound) | 0) * bound

# ============================================================================
# Utilities
# ============================================================================

# Shuffle an array in-place using Fisher-Yates
proc shuffle(state, arr):
    let n = len(arr)
    let i = n - 1

    while i > 0:
        let j = next_bounded(state, i + 1)

        let temp = arr[i]
        arr[i] = arr[j]
        arr[j] = temp

        i = i - 1

    return arr

# ============================================================================
# Cryptographically Secure Random Bytes
# ============================================================================

proc get_urandom_bytes(count):
    let libc = ffi_open("libc.so.6")

    if libc == nil:
        libc = ffi_open("libc.so")

    if libc == nil:
        libc = ffi_open("")

    if libc == nil:
        raise "FFI: libc not found"

    let fd = ffi_call(
        libc,
        "open",
        "int",
        ["/dev/urandom", 0]
    )

    if fd < 0:
        ffi_close(libc)
        raise "Failed to open /dev/urandom"

    let buf = mem_alloc(count)

    let nread = ffi_call(
        libc,
        "read",
        "int",
        [fd, buf, count]
    )

    if nread != count:
        mem_free(buf)
        ffi_call(libc, "close", "int", [fd])
        ffi_close(libc)
        raise "Failed to read enough bytes from /dev/urandom"

    let bytes = []

    for i in range(count):
        push(bytes, mem_read(buf, i, "byte"))

    mem_free(buf)
    ffi_call(libc, "close", "int", [fd])
    ffi_close(libc)

    return bytes
