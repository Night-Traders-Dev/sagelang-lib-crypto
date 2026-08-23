# Pseudorandom number generators for cryptographic and general use
# Implements xoshiro256** (period 2^256 - 1) seeded via SplitMix64.
#
# AUDIT NOTE: Sage numbers are IEEE doubles (53-bit exact integers), so the
# previous direct 64-bit arithmetic silently corrupted every multiply that
# exceeded 2^53. All 64-bit operations below are now performed on {hi, lo}
# 32-bit limb pairs, which keeps every intermediate exactly representable.
# Public API is unchanged.

proc u32(x):
    return x & 4294967295

proc u64(x):
    # Normalize any number into an exact 64-bit pair
    let t = x - (x % 4294967296)
    return {"hi": u32(t / 4294967296), "lo": u32(x)}

proc p_add(a, b):
    let lo = a["lo"] + b["lo"]
    return {"hi": u32(a["hi"] + b["hi"] + (lo >> 32)), "lo": u32(lo)}

proc p_sub(a, b):
    let d = a["lo"] - b["lo"]
    let borrow = 0 - (d >> 63)
    return {"hi": u32(a["hi"] - b["hi"] - borrow), "lo": u32(d)}

proc p_xor(a, b):
    return {"hi": a["hi"] ^ b["hi"], "lo": a["lo"] ^ b["lo"]}

proc p_shl(a, k):
    if k == 0:
        return {"hi": a["hi"], "lo": a["lo"]}
    if k >= 64:
        return {"hi": 0, "lo": 0}
    if k >= 32:
        # keep only bits of lo that survive the extra left shift
        let keep = (1 << (64 - k)) - 1
        return {"hi": (a["lo"] & keep) << (k - 32), "lo": 0}
    let keep = (1 << (32 - k)) - 1
    return {
        "hi": (((a["hi"] & keep) << k) | (a["lo"] >> (32 - k))) & 4294967295,
        "lo": (a["lo"] & keep) << k
    }

proc p_shr(a, k):
    if k == 0:
        return {"hi": a["hi"], "lo": a["lo"]}
    if k >= 64:
        return {"hi": 0, "lo": 0}
    if k >= 32:
        return {"hi": 0, "lo": a["hi"] >> (k - 32)}
    return {
        "hi": a["hi"] >> k,
        "lo": (a["lo"] >> k) | ((a["hi"] & ((1 << k) - 1)) << (32 - k))
    }

proc p_rotl(a, k):
    return p_xor(p_shl(a, k), p_shr(a, 64 - k))

proc p_mul(a, b):
    # Schoolbook multiply on 16-bit limbs: result mod 2^64.
    # All partial products and carries stay below 2^53 (exact doubles).
    let a0 = a["lo"] & 65535
    let a1 = (a["lo"] >> 16) & 65535
    let a2 = a["hi"] & 65535
    let a3 = (a["hi"] >> 16) & 65535
    let b0 = b["lo"] & 65535
    let b1 = (b["lo"] >> 16) & 65535
    let b2 = b["hi"] & 65535
    let b3 = (b["hi"] >> 16) & 65535

    let p0 = a0 * b0
    let p1 = a0 * b1 + a1 * b0
    let p2 = a0 * b2 + a1 * b1 + a2 * b0
    let p3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0

    let d0 = p0 % 65536
    let t1 = p1 + ((p0 - d0) / 65536)
    let d1 = t1 % 65536
    let t2 = p2 + ((t1 - d1) / 65536)
    let d2 = t2 % 65536
    let t3 = p3 + ((t2 - d2) / 65536)
    let d3 = t3 % 65536

    return {
        "hi": (d2 | (d3 << 16)) & 4294967295,
        "lo": (d0 | (d1 << 16)) & 4294967295
    }

proc p_rotl(a, k):
    return p_xor(p_shl(a, k), p_shr(a, 64 - k))

# ============================================================================
# SplitMix64 seeding
# ============================================================================

# SplitMix64 constants, built from 32-bit halves because their full values
# exceed 2^53 and would be silently rounded by double-precision parsing.
proc sm_gamma():
    return {"hi": 2654435769, "lo": 2135587861}      # 0x9E3779B97F4A7C15

proc sm_mult1():
    return {"hi": 3210233709, "lo": 484763065}       # 0xBF58476D1CE4E5B9

proc sm_mult2():
    return {"hi": 2496678331, "lo": 321982955}       # 0x94D049BB133111EB

proc splitmix64_next_pair(state_pair):
    let s = state_pair
    let z = p_add(s, sm_gamma())
    let z2 = p_mul(p_xor(z, p_shr(z, 30)), sm_mult1())
    let z3 = p_mul(p_xor(z2, p_shr(z2, 27)), sm_mult2())
    let out = p_xor(z3, p_shr(z3, 31))
    return {"value": out, "state": z}

# ============================================================================
# xoshiro256**
# ============================================================================

proc create(seed):
    let state = {}
    let s = u64(seed)

    let r0 = splitmix64_next_pair(s)
    let r1 = splitmix64_next_pair(r0["state"])
    let r2 = splitmix64_next_pair(r1["state"])
    let r3 = splitmix64_next_pair(r2["state"])

    state["s0"] = r0["value"]
    state["s1"] = r1["value"]
    state["s2"] = r2["value"]
    state["s3"] = r3["value"]

    return state

proc next_u64_pair(state):
    let s0 = state["s0"]
    let s1 = state["s1"]
    let s2 = state["s2"]
    let s3 = state["s3"]

    # xoshiro256**: rotl(s1 * 5, 7) * 9
    let five = {"hi": 0, "lo": 5}
    let nine = {"hi": 0, "lo": 9}

    let mul5 = p_mul(s1, five)
    let rot7 = p_xor(p_shl(mul5, 7), p_shr(mul5, 57))
    let res = p_mul(rot7, nine)

    let t = p_shl(s1, 17)

    state["s2"] = p_xor(s2, s0)
    state["s3"] = p_xor(s3, s1)
    state["s1"] = p_xor(s1, state["s2"])
    state["s0"] = p_xor(s0, state["s3"])
    state["s2"] = p_xor(state["s2"], t)
    state["s3"] = p_rotl(state["s3"], 45)

    return res

proc next_u32(state):
    return next_u64_pair(state)["lo"]

proc next_bounded(state, bound):
    if bound <= 1:
        return 0
    # Rejection sampling on a full 32-bit draw: unbiased for any bound < 2^32
    let zone = u32(4294967296 - (4294967296 % bound))
    while true:
        let r = next_u32(state)
        if r < zone:
            return r % bound

proc next_float(state):
    return next_u32(state) / 4294967296.0

# ============================================================================
# Random Data
# ============================================================================

proc random_bytes(state, count):
    let result = []
    for i in range(count):
        push(result, next_u32(state) & 255)
    return result

proc random_hex(state, byte_count):
    let digits = "0123456789abcdef"
    let bytes = random_bytes(state, byte_count)
    let out = []
    for b in bytes:
        push(out, digits[(b >> 4) & 15])
        push(out, digits[b & 15])
    return join(out, "")

proc random_string(state, length):
    let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    let out = []
    for i in range(length):
        push(out, chars[next_bounded(state, 62)])
    return join(out, "")

proc uuid4(state):
    let bytes = random_bytes(state, 16)
    bytes[6] = (bytes[6] & 15) | 64
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
# Linear Congruential Generator (products < 2^48: exact in doubles)
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
    return r % bound

# ============================================================================
# Utilities
# ============================================================================

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

    let fd = ffi_call(libc, "open", "int", ["/dev/urandom", 0])
    if fd < 0:
        ffi_close(libc)
        raise "Failed to open /dev/urandom"

    let buf = mem_alloc(count)
    let nread = ffi_call(libc, "read", "int", [fd, buf, count])
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
