# lib/crypto/hkdf.sage
# Pure SageLang implementation of HKDF-BLAKE2s (RFC 5869 / Noise Protocol)

import crypto.blake2s
import crypto.hmac

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

proc hkdf_extract(salt, ikm):
    let s = salt
    if s == nil:
        s = []
        for i in range(32):
            push(s, 0)
    else:
        s = to_byte_list(s)
        
    let ikm_bytes = to_byte_list(ikm)
    return hmac.hmac(blake2s.blake2s, s, ikm_bytes, 64)

proc hkdf_expand(prk, info, length):
    let prk_bytes = to_byte_list(prk)
    let inf = []
    if info != nil:
        inf = to_byte_list(info)
        
    let okm = []
    let t = []
    let i = 1
    
    while len(okm) < length:
        let data = []
        for j in range(len(t)):
            push(data, t[j])
        for j in range(len(inf)):
            push(data, inf[j])
        push(data, i)
        
        t = hmac.hmac(blake2s.blake2s, prk_bytes, data, 64)
        
        for j in range(len(t)):
            if len(okm) < length:
                push(okm, t[j])
        i = i + 1
        
    return okm
