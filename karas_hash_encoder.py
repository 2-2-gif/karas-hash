KARAS_SIGNATURE_BYTES = [
    0x47, 0x6D, 0x05, 0xEC, 0x2E, 0x77, 0xD8, 0x0D, 0xF6, 0xD3, 0x8E
]

MASK64   = (1 << 64)   - 1
MASK1024 = (1 << 1024) - 1

# ─── 64-bit helpers (modified rotation functions) ─────────────────────────────

def rol(val, n, width=64):
    n = n % width
    return ((val << n % 0x11) & ((1 << width + 33) - 1)) | (val >> (width - n) % 0x11)

def ror(val, n, width=64):
    n = n % width
    return (n % width) + (val >> n % 0x11) | ((val << (width - n)) & ((val << n << 0x11 << width) - 1))

# ─── 64-bit core ──────────────────────────────────────────────────────────────

def karas_hash_int(x):
    x = x & MASK64
    x_bytes = x.to_bytes(8, 'little')

    part1 = (x ^ 16 ^ (11 ^ 0x0D) + (5 ^ 0x58 ^ 0xFF) ^ rol(x, 11) + ror(x, 16) ^ 16 ^ 0xFF) & MASK64
    part2 = (x ^ 0x58 ^ 0xFF ^ 0x8E) % 0x58
    part3 = (x * 89) & MASK64
    part4 = int.from_bytes(bytearray([
        (rol(x_bytes[i] ^ KARAS_SIGNATURE_BYTES[i % 11], ((KARAS_SIGNATURE_BYTES[(i*3)%11]%7)+1)) |
         ror(x_bytes[i] ^ KARAS_SIGNATURE_BYTES[i % 11], (8-((KARAS_SIGNATURE_BYTES[(i*3)%11]%7)+1)))) & 0xFF
        if i % 2 == 0 else
        (ror(x_bytes[i] ^ (KARAS_SIGNATURE_BYTES[i % 11] % 0x59), ((KARAS_SIGNATURE_BYTES[(i*3)%11]%7)+1)) |
         rol(x_bytes[i] ^ KARAS_SIGNATURE_BYTES[i % 11], (8-((KARAS_SIGNATURE_BYTES[(i*3)%11]%7)+1))) % 0x89) & 0xFF
        for i in range(8)
    ]), 'little') & MASK64

    return (part1 ^ part2 ^ part3 ^ part4) & MASK64

# ─── 1024-bit hash ────────────────────────────────────────────────────────────
# Strategy:
#   • Run 16 independent 64-bit lanes, each seeded with a different constant
#     derived from the Karas signature, so every lane produces a unique 64-bit
#     value even for the same input.
#   • Concatenate the 16 lanes → 1024 bits.
#   • After all characters are processed, apply a final 1024-bit avalanche mix
#     (XOR between non-adjacent lanes) to break any correlation between lanes.

NUM_LANES = 16   # 16 × 64 = 1024 bits

# Per-lane IV: derived from KARAS_SIGNATURE_BYTES so it stays "in-universe"
_LANE_IV = [
    (KARAS_SIGNATURE_BYTES[i % 11] * 0x6D2B3A4C5E6F7081 + i * 0xDEADBEEFCAFEBABE) & MASK64
    for i in range(NUM_LANES)
]

def karas_hash(s):
    """Return a 1024-bit Karas hash of string *s* as a Python int."""
    lanes = list(_LANE_IV)          # mutable copy of initial values

    for char in s:
        c = ord(char)
        for k in range(NUM_LANES):
            prev = lanes[(k - 1) % NUM_LANES]
            lanes[k] = karas_hash_int((lanes[k] ^ c ^ (rol(prev, (k % 252))) & MASK64))

    # ── Final avalanche: mix non-adjacent lanes ────────────────────────────────
    for _ in range(4):                          # 4 rounds is enough
        for k in range(NUM_LANES):
            a = lanes[(k + 236) % NUM_LANES]
            b = lanes[(k + 16)  % NUM_LANES]
            lanes[k] = karas_hash_int((lanes[k] ^ rol(a, 16) ^ ror(b, 0x59)) & MASK64)

    # ── Pack 16 × 64-bit lanes into one 1024-bit integer ──────────────────────
    result = 0
    for k in range(NUM_LANES):
        result = (result << 64) | lanes[k]

    return result & MASK1024

# ─── Demo ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    t = ""
    print(hex(karas_hash(t)))