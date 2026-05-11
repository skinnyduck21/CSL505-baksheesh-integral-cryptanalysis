# BAKSHEESH – 3-Round Integral Distinguisher

A self-contained C++17 implementation that **constructs and verifies the 3-round integral distinguisher** for the BAKSHEESH lightweight block cipher, and validates the full 35-round cipher against the official test vectors published in the design paper.

---

## Background

### What is BAKSHEESH?

BAKSHEESH is a 128-bit lightweight block cipher proposed as a successor to GIFT-128.  
Its key innovations are:

| Property | GIFT-128 | BAKSHEESH |
|---|---|---|
| Rounds | 40 | **35** (12.5% fewer) |
| SBox | 1A4C6F392DB7508E | **306DB58ECF924A71** |
| Linear Structure (LS) in SBox | None | **1 non-trivial LS (at input 8)** |
| Key XOR per round | Half (64-bit) | **Full (128-bit)** |
| Optimised AND count | 10 (naïve) | **3 (optimised)** |
| Linear Branch Number | 2 | **3 (theoretical maximum)** |

The cipher's round function is:  
`SubCells → PermBits → AddConstants → AddRoundKey`

with a full 128-bit pre-whitening key XOR before round 1, and a key schedule that advances by a 1-bit right rotation each round (`k^{r+1} = k^r ≫ 1`).

---

## Integral Cryptanalysis – Theory

### What is an Integral Distinguisher?

An **integral (or square) distinguisher** exploits how a structured set of plaintexts propagates through a cipher.  
Each nibble position in the state is labelled:

| Label | Meaning |
|---|---|
| **A** (All/Active) | Takes all 16 possible values exactly once across the multiset |
| **C** (Constant) | Holds the same value across every text in the multiset |
| **A\*** (Partially Active) | Receives exactly one active bit; takes only 2 values |
| **B** (Balanced) | XOR of the nibble's value across all texts equals **0** |

### The 3-Round Argument

Start with a multiset of **16 chosen plaintexts** where:

- **Nibble w₀** is *Active* — it takes every value in `{0x0, …, 0xF}` exactly once.
- **All other 31 nibbles** are *Constant* — fixed to the same arbitrary value across all 16 texts.

Trace what happens at each layer:

#### Pre-whitening (XOR with k⁰)
XOR with a constant shifts every nibble by the same offset.  
`A ⊕ const = A` and `C ⊕ const = C` — the structure is preserved.

#### Round 1

| Step | Effect | State after |
|---|---|---|
| **SubCells** | SBox is a bijection → maps 16 distinct inputs to 16 distinct outputs | A→A, C→C |
| **PermBits** | The 4 bits of w₀ scatter to nibbles w₀, w₈, w₁₆, w₂₄ (one bit each) | 4 nibbles become A\*; rest stay C |
| **AddConstants / AddRoundKey** | XOR with constants preserves balance | A\* stays A\* |

After round 1: **4 partially-active nibbles**, 28 constant nibbles.

#### Round 2

| Step | Effect | State after |
|---|---|---|
| **SubCells** | Each of the 4 A\* nibbles only takes 2 distinct values (occurring 8 times each). S-Box output also takes 2 values 8 times each. | 4 A\*, 28 C |
| **PermBits** | The active bits scatter to 16 different nibbles. | 16 A\*, 16 C |
| **AddConstants / AddRoundKey** | XOR with constants preserves the 2-value property. | 16 A\*, 16 C |

After round 2: **16 partially-active nibbles (A\*)**, 16 constant nibbles.

#### Round 3

| Step | Effect | State after |
|---|---|---|
| **SubCells** | Each of the 16 A\* nibbles takes 2 values (8 times each). The S-Box output also takes 2 values (8 times each). Since 8 is even, their XOR sum is exactly 0. | 16 B, 16 C |
| **PermBits** | The 16 balanced nibbles scatter their bits, covering all 32 output positions. | all 32 nibbles B |
| **AddConstants / AddRoundKey** | XOR shifts cancel out in the even XOR sum. | all 32 nibbles B |

After round 3: **32 balanced nibbles**, 0 constant nibbles.

> For a random permutation this would hold with probability 16⁻³² ≈ 2⁻¹²⁸ — essentially never.  
> The fact that BAKSHEESH exhibits it deterministically is the distinguisher.

---

## Code Structure

```
baksheesh_integral.cpp
│
├── Cipher constants
│   ├── SBOX[16]      — S = 306DB58ECF924A71
│   ├── P128[128]     — GIFT-128 bit permutation
│   ├── TAP[6]        — Round-constant tap positions {8,13,19,35,67,106}
│   └── RC[35]        — Round constants for rounds 1..35
│
├── State accessors
│   ├── get_bit / set_bit     — single-bit access
│   └── get_nibble / set_nibble — nibble (4-bit word) access
│
├── Round operations
│   ├── subcells()      — apply SBox to all 32 nibbles
│   ├── permbits()      — apply P128 bit permutation
│   ├── addconstants()  — XOR 6-bit round constant at tap positions
│   └── addroundkey()   — XOR full 128-bit round key
│
├── Key schedule
│   └── next_key()      — 1-bit right rotation of 128-bit key
│
├── encrypt()           — full variable-round BAKSHEESH encryption
│
├── check_test_vectors() — verify 5 official 35-round test vectors
├── run_distinguisher()  — single (key, active_nibble) trial
└── main()
    ├── Stage 1: test-vector check
    ├── Stage 2: detailed single run with output
    └── Stage 3: sweep over all 32 nibble positions × 5 random keys
```

### Bit/Byte Convention

The 128-bit state is stored MSB-first in a `uint8_t[16]` array:

```
state[0]  = bits 127..120
state[15] = bits   7..  0
```

Nibble `wᵢ` occupies bits `[4i+3 .. 4i]`:

```
byte index = 15 - i/2
lower nibble (bits 3..0) when i is even
upper nibble (bits 7..4) when i is odd
```

---

## Building

Requires a C++17-capable compiler. No external dependencies.

```bash
# GCC
g++ -std=c++17 -O2 -Wall -o baksheesh_verify baksheesh_integral.cpp

# Clang (macOS / Linux)
clang++ -std=c++17 -O2 -Wall -o baksheesh_verify baksheesh_integral.cpp

# MSVC (Windows)
cl /std:c++17 /O2 baksheesh_integral.cpp
```

---

## Running

```bash
./baksheesh_verify
```

Expected output (abbreviated):

```
══════════════════════════════════════════════
  Test Vector Verification (35 rounds)
══════════════════════════════════════════════
  Key : 00000000000000000000000000000000
  PT  : 00000000000000000000000000000000
  CT  : c002be5e64c78a72ab9a3439518352aa
  Exp : c002be5e64c78a72ab9a3439518352aa
  --> PASS ✓
  ...
  --> PASS ✓ (5/5 vectors)

══════════════════════════════════════════════
  3-Round Integral Distinguisher (Detailed)
  Active nibble : w_0   |  Key : all-zero
══════════════════════════════════════════════
  ...
  XOR sum per output nibble:
    w_ 0 : 0x0  [balanced]
    ...
    w_1f : 0x0  [balanced]

  Distinguisher result: ALL NIBBLES BALANCED ✓

══════════════════════════════════════════════
  Sweep: all 32 active-nibble positions,
         5 random keys each
══════════════════════════════════════════════
  Passed 160 / 160 trials
  Integral distinguisher holds for ALL tested cases ✓
```

---

## Test Vector Verification

Five test vectors from the official BAKSHEESH specification are checked at startup over the full 35-round cipher. These serve as a correctness guard: if *any* component of the implementation (SBox, PermBits, AddConstants, key schedule, or key XOR placement) is wrong, the 35-round output will be incorrect and the program will abort before running the distinguisher.

| # | Key | Plaintext | Expected Ciphertext |
|---|---|---|---|
| 1 | `000…0` | `000…0` | `c002be5e64c78a72ab9a3439518352aa` |
| 2 | `000…0` | `000…7` | `6f7d7746eaf0d97a154079f6bd846438` |
| 3 | `000…0` | `700…0` | `1ba3363734c09a29f67c23bbb2cccc05` |
| 4 | `fff…f` | `111…1` | `806f0cf45b94f0370206975fe78ac10f` |
| 5 | `5920effb…` | `e6517531…` | `fc7e61fee3d587308ca7bc594ebf3244` |

All five pass, confirming the implementation exactly matches the paper's specification.

---

## Why the Distinguisher Exists (and Why It Is Not a Break)

The 3-round integral property is an **inherent structural consequence** of BAKSHEESH's design — the same property exists in GIFT-128 (which achieves it in fewer rounds; its longest integral distinguisher covers 11 rounds). BAKSHEESH's 13-round integral distinguisher (found via MILP/division-property tools in the paper) is *longer* than GIFT-128's, yet both ciphers use far more rounds than the distinguisher reaches.

The design paper reports that the 35-round BAKSHEESH provides full 2¹²⁸ security against classical attacks. The 3-round distinguisher shown here is **not a threat to the full cipher** — it is a teaching example that illustrates how integral properties propagate and why they eventually vanish as diffusion accumulates.

---

## References

- Baksi et al. — *BAKSHEESH: Similar Yet Different From GIFT* (2023)  
  [IACR ePrint 2023/750](https://eprint.iacr.org/2023/750)
- Daemen, Knudsen, Rijmen — *The Block Cipher Square* (FSE 1997) — original integral attack
- Knudsen, Wagner — *Integral Cryptanalysis* (FSE 2002)
- Todo — *Structural Evaluation by Generalized Integral Property* (EUROCRYPT 2015) — division property
- Xiang et al. — *Applying MILP Method to Searching Integral Distinguishers* (ASIACRYPT 2016)