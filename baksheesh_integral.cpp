/**
 * BAKSHEESH Cipher – 3-Round Integral Distinguisher Verification
 *
 * Implements the integral cryptanalysis from ic_on_bak_2.pdf:
 *   - Build a set of 16 chosen plaintexts where nibble w_0 is ACTIVE
 *     (takes all 16 values 0x0..0xF) and every other nibble is CONSTANT.
 *   - Encrypt each plaintext through 3 rounds of BAKSHEESH.
 *   - Verify that the XOR sum of every output nibble across the 16
 *     ciphertexts is 0 (i.e., all nibbles are BALANCED).
 *
 * Cipher specification (baksheesh_cipher.pdf / 2023-750.pdf):
 *   State     : 128 bits = 32 nibbles (w_0 … w_31), b_0 is LSB.
 *   SBox      : S = 306DB58ECF924A71
 *   PermBits  : P128 from GIFT-128
 *   AddConst  : 6-bit RC at tap positions {8,13,19,35,67,106}
 *   AddRndKey : Full 128-bit XOR; k^{j+1} = k^j rotated right 1 bit
 *   Encryption: state ^= k^0 , then for r=1..N: SubCells, PermBits,
 *               AddConstants(r), state ^= k^r
 *
 * Byte storage convention:
 *   state[0]  = most-significant byte  (bits 127..120)
 *   state[15] = least-significant byte (bits   7..  0)
 *   Nibble w_i occupies bits 4i+3..4i:
 *     byte index = 15 - i/2  ,  lower nibble if i even, upper if i odd.
 */

#include <iostream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <array>
#include <vector>
#include <random>
#include <string>
#include <sstream>

// ──────────────────────────────────────────────────────────────────────────────
//  Cipher constants
// ──────────────────────────────────────────────────────────────────────────────

// S = 306DB58ECF924A71
static const uint8_t SBOX[16] = {
    3, 0, 6, 13, 11, 5, 8, 14, 12, 15, 9, 2, 4, 10, 7, 1
};

// P128 bit permutation (bit i of input → position P128[i] of output)
static const uint8_t P128[128] = {
      0,  33,  66,  99,  96,   1,  34,  67,  64,  97,   2,  35,  32,  65,  98,   3,
      4,  37,  70, 103, 100,   5,  38,  71,  68, 101,   6,  39,  36,  69, 102,   7,
      8,  41,  74, 107, 104,   9,  42,  75,  72, 105,  10,  43,  40,  73, 106,  11,
     12,  45,  78, 111, 108,  13,  46,  79,  76, 109,  14,  47,  44,  77, 110,  15,
     16,  49,  82, 115, 112,  17,  50,  83,  80, 113,  18,  51,  48,  81, 114,  19,
     20,  53,  86, 119, 116,  21,  54,  87,  84, 117,  22,  55,  52,  85, 118,  23,
     24,  57,  90, 123, 120,  25,  58,  91,  88, 121,  26,  59,  56,  89, 122,  27,
     28,  61,  94, 127, 124,  29,  62,  95,  92, 125,  30,  63,  60,  93, 126,  31
};

// Tap positions for round-constant XOR
static const uint8_t TAP[6] = { 8, 13, 19, 35, 67, 106 };

// Round constants for rounds 1..35 (index 0 → round 1)
static const uint8_t RC[35] = {
     2, 33, 16,  9, 36, 19, 40, 53, 26, 13, 38, 51, 56, 61, 62, 31,
    14,  7, 34, 49, 24, 45, 54, 59, 28, 47, 22, 43, 20, 11,  4,  3,
    32, 17,  8
};

// ──────────────────────────────────────────────────────────────────────────────
//  State type and helper accessors
// ──────────────────────────────────────────────────────────────────────────────

using State = std::array<uint8_t, 16>;   // 128-bit block

// state[0] = MSB byte; bit j (0=LSB) is in byte (15 - j/8), position j%8.
inline uint8_t get_bit(const State& s, int j) {
    return (s[15 - j / 8] >> (j % 8)) & 1u;
}
inline void set_bit(State& s, int j, uint8_t v) {
    uint8_t& byte = s[15 - j / 8];
    uint8_t  mask = static_cast<uint8_t>(1u << (j % 8));
    byte = v ? (byte | mask) : (byte & ~mask);
}

// Nibble w_i = bits [4i+3 .. 4i]:  byte 15-i/2, lower if i even, upper if i odd.
inline uint8_t get_nibble(const State& s, int i) {
    return (i % 2 == 0) ? (s[15 - i / 2] & 0xFu)
                        : (s[15 - i / 2] >> 4) & 0xFu;
}
inline void set_nibble(State& s, int i, uint8_t v) {
    uint8_t& byte = s[15 - i / 2];
    if (i % 2 == 0) byte = (byte & 0xF0u) | (v & 0x0Fu);
    else             byte = (byte & 0x0Fu) | ((v & 0x0Fu) << 4);
}

// ──────────────────────────────────────────────────────────────────────────────
//  Round operations
// ──────────────────────────────────────────────────────────────────────────────

// SubCells: apply SBox to every nibble
static void subcells(State& s) {
    for (int i = 0; i < 32; ++i)
        set_nibble(s, i, SBOX[get_nibble(s, i)]);
}

// PermBits: route bit i to position P128[i]
static void permbits(State& s) {
    State ns{};
    for (int i = 0; i < 128; ++i)
        set_bit(ns, P128[i], get_bit(s, i));
    s = ns;
}

// AddConstants: for round r (1-indexed), XOR the 6-bit RC at the tap positions
static void addconstants(State& s, int r) {
    uint8_t rc = RC[r - 1];
    for (int i = 0; i < 6; ++i)
        if ((rc >> i) & 1u)
            set_bit(s, TAP[i], get_bit(s, TAP[i]) ^ 1u);
}

// AddRoundKey: state ^= key
static void addroundkey(State& s, const State& key) {
    for (int i = 0; i < 16; ++i) s[i] ^= key[i];
}

// Key schedule: k^{j+1} = k^j rotated right by 1 bit (128-bit rotation).
// With MSB-first storage: LSB of state = bit 0 = LSB of state[15].
static State next_key(const State& key) {
    State nk;
    uint8_t carry_in = key[15] & 1u;          // bit 0 wraps to bit 127
    for (int k = 1; k < 16; ++k)              // from k=1 (byte 126..120) down to byte 0
        nk[k] = static_cast<uint8_t>((key[k] >> 1) | ((key[k - 1] & 1u) << 7));
    nk[0] = static_cast<uint8_t>((key[0] >> 1) | (carry_in << 7));
    return nk;
}

// ──────────────────────────────────────────────────────────────────────────────
//  BAKSHEESH encryption (variable number of rounds)
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Encrypt `plaintext` using `master_key` for `num_rounds` rounds.
 * Structure:
 *   state = plaintext XOR k^0
 *   for r = 1 .. num_rounds:
 *       SubCells → PermBits → AddConstants(r) → XOR k^r
 */
static State encrypt(const State& plaintext,
                     const State& master_key,
                     int num_rounds)
{
    State state = plaintext;
    State key   = master_key;          // k^0

    addroundkey(state, key);           // pre-whitening with k^0

    for (int r = 1; r <= num_rounds; ++r) {
        key = next_key(key);           // k^r
        subcells(state);
        permbits(state);
        addconstants(state, r);
        addroundkey(state, key);
    }
    return state;
}

// ──────────────────────────────────────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────────────────────────────────────

static std::string hex(const State& s) {
    std::ostringstream ss;
    for (uint8_t b : s) ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return ss.str();
}

static State from_hex(const std::string& h) {
    State s{};
    for (int i = 0; i < 16; ++i)
        s[i] = static_cast<uint8_t>(std::stoul(h.substr(2 * i, 2), nullptr, 16));
    return s;
}

// ──────────────────────────────────────────────────────────────────────────────
//  Test-vector check (full 35 rounds)
// ──────────────────────────────────────────────────────────────────────────────

static bool check_test_vectors() {
    struct TV { const char* key; const char* pt; const char* ct; };
    static const TV tvs[] = {
        { "00000000000000000000000000000000",
          "00000000000000000000000000000000",
          "c002be5e64c78a72ab9a3439518352aa" },
        { "00000000000000000000000000000000",
          "00000000000000000000000000000007",
          "6f7d7746eaf0d97a154079f6bd846438" },
        { "00000000000000000000000000000000",
          "70000000000000000000000000000000",
          "1ba3363734c09a29f67c23bbb2cccc05" },
        { "ffffffffffffffffffffffffffffffff",
          "11111111111111111111111111111111",
          "806f0cf45b94f0370206975fe78ac10f" },
        { "5920effb52bc61e33a98425321e76915",
          "e6517531abf63f3d7805e126943a081c",
          "fc7e61fee3d587308ca7bc594ebf3244" },
    };

    bool all_pass = true;
    std::cout << "══════════════════════════════════════════════\n";
    std::cout << "  Test Vector Verification (35 rounds)\n";
    std::cout << "══════════════════════════════════════════════\n";
    for (auto& tv : tvs) {
        State key = from_hex(tv.key);
        State pt  = from_hex(tv.pt);
        State ct  = encrypt(pt, key, 35);
        bool  ok  = (hex(ct) == std::string(tv.ct));
        all_pass &= ok;
        std::cout << "  Key : " << tv.key << "\n"
                  << "  PT  : " << tv.pt  << "\n"
                  << "  CT  : " << hex(ct) << "\n"
                  << "  Exp : " << tv.ct   << "\n"
                  << "  --> " << (ok ? "PASS ✓" : "FAIL ✗") << "\n\n";
    }
    return all_pass;
}

// ──────────────────────────────────────────────────────────────────────────────
//  3-round integral distinguisher
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Run the integral distinguisher for one (key, active_nibble, constant_nibbles)
 * combination.
 *
 * Returns true iff every one of the 32 output nibbles XORs to 0 across the
 * 16 ciphertexts.
 */
static bool run_distinguisher(const State& master_key,
                              int active_nibble,
                              const State& base_plaintext)
{
    // XOR accumulators for each of the 32 output nibbles
    uint8_t xor_acc[32] = {};

    for (int v = 0; v < 16; ++v) {
        State pt = base_plaintext;
        set_nibble(pt, active_nibble, static_cast<uint8_t>(v));

        State ct = encrypt(pt, master_key, 3);

        for (int n = 0; n < 32; ++n)
            xor_acc[n] ^= get_nibble(ct, n);
    }

    for (int n = 0; n < 32; ++n)
        if (xor_acc[n] != 0) return false;
    return true;
}

// ──────────────────────────────────────────────────────────────────────────────
//  Main
// ──────────────────────────────────────────────────────────────────────────────

int main() {
    // 1. Test-vector verification (sanity check)
    bool tv_ok = check_test_vectors();
    if (!tv_ok) {
        std::cerr << "ERROR: one or more test vectors failed – "
                     "implementation may be incorrect.\n";
        return 1;
    }

    // 2. Detailed single run: nibble 0 active, all other nibbles = 0, key = 0
    std::cout << "══════════════════════════════════════════════\n";
    std::cout << "  3-Round Integral Distinguisher (Detailed)\n";
    std::cout << "  Active nibble : w_0   |  Key : all-zero\n";
    std::cout << "══════════════════════════════════════════════\n";

    State zero_key{}, base_pt{};       // both all-zeros

    uint8_t xor_acc[32] = {};
    std::vector<State> cts(16);

    for (int v = 0; v < 16; ++v) {
        State pt = base_pt;
        set_nibble(pt, 0, static_cast<uint8_t>(v));
        cts[v] = encrypt(pt, zero_key, 3);
        for (int n = 0; n < 32; ++n)
            xor_acc[n] ^= get_nibble(cts[v], n);
    }

    std::cout << "\n  Ciphertexts after 3 rounds:\n";
    for (int v = 0; v < 16; ++v)
        std::cout << "    P[w0=" << std::hex << v << "] -> " << hex(cts[v]) << "\n";

    std::cout << std::dec << "\n  XOR sum per output nibble:\n";
    bool all_balanced = true;
    for (int n = 0; n < 32; ++n) {
        bool bal = (xor_acc[n] == 0);
        all_balanced &= bal;
        std::cout << "    w_" << std::setw(2) << n
                  << " : 0x" << std::hex << (int)xor_acc[n]
                  << (bal ? "  [balanced]" : "  [NOT balanced!]") << "\n";
    }
    std::cout << std::dec;
    std::cout << "\n  Distinguisher result: "
              << (all_balanced ? "ALL NIBBLES BALANCED ✓" : "FAILED ✗") << "\n\n";

    // 3. Exhaustive sweep: all 32 active-nibble positions × 5 random keys
    std::cout << "══════════════════════════════════════════════\n";
    std::cout << "  Sweep: all 32 active-nibble positions,\n";
    std::cout << "         5 random keys each\n";
    std::cout << "══════════════════════════════════════════════\n";

    std::mt19937 rng(0xBADC0FFE);
    auto rand_state = [&]() {
        State s;
        for (auto& b : s) b = static_cast<uint8_t>(rng());
        return s;
    };

    int total = 0, passed = 0;
    for (int trial = 0; trial < 5; ++trial) {
        State key  = rand_state();
        State base = rand_state();   // random constant for all non-active nibbles
        for (int an = 0; an < 32; ++an) {
            ++total;
            if (run_distinguisher(key, an, base)) ++passed;
        }
    }

    std::cout << "  Passed " << passed << " / " << total << " trials\n";
    if (passed == total)
        std::cout << "  Integral distinguisher holds for ALL tested cases ✓\n";
    else
        std::cout << "  WARNING: " << (total - passed) << " case(s) FAILED ✗\n";

    return (tv_ok && passed == total) ? 0 : 1;
}