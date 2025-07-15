// ? 优化后的 SM3 实现 with 基础性能对比测试（含优化前函数）
// 见详细注释说明优化方式
#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <chrono>

using namespace std;
using namespace std::chrono;

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define FF(x, y, z, j) ((j) < 16 ? ((x) ^ (y) ^ (z)) : ((x & y) | (x & z) | (y & z)))
#define GG(x, y, z, j) ((j) < 16 ? ((x) ^ (y) ^ (z)) : ((x & y) | ((~x) & z)))
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))

const uint32_t T[64] = {
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

const uint32_t IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

inline uint32_t to_uint32(const uint8_t* p) {
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

inline void to_bytes(uint32_t val, uint8_t* out) {
    out[0] = (val >> 24) & 0xff;
    out[1] = (val >> 16) & 0xff;
    out[2] = (val >> 8) & 0xff;
    out[3] = val & 0xff;
}

vector<uint8_t> padding(const vector<uint8_t>& msg) {
    uint64_t bit_len = msg.size() * 8;
    vector<uint8_t> padded = msg;
    padded.push_back(0x80);
    while ((padded.size() + 8) % 64 != 0) padded.push_back(0);
    for (int i = 7; i >= 0; --i)
        padded.push_back((bit_len >> (8 * i)) & 0xFF);
    return padded;
}

void compress_original(uint32_t V[8], const uint8_t block[64]);
void compress_optimized(uint32_t V[8], const uint8_t block[64]);

vector<uint8_t> sm3(bool use_opt, const vector<uint8_t>& msg) {
    vector<uint8_t> padded = padding(msg);
    uint32_t V[8];
    memcpy(V, IV, sizeof(IV));
    for (size_t i = 0; i < padded.size(); i += 64) {
        if (use_opt) compress_optimized(V, &padded[i]);
        else compress_original(V, &padded[i]);
    }
    vector<uint8_t> hash(32);
    for (int i = 0; i < 8; ++i)
        to_bytes(V[i], &hash[i * 4]);
    return hash;
}

int main() {
    string input = "abc";
    vector<uint8_t> msg(input.begin(), input.end());
    int N = 100000;

    auto run = [&](bool opt) {
        auto start = high_resolution_clock::now();
        for (int i = 0; i < N; ++i) sm3(opt, msg);
        auto end = high_resolution_clock::now();
        return duration<double, micro>(end - start).count() / N;
        };

    double t_orig = run(false);
    double t_opt = run(true);

    cout << fixed << setprecision(3);
    cout << "优化前平均耗时: " << t_orig << " us\n";
    cout << "优化后平均耗时: " << t_opt << " us\n";
    cout << "提升比例: " << (t_orig - t_opt) / t_orig * 100.0 << " %\n";
    return 0;
}

// 原始压缩函数定义
void compress_original(uint32_t V[8], const uint8_t block[64]) {
    uint32_t W[68], W1[64];
    for (int i = 0; i < 16; ++i)
        W[i] = to_uint32(block + 4 * i);
    for (int j = 16; j < 68; ++j)
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
    for (int j = 0; j < 64; ++j)
        W1[j] = W[j] ^ W[j + 4];
    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];
    for (int j = 0; j < 64; ++j) {
        uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)) & 0xffffffff, 7);
        uint32_t SS2 = SS1 ^ ROTL(A, 12);
        uint32_t TT1 = (FF(A, B, C, j) + D + SS2 + W1[j]) & 0xffffffff;
        uint32_t TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xffffffff;
        D = C; C = ROTL(B, 9); B = A; A = TT1;
        H = G; G = ROTL(F, 19); F = E; E = P0(TT2);
    }
    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

// 优化压缩函数定义
void compress_optimized(uint32_t V[8], const uint8_t block[64]) {
    uint32_t W[68], W1[64];
#pragma GCC unroll 4
    for (int i = 0; i < 16; ++i)
        W[i] = to_uint32(block + i * 4);
#pragma GCC unroll 8
    for (int j = 16; j < 68; ++j)
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
#pragma GCC unroll 8
    for (int j = 0; j < 64; ++j)
        W1[j] = W[j] ^ W[j + 4];
    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];
#pragma GCC unroll 8
    for (int j = 0; j < 64; ++j) {
        uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)) & 0xffffffff, 7);
        uint32_t SS2 = SS1 ^ ROTL(A, 12);
        uint32_t TT1 = (FF(A, B, C, j) + D + SS2 + W1[j]) & 0xffffffff;
        uint32_t TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xffffffff;
        D = C; C = ROTL(B, 9); B = A; A = TT1;
        H = G; G = ROTL(F, 19); F = E; E = P0(TT2);
    }
    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}
