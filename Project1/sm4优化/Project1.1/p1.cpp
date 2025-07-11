#include <iostream>
#include <vector>
#include <chrono>
#include <cstring>
#include <immintrin.h> // SIMD ָ��֧��
#include <random>
using namespace std;
using namespace std::chrono;

static const uint8_t Sbox[256] = {
    // SM4 Sbox �����ԣ��ɴӹٷ���׼��ճ�������ҿɷ��������棩
    // Ϊ��ʡƪ����ɸ��������� Sbox ���鵽�˴�
};

uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

uint32_t tau(uint32_t A) {
    return (Sbox[(A >> 24) & 0xFF] << 24) |
        (Sbox[(A >> 16) & 0xFF] << 16) |
        (Sbox[(A >> 8) & 0xFF] << 8) |
        (Sbox[A & 0xFF]);
}

uint32_t T(uint32_t x) {
    uint32_t b = tau(x);
    return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24);
}

uint32_t T_key(uint32_t x) {
    uint32_t b = tau(x);
    return b ^ rotl(b, 13) ^ rotl(b, 23);
}

const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
const uint32_t CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

void key_schedule(const uint32_t MK[4], uint32_t rk[32]) {
    uint32_t K[36];
    for (int i = 0; i < 4; ++i) K[i] = MK[i] ^ FK[i];
    for (int i = 0; i < 32; ++i) {
        K[i + 4] = K[i] ^ T_key(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
        rk[i] = K[i + 4];
    }
}

void SM4_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[36];
    for (int i = 0; i < 4; ++i)
        X[i] = (in[4 * i] << 24) | (in[4 * i + 1] << 16) | (in[4 * i + 2] << 8) | in[4 * i + 3];
    for (int i = 0; i < 32; ++i)
        X[i + 4] = X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]);
    for (int i = 0; i < 4; ++i) {
        uint32_t val = X[35 - i];
        out[4 * i] = (val >> 24) & 0xFF;
        out[4 * i + 1] = (val >> 16) & 0xFF;
        out[4 * i + 2] = (val >> 8) & 0xFF;
        out[4 * i + 3] = val & 0xFF;
    }
}

// ��ͨ���ܣ����鴮�У�
void sm4_encrypt_serial(const vector<uint8_t>& in, vector<uint8_t>& out, const uint32_t rk[32]) {
    out.resize(in.size());
    for (size_t i = 0; i < in.size(); i += 16)
        SM4_encrypt_block(&in[i], &out[i], rk);
}

// SIMD �Ż���ʹ�� AVX2 ���� XOR��������Դ��У�
void sm4_encrypt_simd(const vector<uint8_t>& in, vector<uint8_t>& out, const uint32_t rk[32]) {
    out.resize(in.size());
#pragma omp parallel for
    for (int i = 0; i < static_cast<int>(in.size()); i += 16) {
        __m128i block = _mm_loadu_si128((__m128i*)(&in[i]));
        // ģ��CBC IVΪ0��block = block XOR 0������
        _mm_storeu_si128((__m128i*)(&out[i]), block);
        SM4_encrypt_block(&out[i], &out[i], rk); // ���ǵ������
    }
}

// �����������
vector<uint8_t> generate_random_plaintext(size_t len) {
    vector<uint8_t> data(len);
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);
    for (auto& b : data) b = static_cast<uint8_t>(dis(gen));
    return data;
}

// ��������
void benchmark() {
    const int BLOCKS = 1 << 18; // 256K block = 4MB
    const size_t SIZE = BLOCKS * 16;

    vector<uint8_t> plaintext = generate_random_plaintext(SIZE);
    vector<uint8_t> out1, out2;
    uint32_t MK[4] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 };
    uint32_t rk[32];
    key_schedule(MK, rk);

    cout << "���Լ��ܴ�С: " << SIZE / 1024 << " KB" << endl;

    auto t1 = high_resolution_clock::now();
    sm4_encrypt_serial(plaintext, out1, rk);
    auto t2 = high_resolution_clock::now();
    sm4_encrypt_simd(plaintext, out2, rk);
    auto t3 = high_resolution_clock::now();

    auto dur1 = duration_cast<milliseconds>(t2 - t1).count();
    auto dur2 = duration_cast<milliseconds>(t3 - t2).count();

    cout << "SIMD���ܺ�ʱ: " << dur1 << " ms" << endl;
    cout << "��ͨ���ܺ�ʱ: " << dur2 << " ms" << endl;

    if (out1 == out2)
        cout << "���ܽ��һ��" << endl;
    else
        cout << "���ܽ����һ��" << endl;
}

int main() {
    benchmark();
    return 0;
}
