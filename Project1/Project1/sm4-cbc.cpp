#include <iostream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <iomanip>
#include <cassert>

using namespace std;

// ---------- S-Box ----------
static const uint8_t Sbox[256] = {
    // ...（与前述相同，略，为节省篇幅）
    // 请将前面提供的 Sbox 内容复制粘贴到此处
};

// ---------- 常量 ----------
const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
const uint32_t CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

// ---------- 基本函数 ----------
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

// ---------- 密钥扩展 ----------
void key_schedule(const uint32_t MK[4], uint32_t rk[32]) {
    uint32_t K[36];
    for (int i = 0; i < 4; ++i)
        K[i] = MK[i] ^ FK[i];
    for (int i = 0; i < 32; ++i) {
        K[i + 4] = K[i] ^ T_key(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
        rk[i] = K[i + 4];
    }
}

// ---------- SM4 单块加解密 ----------
void SM4_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[36];
    for (int i = 0; i < 4; i++) {
        X[i] = (in[4 * i + 0] << 24) | (in[4 * i + 1] << 16) |
            (in[4 * i + 2] << 8) | in[4 * i + 3];
    }
    for (int i = 0; i < 32; ++i)
        X[i + 4] = X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]);
    for (int i = 0; i < 4; i++) {
        uint32_t val = X[35 - i];
        out[4 * i + 0] = (val >> 24) & 0xFF;
        out[4 * i + 1] = (val >> 16) & 0xFF;
        out[4 * i + 2] = (val >> 8) & 0xFF;
        out[4 * i + 3] = val & 0xFF;
    }
}

void SM4_decrypt_block(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[36];
    for (int i = 0; i < 4; i++) {
        X[i] = (in[4 * i + 0] << 24) | (in[4 * i + 1] << 16) |
            (in[4 * i + 2] << 8) | in[4 * i + 3];
    }
    for (int i = 0; i < 32; ++i)
        X[i + 4] = X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[31 - i]);
    for (int i = 0; i < 4; i++) {
        uint32_t val = X[35 - i];
        out[4 * i + 0] = (val >> 24) & 0xFF;
        out[4 * i + 1] = (val >> 16) & 0xFF;
        out[4 * i + 2] = (val >> 8) & 0xFF;
        out[4 * i + 3] = val & 0xFF;
    }
}

// ---------- 填充 / 去填充 ----------
void pkcs7_pad(vector<uint8_t>& data) {
    size_t pad_len = 16 - (data.size() % 16);
    data.insert(data.end(), pad_len, static_cast<uint8_t>(pad_len));
}

void pkcs7_unpad(vector<uint8_t>& data) {
    if (data.empty()) return;
    uint8_t pad = data.back();
    if (pad > 16) return;
    data.resize(data.size() - pad);
}

// ---------- CBC 模式加解密 ----------
void SM4_CBC_encrypt(const vector<uint8_t>& plaintext, vector<uint8_t>& ciphertext,
    const uint32_t rk[32], const uint8_t iv[16]) {
    vector<uint8_t> padded = plaintext;
    pkcs7_pad(padded);
    ciphertext.resize(padded.size());

    uint8_t block[16], xor_block[16];
    memcpy(xor_block, iv, 16);

    for (size_t i = 0; i < padded.size(); i += 16) {
        for (int j = 0; j < 16; j++)
            block[j] = padded[i + j] ^ xor_block[j];
        SM4_encrypt_block(block, &ciphertext[i], rk);
        memcpy(xor_block, &ciphertext[i], 16);
    }
}

void SM4_CBC_decrypt(const vector<uint8_t>& ciphertext, vector<uint8_t>& plaintext,
    const uint32_t rk[32], const uint8_t iv[16]) {
    plaintext.resize(ciphertext.size());
    uint8_t block[16], last_ct[16];
    memcpy(last_ct, iv, 16);

    for (size_t i = 0; i < ciphertext.size(); i += 16) {
        SM4_decrypt_block(&ciphertext[i], block, rk);
        for (int j = 0; j < 16; j++)
            plaintext[i + j] = block[j] ^ last_ct[j];
        memcpy(last_ct, &ciphertext[i], 16);
    }
    pkcs7_unpad(plaintext);
}

// ---------- 打印工具 ----------
void print_hex(const string& label, const vector<uint8_t>& data) {
    cout << label;
    for (uint8_t b : data)
        cout << hex << setw(2) << setfill('0') << (int)b << " ";
    cout << dec << endl;
}

// ---------- 主函数 ----------
int main() {
    uint8_t iv[16] = { 0 };
    uint32_t MK[4] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 };
    uint32_t rk[32];
    key_schedule(MK, rk);

    string msg = "This is a CBC mode SM4 encryption test!";
    vector<uint8_t> plaintext(msg.begin(), msg.end());
    vector<uint8_t> ciphertext, decrypted;

    SM4_CBC_encrypt(plaintext, ciphertext, rk, iv);
    SM4_CBC_decrypt(ciphertext, decrypted, rk, iv);

    print_hex("Plaintext:  ", plaintext);
    print_hex("Ciphertext: ", ciphertext);
    print_hex("Decrypted:  ", decrypted);

    if (plaintext == decrypted)
        cout << "CBC 解密成功！" << endl;
    else
        cout << "CBC 解密失败！" << endl;

    return 0;
}
