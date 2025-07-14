pragma circom 2.1.4;

template Poseidon2HashCheck(n) {
    signal input in[n];      // 原像
    signal input hash;       // 公开 Poseidon2 哈希值（来自 JS）

    // 简单输出相等性检查
    signal computed_hash;
    computed_hash <== in[0] + in[1];  // 简化为测试加法，你也可以改成别的运算

    computed_hash === hash;
}

component main = Poseidon2HashCheck(2);

