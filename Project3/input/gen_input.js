// 使用相对路径引用 circomlibjs 源码构建
const circomlibjs = require("..build/main.cjs");  // ✅ 注意路径
const fs = require("fs");

async function main() {
    const poseidon = await circomlibjs.buildPoseidon2();  // ✅ 现在有效
    const F = poseidon.F;

    const inputs = [1n, 2n];
    const hash = poseidon(inputs);
    const hashValue = F.toString(hash);

    const inputJson = {
        in: inputs.map(x => x.toString()),
        hash: hashValue
    };

    fs.writeFileSync("input/input.json", JSON.stringify(inputJson, null, 2));
    console.log("✅ input.json 生成成功");
}

main();

