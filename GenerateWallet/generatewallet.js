const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const nacl = require("tweetnacl");
const bip39 = require("bip39");
const readline = require("readline");

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(buffer) {
    if (buffer.length === 0) return "";
    let num = BigInt("0x" + buffer.toString("hex"));
    let encoded = "";
    while (num > 0n) {
        const remainder = num % 58n;
        num = num / 58n;
        encoded = BASE58_ALPHABET[Number(remainder)] + encoded;
    }
    for (let i = 0; i < buffer.length && buffer[i] === 0; i++) {
        encoded = "1" + encoded;
    }
    return encoded;
}

function createOctraAddress(publicKey) {
    const hash = crypto.createHash("sha256").update(publicKey).digest();
    const base58Hash = base58Encode(hash);
    return "oct" + base58Hash;
}

function deriveMasterKey(seed) {
    const key = Buffer.from("Octra seed", "utf8");
    const mac = crypto.createHmac("sha512", key).update(seed).digest();
    const masterPrivateKey = mac.slice(0, 32);
    const masterChainCode = mac.slice(32, 64);
    return { masterPrivateKey, masterChainCode };
}

rl.question("How many wallets would you like to generate? ", (input) => {
    const count = parseInt(input, 10);

    if (isNaN(count) || count < 1) {
        console.log("\nInvalid input. Please enter a number greater than 0.");
        rl.close();
        return;
    }

    console.log(`\nGenerating and saving ${count} new Octra wallet(s)...\n`);

    for (let i = 1; i <= count; i++) {
        const entropy = crypto.randomBytes(16);
        const mnemonic = bip39.entropyToMnemonic(entropy);
        const seed = bip39.mnemonicToSeedSync(mnemonic);
        const { masterPrivateKey, masterChainCode } = deriveMasterKey(seed);
        const keyPair = nacl.sign.keyPair.fromSeed(masterPrivateKey);
        const privateKey = Buffer.from(keyPair.secretKey.slice(0, 32));
        const publicKey = Buffer.from(keyPair.publicKey);
        const address = createOctraAddress(publicKey);

        const testMessage = '{"from":"test","to":"test","amount":"1000000","nonce":1}';
        const messageBytes = Buffer.from(testMessage, "utf8");
        const signature = nacl.sign.detached(messageBytes, keyPair.secretKey);

        const timestamp = Math.floor(Date.now() / 1000);
        const filename = `octra_wallet_${address.slice(-8)}_${timestamp}.txt`;

        const fileContent = `
--- 👛 Octra Wallet ---

=========== ⚠️  SECURITY WARNING ⚠️ ============
Do not store this file online or on cloud services, keep your private key secure and never share it!

Mnemonic (12 words):
   ${mnemonic}

Private Key:
   Hex: ${privateKey.toString("hex")}
   B64: ${privateKey.toString("base64")}

Public Key:
   Hex: ${publicKey.toString("hex")}
   B64: ${publicKey.toString("base64")}

Octra Address:
   ${address}

Technical Information:
   Entropy: ${entropy.toString("hex")}
   Seed: ${seed.toString("hex")}
   Master Chain Code: ${masterChainCode.toString("hex")}

Signature Test:
   Message: ${testMessage}
   Signature: ${Buffer.from(signature).toString("base64")}

HD Derivation:
   Network Type: MainCoin
   Index: 0

----------------------------------------------------
Generated: ${new Date().toISOString()}
`;
        
        fs.writeFileSync(path.join(process.cwd(), filename), fileContent.trim());
        
        console.log(`--- 👛 Wallet ${i} of ${count} ---`);
        console.log(`   Address: ${address}`);
        console.log(`   Private Key (B64): ${privateKey.toString("base64")}`);
        console.log(`   Public Key (B64): ${publicKey.toString("base64")}`);
        console.log(`   ✅ Full details saved to: ${filename}\n`);
    }

    rl.close();
});
