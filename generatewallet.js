const crypto = require("crypto");
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
    return { masterPrivateKey };
}

rl.question("How many wallets would you like to generate? ", (input) => {
    const count = parseInt(input, 10);

    if (isNaN(count) || count < 1) {
        console.log("\nInvalid input. Please enter a number greater than 0.");
        rl.close();
        return;
    }

    console.log(`\nGenerating ${count} new Octra wallet(s)...`);

    for (let i = 1; i <= count; i++) {
        const entropy = crypto.randomBytes(16);
        const mnemonic = bip39.entropyToMnemonic(entropy);
        const seed = bip39.mnemonicToSeedSync(mnemonic);
        const { masterPrivateKey } = deriveMasterKey(seed);
        const keyPair = nacl.sign.keyPair.fromSeed(masterPrivateKey);
        const privateKey = Buffer.from(keyPair.secretKey.slice(0, 32));
        const publicKey = Buffer.from(keyPair.publicKey);
        const address = createOctraAddress(publicKey);

        console.log(`\n\n--- 👛 Wallet ${i} of ${count} ---`);

        console.log("\n=========== ⚠️  SECURITY WARNING ⚠️ ============");
        console.log("STORE YOUR MNEMONIC PHRASE IN A VERY SECURE LOCATION.");
        console.log("NEVER SHARE YOUR MNEMONIC OR PRIVATE KEY.\n");

        console.log("🔑 Mnemonic Phrase (Save this):");
        console.log(`   ${mnemonic}\n`);

        console.log("================== Keys & Address ==================");
        console.log("📬 Your Octra Address:");
        console.log(`   ${address}\n`);

        console.log("🔒 Private Key (Hex):");
        console.log(`   ${privateKey.toString("hex")}\n`);

        console.log("🔒 Private Key (B64):");
        console.log(`   ${privateKey.toString("base64")}\n`);

        console.log("📢 Public Key (Hex):");
        console.log(`   ${publicKey.toString("hex")}\n`);

        console.log("📢 Public Key (B64):");
        console.log(`   ${publicKey.toString("base64")}\n`);

        console.log("----------------------------------------------------");
    }

    rl.close();
});