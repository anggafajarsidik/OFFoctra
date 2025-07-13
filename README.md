# 🚀 Octra Tools Repository

Welcome to the Octra Tools Repository — a curated collection of powerful command-line tools designed for seamless and secure interaction with the Octra network.

This script is a simplified modification of the original, offering a cleaner interface, enhanced ease of use for daily operations.
---

## 👛 Octra Wallet Generator

![Node.js](https://img.shields.io/badge/Node.js-18.x+-green.svg)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

A simple, interactive, command-line tool to securely generate wallets for the Octra network. [cite_start]All keys are generated offline, and full wallet details are automatically saved to a local `.txt` file for your records[cite: 2].

### ✨ Features (Wallet Generator)
* **Interactive Prompt:** No need for command-line arguments. [cite_start]The script asks you how many wallets you want to create[cite: 3, 4].
* [cite_start]**Multiple Wallet Generation:** Create one or hundreds of wallets in a single run[cite: 5].
* **Secure & Offline:** All cryptographic operations happen locally on your machine. [cite_start]The script makes no internet connections, ensuring your keys are never exposed[cite: 6, 7].
* [cite_start]**Automatic File Saving:** Each generated wallet's full details are saved to a unique, timestamped `.txt` file for maximum security and easy management[cite: 8].
* [cite_start]**Clean Console Output:** The terminal displays only the most essential information (Address, Public/Private Keys), while the comprehensive data is stored securely in the generated files[cite: 9].

### 🛠️ Installation (Wallet Generator)

#### Prerequisites
[cite_start]You must have **Node.js** (version 18.x or higher) installed on your system[cite: 10].

#### Steps
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/anggafajarsidik/OFFoctra
    ```
2.  **Navigate to the project directory:**
    ```bash
    cd OFFoctra/GenerateWallet
    ```
3.  **Install dependencies:**
    ```bash
    npm install
    ```
    [cite_start]This will install `tweetnacl` and `bip39`, which are required for key generation[cite: 11].

### 💻 How to Use (Wallet Generator)
1.  **Run the script from your terminal:**
    ```bash
    node generatewallet.js
    ```
2.  **The script will ask you for input:**
    ```
    How many wallets would you like to generate?
    ```
3.  **Type the desired number and press `Enter`**. The script will then generate and save the wallets.

---

## 📝 Output Examples

### Console Output

After running the script and entering `2`, your terminal will display a clean summary for each wallet:

```
Generating and saving 2 new Octra wallet(s)...

--- 👛 Wallet 1 of 2 ---
   Address: Octra_Address
   Private Key (B64): YOUR_PRIVATE_KEY_IN_BASE64
   Public Key (B64): YOUR_PUBLIC_KEY_IN_BASE64
   ✅ Full details saved to: octra_wallet_dPofwFQcu_1672531200.txt

--- 👛 Wallet 2 of 2 ---
   Address: Octra_Address
   Private Key (B64): ANOTHER_PRIVATE_KEY_IN_BASE64
   Public Key (B64): ANOTHER_PUBLIC_KEY_IN_BASE64
   ✅ Full details saved to: octra_wallet_yZBauZWZN_1672531201.txt
```

### File Output (`octra_wallet_dPofwFQcu_1672531200.txt`)

The full, detailed information for each wallet is saved inside its corresponding `.txt` file.

```
--- 👛 Octra Wallet ---

=========== ⚠️  SECURITY WARNING ⚠️ ============
Do not store this file online or on cloud services, keep your private key secure and never share it!

Mnemonic (12 words):
   word word word word word word word word word word word word

Private Key:
   Hex: your_private_key_in_hexadecimal_format
   B64: YOUR_PRIVATE_KEY_IN_BASE64

Public Key:
   Hex: your_public_key_in_hexadecimal_format
   B64: YOUR_PUBLIC_KEY_IN_BASE64

Octra Address:
   Your_Octra_Address

Technical Information:
   Entropy: entropy_hex_data
   Seed: seed_hex_data
   Master Chain Code: master_chain_code_hex_data

Signature Test:
   Message: {"from":"test","to":"test","amount":"1000000","nonce":1}
   Signature: signature_in_base64

HD Derivation:
   Network Type: MainCoin
   Index: 0

----------------------------------------------------
Generated: 2025-01-01T00:00:00.000Z
```

---


## 📊 Octra Wallet CLI Management Tool

![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![CLI](https://img.shields.io/badge/Type-CLI-orange.svg)

This is a powerful, interactive command-line interface (CLI) tool designed for comprehensive management and interaction with your Octra wallets and the Octra network. It allows you to perform various transactions, manage encrypted balances, and automate operations directly from your terminal.

### ✨ Features (CLI Management Tool)
* **Multi-Wallet Support:** Load and manage multiple Octra wallets from a single `wallet.json` file.
* **Flexible Wallet Selection:** Choose to operate with a single selected wallet or perform actions across all loaded wallets concurrently.
* **Proxy Integration:** Supports loading and utilizing proxy URLs from `proxy.txt` for network requests, enhancing privacy and connectivity.
* **Diverse Transaction Types:**
    * **Standard Transfers:** Send Octra tokens to any public address with configurable amounts, messages, multiple repetitions, and **configurable retry attempts for failed transactions**.
    * **Multi-Send from File:** Automate sending transactions to a list of recipients specified in `recipentaddress.txt`. Supports **randomized recipient order**, **multiple runs**, and **configurable retry attempts for failed transactions**.
    * **Encrypted Balance Management:** Securely move funds between your public and encrypted (private) balances, with **configurable retry attempts for failed operations**.
    * **Private Transfers:** Send tokens directly from your encrypted balance to another Octra address. Supports **randomized recipient order**, **multiple runs**, and **configurable retry attempts for failed transfers**.
    * **Claim Private Transfers:** Easily claim pending private transfers addressed to your wallet(s), with **configurable retry attempts for failed claims**.
* **Automated "Daily Multi Send" Mode:** Configure the tool to automatically perform multi-send operations at a predefined daily interval. **This mode can be set up for a single selected wallet or across all loaded wallets.** **Includes configurable retry attempts for failed transactions within daily runs.** To stop the daily mode, **press `Ctrl+C`**.
* **Real-time Updates:** Displays current balances, nonces, and recent transaction history. Updates automatically on refresh command.
* **Secure Operations:** Utilizes robust cryptographic libraries for secure transaction signing and encrypted balance management.
### 🛠️ Installation (CLI Management Tool)

### 🛠️ Installation (CLI Management Tool)

#### Prerequisites
You must have **Python 3.8 or higher** installed on your system.

#### Steps
1.  **Clone the repository (if you haven't already):**
    ```bash
    git clone https://github.com/anggafajarsidik/OFFoctra
    ```
2.  **Navigate to the project directory:**
    ```bash
    cd OFFoctra/CLI
    ```
3.  **Install Python dependencies:**
    ```bash
    pip3 install -r requirements.txt
    ```
4.  **Prepare your wallet data:**
    * Create a `wallet.json` file in the main directory. This file should contain your wallet private keys, addresses, and RPC URLs.
        * **Example for a single wallet:**
            ```json
            {
              "priv": "YOUR_PRIVATE_KEY_B64",
              "addr": "YOUR_OCTRA_ADDRESS",
              "rpc": "https://octra.network",
              "name": "MyMainWallet"
            }
            ```
        * **Example for multiple wallets:**
            ```json
            [
              {
                "priv": "PRIVATE_KEY_1_B64",
                "addr": "OCTRA_ADDRESS_1",
                "rpc": "https://octra.network",
                "name": "Wallet1"
              },
              {
                "priv": "PRIVATE_KEY_2_B64",
                "addr": "OCTRA_ADDRESS_2",
                "rpc": "https://octra.network",
                "name": "Wallet2"
              }
            ]
            ```
    * (Optional) Create a `proxy.txt` file (one proxy URL per line) if you wish to use proxies for your transactions.
    * (Optional) Create a `recipentaddress.txt` file (one Octra address per line) if you plan to use the multi-send feature.

### 💻 How to Use (CLI Management Tool)

1.  **Run the script from your terminal:**
    ```bash
    python3 cli.py
    ```
2.  **The script will load your wallets and present an interactive menu.**
3.  **Follow the on-screen prompts** to select a wallet (or all wallets) and execute commands like sending transactions, encrypting/decrypting balances, or managing private transfers.

### 📝 Key Operations & Commands (CLI Management Tool)

Once the script is running, you will be presented with a main menu. Here are some of the actions you can perform:

* `[1] Send Transaction`: Initiate a standard public transaction.
* `[2] Refresh Wallet(s)`: Update balance, nonce, and transaction history. This is the only command that will display the Wallet Explorer summary.
* `[3] Multi Send from File`: Send funds to multiple recipients listed in `recipentaddress.txt`.
* `[4] Encrypt Balance`: Move funds from your public balance to your encrypted balance.
* `[5] Decrypt Balance`: Move funds from your encrypted balance to your public balance.
* `[6] Private Transfer`: Send funds privately from your encrypted balance to another address.
* `[7] Claim Transfers`: Claim pending private transfers addressed to your wallet(s).
* `[8] Export Keys`: Export private keys for chosen wallet(s) to a file (use with extreme caution!).
* `[9] Clear History`: Clear local transaction history cache.
* `[0] Exit`: Close the application.
* `[s] Select Wallet / All Wallets`: Switch between managing a single wallet or all loaded wallets.

---

## 📊 Format to Json (FormatToJson.js)
* in JSON format. You'll be prompted to enter details like Octra addresses and private keys (B64) for each wallet. The final output is a JSON array ready for use on Octra Testnet
 * How to Use:
 * 1. Ensure Node.js is installed.
 * 2. Run from your terminal: `node formattojson.js`
 * 3. Follow the on-screen prompts.
 * FormatToJson.js in the GenerateWallet directory will display the JSON output in your console once all data has been entered. You can then copy it and use it in any script that requires it.
 * FormatToJson.js in the CLI directory will generate and save the data to a wallet.json file, which can be used directly. If a wallet.json file already exists, it will be overwritten when you run the script again. So, make sure to always back up your wallet.json file if it contains important data before running FormatToJson.js again.

## ⚠️ Disclaimer & Security Guidelines

* These scripts are provided "as-is" for educational and experimental purposes only[cite: 17]. [cite_start]The author and contributors are not responsible for any damages, losses, or legal issues arising from their use[cite: 18].
* **Use at your own risk.** You are solely responsible for your actions and any potential loss of funds[cite: 19].
* The keys generated and managed by these tools control access to your crypto assets[cite: 20].
* For generating or managing wallets that will hold significant value, it is **highly recommended** to run these scripts on a secure, **air-gapped (offline) computer** to prevent any possibility of exposure to malware or network attacks[cite: 21].
* **NEVER share your `Mnemonic Phrase` or `Private Key` with anyone.** Anyone who has them can steal your funds[cite: 22].
* Store all generated `.txt` files containing wallet details in a secure, encrypted, offline location[cite: 23].

---
