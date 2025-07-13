const readline = require('readline');
const fs = require('fs');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function askQuestion(query) {
  return new Promise(resolve => rl.question(query, ans => {
    if (!ans || ans.trim() === "") {
      console.log("Input cannot be empty. Please enter a value.");
      return askQuestion(query).then(resolve);
    }
    resolve(ans.trim());
  }));
}

async function getNumberInput(promptMessage) {
  let input;
  let isValid = false;
  while (!isValid) {
    input = await askQuestion(promptMessage);
    const num = parseInt(input);
    if (!isNaN(num) && num > 0) {
      isValid = true;
      return num;
    } else {
      console.log("Please enter a valid number greater than 0.");
    }
  }
}

async function runScript() {
  const numberOfConfigs = await getNumberInput("How many wallet configurations do you want to create? ");

  const allWalletConfigs = [];

  for (let i = 0; i < numberOfConfigs; i++) {
    console.log(`\n--- Entering data for Wallet #${i + 1} ---`);
    const octraAddress = await askQuestion(`Enter the Octra Address for Wallet #${i + 1}: `);

    const privateKeyB64 = await askQuestion(`Enter the Private Key (B64) for Wallet #${i + 1}: `);

    const walletConfig = {
      "priv": privateKeyB64,
      "addr": octraAddress,
      "rpc": "https://octra.network",
      "name": `Wallet${i + 1}`
    };
    allWalletConfigs.push(walletConfig);
  }

  const filename = 'wallet.json';
  const jsonOutput = JSON.stringify(allWalletConfigs, null, 2);

  try {
    fs.writeFileSync(filename, jsonOutput);
    console.log(`\n--- Done! ${numberOfConfigs} wallet configuration(s) generated. ---`);
    console.log(`The configurations have been successfully saved to **${filename}** in this directory.`);
  } catch (error) {
    console.error(`\nError saving wallet configurations to ${filename}:`, error);
  } finally {
    rl.close();
  }
}

runScript();
