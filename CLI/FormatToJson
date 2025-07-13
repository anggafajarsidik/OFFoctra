const readline = require('readline');
const fs = require('fs'); // Import the file system module

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// Function to get user input (asynchronous)
function askQuestion(query) {
  return new Promise(resolve => rl.question(query, ans => {
    if (!ans || ans.trim() === "") {
      console.log("Input cannot be empty. Please enter a value.");
      return askQuestion(query).then(resolve); // Repeat question if empty
    }
    resolve(ans.trim());
  }));
}

// Function to get number input from user (asynchronous)
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
  // Ask for the number of configurations to create
  const numberOfConfigs = await getNumberInput("How many wallet configurations do you want to create? ");

  const allWalletConfigs = [];

  for (let i = 0; i < numberOfConfigs; i++) {
    console.log(`\n--- Entering data for Wallet #${i + 1} ---`);
    // Ask for Octra Address first
    const octraAddress = await askQuestion(`Enter the Octra Address for Wallet #${i + 1}: `);

    // Then ask for Private Key (B64)
    const privateKeyB64 = await askQuestion(`Enter the Private Key (B64) for Wallet #${i + 1}: `);

    // Create the object with the desired format
    const walletConfig = {
      "priv": privateKeyB64,
      "addr": octraAddress,
      "rpc": "https://octra.network",
      "name": `Wallet${i + 1}` // Wallet name will increment
    };
    allWalletConfigs.push(walletConfig);
  }

  // Define the filename
  const filename = 'wallet.json';
  // Convert the array of wallet configs to a JSON string
  const jsonOutput = JSON.stringify(allWalletConfigs, null, 2);

  // Write the JSON output to a file
  try {
    fs.writeFileSync(filename, jsonOutput);
    console.log(`\n--- Done! ${numberOfConfigs} wallet configuration(s) generated. ---`);
    console.log(`The configurations have been successfully saved to **${filename}** in this directory.`);
  } catch (error) {
    console.error(`\nError saving wallet configurations to ${filename}:`, error);
  } finally {
    rl.close(); // Important to close the readline interface
  }
}

runScript();
