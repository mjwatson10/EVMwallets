# PKwallet - EVM Compatible Wallet

A secure Ethereum/EVM compatible wallet implementation that can generate private keys and mnemonic seed phrases.

## Features

- Generate secure random private keys
- Create BIP39 compliant mnemonic seed phrases (24 words)
- Sign messages
- Import existing wallets from private keys or mnemonic phrases
- EVM compatible

## Installation

1. Create a virtual environment (recommended):

```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```python
from wallet import EVMWallet

# Create a new wallet
wallet = EVMWallet()

# Generate new wallet
wallet_data = wallet.generate_wallet()
print(f"Address: {wallet_data['address']}")
print(f"Private Key: {wallet_data['private_key']}")
print(f"Mnemonic: {wallet_data['mnemonic']}")

# Sign a message
signature = wallet.sign_message("Hello, Ethereum!")
print(f"Signature: {signature}")

# Import from private key
wallet.import_from_private_key(private_key)

# Import from mnemonic
wallet.import_from_mnemonic(mnemonic)
```

## Using the Bash Scripts

### Creating a New Wallet

1. Navigate to the PKwallet directory:

2. Make the create wallet script executable:

```bash
chmod +x create_wallet.sh
```

3. Run the create wallet script:

```bash
./create_wallet.sh
```

4. Follow the prompts:
   - Enter and confirm a strong password (minimum 8 characters)
   - Choose whether to reveal the private key
   - Choose whether to reveal the mnemonic phrase
   - Enter your password when prompted to reveal sensitive information

The wallet will be saved as a JSON file in the format `wallet_<first10CharsOfAddress>.json`

### Viewing an Existing Wallet

1. Navigate to the PKwallet directory:

2. Make the view wallet script executable:

```bash
chmod +x view_wallet.sh
```

3. Run the view wallet script:

```bash
./view_wallet.sh
```

4. Follow the prompts:
   - Enter the wallet file name (e.g., `wallet_0xF9fB16cE.json`)
   - Choose whether to reveal the private key
   - Enter your password when prompted
   - Choose whether to reveal the mnemonic phrase
   - Enter your password when prompted

### Security Notes

1. After viewing sensitive information, clear your terminal history:
   - For bash: `history -c`
   - For zsh: `history -p`
2. Clear history files:

   - For bash: `rm ~/.bash_history`
   - For zsh: `rm ~/.zsh_history`

3. Important Security Practices:
   - Never share your private key or mnemonic phrase
   - Store your wallet password securely
   - Keep a secure backup of your wallet file
   - Clear terminal history after viewing sensitive information
   - Consider using a hardware wallet for large amounts

## Security Notes

- Never share your private key or mnemonic phrase with anyone
- Store your mnemonic phrase in a secure location
- This wallet is for educational purposes. For production use, consider using established wallet solutions

## Example

Run the example script to see the wallet in action:

```bash
python src/example.py
```
