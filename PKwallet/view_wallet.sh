#!/bin/bash

# Activate virtual environment
source venv/bin/activate

# Create Python script for wallet decryption
cat > temp_decrypt_script.py << 'EOF'
import json
import sys
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import os

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()

def get_stored_password(wallet_address: str) -> str:
    """Retrieve password from .password file"""
    try:
        with open('.password', 'r') as file:
            for line in file:
                addr, pwd = line.strip().split(':', 1)
                if addr == wallet_address:
                    return pwd
        return None
    except (FileNotFoundError, ValueError):
        return None

def prompt_reveal(item_name: str, encrypted_data: bytes, salt: bytes, stored_password: str = None) -> None:
    while True:
        reveal = input(f"\nWould you like to reveal the {item_name}? (yes/no): ").lower()
        if reveal in ['yes', 'y']:
            if stored_password:
                try:
                    key = derive_key(stored_password, salt)
                    decrypted_data = decrypt_data(encrypted_data, key)
                    print(f"\n{item_name}: {decrypted_data}")
                    break
                except:
                    print("Stored password is invalid. Please enter password manually.")
                    stored_password = None
                    
            if not stored_password:
                while True:
                    verify_pass = getpass.getpass("Enter your password to reveal: ")
                    key = derive_key(verify_pass, salt)
                    try:
                        decrypted_data = decrypt_data(encrypted_data, key)
                        print(f"\n{item_name}: {decrypted_data}")
                        break
                    except:
                        print("Invalid password. Please try again.")
                        retry = input("Would you like to try again? (yes/no): ").lower()
                        if retry not in ['yes', 'y']:
                            break
            break
        elif reveal in ['no', 'n']:
            break
        else:
            print("Please enter 'yes' or 'no'")

def view_wallet(wallet_file: str):
    try:
        # Load wallet file from wallets directory
        filepath = os.path.join('wallets', wallet_file)
        with open(filepath, 'r') as f:
            wallet_data = json.load(f)
        
        # Get stored password
        stored_password = get_stored_password(wallet_data['address'])
        if stored_password:
            print("\nFound stored password for this wallet")
        
        # Get salt and encrypted data
        salt = base64.b64decode(wallet_data['salt'])
        encrypted_private_key = base64.b64decode(wallet_data['encrypted_private_key'])
        encrypted_mnemonic = base64.b64decode(wallet_data['encrypted_mnemonic'])
        
        print("\n=== Wallet Details ===")
        print(f"Address: {wallet_data['address']}")
        
        # Prompt for private key revelation
        prompt_reveal("Private Key", encrypted_private_key, salt, stored_password)
        
        # Prompt for mnemonic revelation
        prompt_reveal("Mnemonic Phrase", encrypted_mnemonic, salt, stored_password)
        
        print("\nIMPORTANT:")
        print("- Never share your private key or mnemonic phrase with anyone!")
        print("- Be sure to clear your history for bash use: history -c and for zsh use: history -p")
        print("- To clear bash history file, use: rm ~/.bash_history")
        print("- To clear zsh history file, use: rm ~/.zsh_history")
        
    except Exception as e:
        print(f"\nError: Unable to read wallet file. Make sure the file exists and is valid.")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <wallet_file>")
        sys.exit(1)
    
    wallet_file = sys.argv[1]
    view_wallet(wallet_file)
EOF

# List available wallets
echo -e "\nAvailable wallets in the wallets directory:"
ls -1 wallets/*.json 2>/dev/null || echo "No wallet files found."
echo ""

# Get wallet file
echo -n "Enter the wallet filename (e.g., wallet_0xF9fB16cE.json): "
read wallet_file

# Run the decryption script
python temp_decrypt_script.py "$wallet_file"

# Clean up
rm temp_decrypt_script.py
deactivate
