#!/bin/bash

# Exit on error
set -e

# Activate virtual environment
source venv/bin/activate 2>/dev/null || {
    echo "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
}

# Upgrade pip and install dependencies
echo "Installing dependencies..."
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install "eth-hash[pycryptodome]"

# Create Python script for wallet creation
cat > wallet_creator.py << 'EOF'
from src.wallet import EVMWallet
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import getpass
import os

def derive_key(password: str, salt: bytes = None):
    if salt is None:
        salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_data(data: str, key: bytes):
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(encrypted_data: bytes, key: bytes):
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()

def ensure_wallets_directory():
    """Create wallets directory if it doesn't exist"""
    wallets_dir = 'wallets'
    if not os.path.exists(wallets_dir):
        print("\nCreating wallets directory...")
        os.makedirs(wallets_dir)
        print(f"Created directory: {os.path.abspath(wallets_dir)}")
    return wallets_dir

def ensure_password_file():
    """Create .password file if it doesn't exist"""
    password_file = '.password'
    if not os.path.exists(password_file):
        print("\nCreating password file...")
        with open(password_file, 'w') as f:
            pass  # Create empty file
        os.chmod(password_file, 0o600)  # Set restrictive permissions
        print(f"Created password file: {os.path.abspath(password_file)}")
    return password_file

def save_password(password: str, wallet_address: str):
    """Save password to .password file"""
    # Ensure password file exists with correct permissions
    password_file = ensure_password_file()
    
    # Create password entry
    password_entry = f"{wallet_address}:{password}\n"
    
    # Append to password file
    with open(password_file, 'a') as file:
        file.write(password_entry)
    
    # Double-check permissions (in case they were changed)
    os.chmod(password_file, 0o600)

def main():
    print("\n=== Create New Encrypted Wallet ===\n")
    
    # Ensure wallets directory exists
    wallets_dir = ensure_wallets_directory()
    
    # Get password
    while True:
        password = getpass.getpass("Create a strong password for wallet encryption: ")
        confirm = getpass.getpass("Confirm password: ")
        if password == confirm and len(password) >= 8:
            break
        print("\nPasswords don't match or too short (min 8 chars). Try again.\n")

    # Create and encrypt wallet
    print("\nGenerating new wallet...")
    wallet = EVMWallet()
    wallet_data = wallet.generate_wallet()
    
    # Save password
    save_password(password, wallet_data["address"])
    
    key, salt = derive_key(password)
    encrypted_private_key = encrypt_data(wallet_data["private_key"], key)
    encrypted_mnemonic = encrypt_data(wallet_data["mnemonic"], key)
    
    # Save encrypted data
    output = {
        "address": wallet_data["address"],
        "encrypted_private_key": base64.b64encode(encrypted_private_key).decode('utf-8'),
        "encrypted_mnemonic": base64.b64encode(encrypted_mnemonic).decode('utf-8'),
        "salt": base64.b64encode(salt).decode('utf-8')
    }
    
    filename = f"wallet_{wallet_data['address'][:10]}.json"
    filepath = os.path.join(wallets_dir, filename)
    
    with open(filepath, "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\n=== New Encrypted Wallet Created ===")
    print(f"Address: {wallet_data['address']}")
    print(f"Wallet saved to: {os.path.abspath(filepath)}\n")
    
    # Ask about revealing private key
    reveal = input("Would you like to reveal the private key? (yes/no): ").lower()
    if reveal in ['y', 'yes']:
        verify = getpass.getpass("Enter your password to reveal private key: ")
        try:
            key, _ = derive_key(verify, salt)
            decrypted_key = decrypt_data(encrypted_private_key, key)
            print(f"\nPrivate Key: {decrypted_key}")
        except:
            print("\nError: Invalid password!")
    
    # Ask about revealing mnemonic
    reveal = input("\nWould you like to reveal the mnemonic phrase? (yes/no): ").lower()
    if reveal in ['y', 'yes']:
        verify = getpass.getpass("Enter your password to reveal mnemonic: ")
        try:
            key, _ = derive_key(verify, salt)
            decrypted_mnemonic = decrypt_data(encrypted_mnemonic, key)
            print(f"\nMnemonic Phrase: {decrypted_mnemonic}")
        except:
            print("\nError: Invalid password!")
    
    print("\nIMPORTANT:")
    print("- Your wallet data is encrypted with your password")
    print("- Keep your password safe - there's no way to recover encrypted data without it")
    print("- Make sure to backup your wallet file")
    print("- Never share your private key or mnemonic phrase with anyone!")
    print("- Be sure to clear your history for bash by using history -c and for zsh by using history -p")
    print("- To clear bash history file, use: rm ~/.bash_history")
    print("- To clear zsh history file, use: rm ~/.zsh_history")
    print(f"- Your wallet file is stored in: {os.path.abspath(wallets_dir)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"\nError: {str(e)}")
EOF

# Run the wallet creation script
python wallet_creator.py

# Clean up
rm wallet_creator.py
deactivate
