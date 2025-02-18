from wallet import EVMWallet

def main():
    # Create a new wallet
    wallet = EVMWallet()
    
    # Generate new wallet with private key and mnemonic
    wallet_data = wallet.generate_wallet()
    
    print("\nNew Wallet Generated:")
    print(f"Address: {wallet_data['address']}")
    print(f"Private Key: {wallet_data['private_key']}")
    print(f"Mnemonic Phrase: {wallet_data['mnemonic']}")
    
    # Example of signing a message
    message = "Hello, Ethereum!"
    signature = wallet.sign_message(message)
    print(f"\nSigned message '{message}':")
    print(f"Signature: {signature}")

if __name__ == "__main__":
    main()
