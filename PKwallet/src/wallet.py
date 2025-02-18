import secrets
import hashlib
from mnemonic import Mnemonic
from eth_keys import keys
from eth_utils import to_checksum_address, keccak

class EVMWallet:
    def __init__(self):
        """Initialize an EVM-compatible wallet"""
        self.private_key = None
        self.public_key = None
        self.address = None
        self.mnemonic = None
        
    def generate_wallet(self):
        """Generate a new wallet with private key and mnemonic phrase"""
        # Generate a secure random mnemonic
        mnemo = Mnemonic("english")
        self.mnemonic = mnemo.generate(strength=256)  # 24 words
        
        # Generate seed from mnemonic
        seed = mnemo.to_seed(self.mnemonic)
        
        # Use the first 32 bytes of the seed as private key
        private_key_bytes = seed[:32]
        self.private_key = private_key_bytes.hex()
        
        # Generate public key and address
        private_key = keys.PrivateKey(bytes.fromhex(self.private_key))
        self.public_key = private_key.public_key
        
        # Generate Ethereum address (last 20 bytes of keccak hash of public key)
        public_key_bytes = self.public_key.to_bytes()
        address_bytes = keccak(public_key_bytes)[12:]
        self.address = to_checksum_address(address_bytes)
        
        return {
            'address': self.address,
            'private_key': self.private_key,
            'mnemonic': self.mnemonic
        }
    
    def import_from_private_key(self, private_key: str):
        """Import wallet from private key"""
        try:
            if private_key.startswith('0x'):
                private_key = private_key[2:]
            
            private_key_obj = keys.PrivateKey(bytes.fromhex(private_key))
            self.private_key = private_key
            self.public_key = private_key_obj.public_key
            
            # Generate Ethereum address
            public_key_bytes = self.public_key.to_bytes()
            address_bytes = keccak(public_key_bytes)[12:]
            self.address = to_checksum_address(address_bytes)
            
            return {'address': self.address}
        except Exception as e:
            raise ValueError(f"Invalid private key: {str(e)}")
    
    def import_from_mnemonic(self, mnemonic: str):
        """Import wallet from mnemonic phrase"""
        try:
            mnemo = Mnemonic("english")
            if not mnemo.check(mnemonic):
                raise ValueError("Invalid mnemonic phrase")
            
            self.mnemonic = mnemonic
            seed = mnemo.to_seed(mnemonic)
            
            # Use the first 32 bytes of the seed as private key
            private_key_bytes = seed[:32]
            self.private_key = private_key_bytes.hex()
            
            # Generate public key and address
            private_key = keys.PrivateKey(bytes.fromhex(self.private_key))
            self.public_key = private_key.public_key
            
            # Generate Ethereum address
            public_key_bytes = self.public_key.to_bytes()
            address_bytes = keccak(public_key_bytes)[12:]
            self.address = to_checksum_address(address_bytes)
            
            return {
                'address': self.address,
                'private_key': self.private_key,
                'mnemonic': self.mnemonic
            }
        except Exception as e:
            raise ValueError(f"Error importing from mnemonic: {str(e)}")
            
    def sign_message(self, message: str) -> str:
        """Sign a message using the wallet's private key"""
        if not self.private_key:
            raise ValueError("Wallet not initialized. Generate or import a wallet first.")
        
        # Hash the message
        message_hash = keccak(text=message)
        
        # Sign the hash
        private_key = keys.PrivateKey(bytes.fromhex(self.private_key))
        signature = private_key.sign_msg_hash(message_hash)
        
        return signature.to_hex()
    
    def get_address(self) -> str:
        """Get the wallet's public address"""
        if not self.address:
            raise ValueError("Wallet not initialized. Generate or import a wallet first.")
        return self.address
