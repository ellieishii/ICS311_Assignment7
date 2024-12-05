import networkx as nx
from typing import Optional, Tuple
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

@dataclass
class Person:
    id: str
    public_key: Optional[bytes] = None
    private_key: Optional[bytes] = None

@dataclass
class Message:
    sender: str
    receiver: str
    body: str
    signature: bytes
    original_hash: bytes

class SecureMessenger:
    def __init__(self):
        self.network = nx.Graph()
        self.people = {}

    def add_person(self, person: Person):
        # Add a person to the network
        self.people[person.id] = person
        self.network.add_node(person.id)

    def add_connection(self, person1: str, person2: str):
        # Add a connection between two people
        self.network.add_edge(person1, person2)

    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
    
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
        return private_bytes, public_bytes

    def calculate_hash(self, message: str) -> bytes:
        # Calculate SHA-256 hash of message
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message.encode())
        return digest.finalize()

    def sign_message(self, sender_id: str, receiver_id: str, message_body: str) -> Message:
        # Create a signed message
        sender = self.people.get(sender_id)
        if not sender or not sender.private_key:
            raise ValueError(f"Sender {sender_id} not found or missing private key")

        # Calculate message hash
        message_hash = self.calculate_hash(message_body)

        # Sign the hash
        key = serialization.load_pem_private_key(sender.private_key, password=None)
        signature = key.sign(
            message_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return Message(
            sender=sender_id,
            receiver=receiver_id,
            body=message_body,
            signature=signature,
            original_hash=message_hash
        )

    def verify_signed_message(self, message: Message) -> bool:
        # Verify a signed message
        sender = self.people.get(message.sender)
        if not sender or not sender.public_key:
            return False

        try:
            # Recalculate hash
            calculated_hash = self.calculate_hash(message.body)

            # Verify hash matches
            if calculated_hash != message.original_hash:
                return False

            # Verify signature
            key = serialization.load_pem_public_key(sender.public_key)
            key.verify(
                message.signature,
                message.original_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

def main():
    messenger = SecureMessenger()

    # Create people and generate key pairs
    alice = Person("alice")
    alice_private, alice_public = messenger.generate_key_pair()
    alice.private_key = alice_private
    alice.public_key = alice_public

    bob = Person("bob")
    bob_private, bob_public = messenger.generate_key_pair()
    bob.private_key = bob_private
    bob.public_key = bob_public

    # Add people to network
    messenger.add_person(alice)
    messenger.add_person(bob)
    messenger.add_connection("alice", "bob")

    # Send signed message
    message = messenger.sign_message("alice", "bob", "Secure communication test")
    
    # Verify message
    is_valid = messenger.verify_signed_message(message)
    
    # Output the message details, including the signature
    print(f"Sender: {message.sender}")
    print(f"Receiver: {message.receiver}")
    print(f"Message: {message.body}")
    print(f"Signature: {message.signature.hex()}")
    print(f"Verification: {'✅ Valid' if is_valid else '❌ Invalid'}")

if __name__ == "__main__":
    main()
