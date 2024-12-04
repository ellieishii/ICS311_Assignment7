  # Task 1 Implementation(Ralph Ramos)
def run_length_encode(message):
    if not message:
        return ""
        
    result = []
    count = 1
    current_char = message[0]
    
    # Single pass through the string
    for i in range(1, len(message)):
        if message[i] == current_char:
            count += 1
        else:
            result.append(str(count) + current_char)
            current_char = message[i]
            count = 1
            
    # Append the last run
    result.append(str(count) + current_char)
    
    return "".join(result)

def send_compressed_message(sender, receiver, message):
    compressed_body = run_length_encode(message)
    metadata = {
        "encoding": "run-length"
    }
    message_triple = (sender, receiver, metadata, compressed_body)
    return message_triple

# Example usage
if __name__ == "__main__":
    sender = "Alice"
    receiver = "Bob"
    message = "aaabbbbcc"
    message_triple = send_compressed_message(sender, receiver, message)
    print(message_triple)
    print(f"Metadata: {message_triple[2]}")

# Task 2 Implementation (Binh Tran)
from collections import deque 
from zlib import compress, decompress  
from Crypto.Cipher import AES  
from Crypto.Util.Padding import pad, unpad 
from Crypto.Random import get_random_bytes  

# Graph Representation (Adjacency List)
class Graph:
    def __init__(self, vertices):
        self.V = vertices  # Number of nodes
        self.adj_list = {i: [] for i in range(vertices)}  # adjacency list

    def add_edge(self, u, v):
        self.adj_list[u].append(v)  # Add an undirected edge between nodes u and v
        self.adj_list[v].append(u)  # Since the graph is undirected, add the reverse edge as well

# BFS to find the shortest path in the graph
def bfs(graph, start, end):
    visited = [False] * graph.V  # Keeps track of visited nodes
    parent = [-1] * graph.V  # Stores the parent of each node in the BFS tree
    queue = deque([start])  # Initialize BFS queue
    visited[start] = True  # Mark the start node as visited
    
    while queue:
        node = queue.popleft()  # Pop the node from the front of the queue
        
        if node == end:  # If the target node is found, stop searching
            break
        
        # Iterate over the adjacent nodes of the current node
        for neighbor in graph.adj_list[node]:
            if not visited[neighbor]:  # If the neighbor has not been visited
                visited[neighbor] = True  # Mark the neighbor as visited
                parent[neighbor] = node  # Set the parent of the neighbor to the current node
                queue.append(neighbor)  # Add the neighbor to the queue for further exploration
    
    # Reconstruct the path from the start to the end
    path = []
    current = end
    while current != -1:  # Backtrack from the target node to the start node using the parent array
        path.append(current)
        current = parent[current]
    
    return path[::-1]  # Reverse the path to get it in the correct order

# Lossless Compression using zlib
def compress_message(message):
    # Convert message to bytes (ASCII)
    message_bytes = message.encode('utf-8')  # Encoding the message to bytes
    compressed_message = compress(message_bytes)  # Compress the message using zlib
    return compressed_message  # Return the compressed message as a byte string

def decompress_message(compressed_message):
    # Decompress the message using zlib
    decompressed_message = decompress(compressed_message).decode('utf-8')  # Decompress and decode to string
    return decompressed_message  # Return the decompressed message

# AES Encryption and Decryption
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)  # Create a new AES cipher object in CBC mode
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))  # Encrypt the message after padding it
    return cipher.iv + ct_bytes  # Return IV + Ciphertext to ensure decryption can use the same IV

def decrypt_message(encrypted_message, key):
    iv = encrypted_message[:16]  # Extract IV from the encrypted message (first 16 bytes)
    ct = encrypted_message[16:]  # Extract the actual ciphertext (everything after the IV)
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create a new cipher object using the same IV
    decrypted_message = unpad(cipher.decrypt(ct), AES.block_size).decode()  # Decrypt and unpad the message
    return decrypted_message  # Return the decrypted message

# Sender function: Finds a path, compresses, encrypts, and sends the message
def send_message(graph, sender, receiver, message, encryption_key):
    print("Sending message from {} to {}...".format(sender, receiver))
    # Step 1: Find a path using BFS
    path = bfs(graph, sender, receiver)
    
    if not path:
        print("No path found between sender and receiver.")  # If no path is found, print a message
        return None  # Return None to indicate that no message was sent
    
    print("Path found: {}".format(path))
    
    # Step 2: Compress the message using zlib (lossless compression)
    compressed_message = compress_message(message)
    print("Compressed message (length {} bytes): {}".format(len(compressed_message), compressed_message))
    
    # Step 3: Encrypt the message
    encrypted_message = encrypt_message(compressed_message.decode('latin1'), encryption_key)  # Encrypt the compressed message
    print("Encrypted message (Hex): {}".format(encrypted_message.hex()))  # Print the encrypted message in hexadecimal format
    
    return encrypted_message, path  # Return the encrypted message and the path

# Receiver function: Decrypts and decompresses the message
def receive_message(encrypted_message, encryption_key):
    print("Receiver is decrypting and reconstructing the message...")
    # Step 1: Decrypt the message
    decrypted_message = decrypt_message(encrypted_message, encryption_key)
    print("Decrypted message (bytes): {}".format(decrypted_message))  # Print the decrypted message in byte format
    
    # Step 2: Decompress the message using zlib
    decompressed_message = decompress_message(decrypted_message.encode('latin1'))  # Decompress the message back to string
    print("Decompressed message: {}".format(decompressed_message))  # Print the decompressed message
    
    return decompressed_message  # Return the decompressed message

# Main
def main():
    print("Initializing the network graph...")
    # Create a sample graph (6 nodes representing people)
    graph = Graph(6)  # 6 people
    graph.add_edge(0, 1)  # Add edges between the nodes
    graph.add_edge(1, 2)
    graph.add_edge(2, 3)
    graph.add_edge(0, 4)
    graph.add_edge(4, 5)

    # Define the sender, receiver, message, and encryption key
    sender = 0  # Sender node
    receiver = 5  # Receiver node
    message = "This is a secret message!"  # The message to be sent
    encryption_key = get_random_bytes(16)  # AES key (16 bytes for AES-128)

    # Sender sends the message
    encrypted_message, path = send_message(graph, sender, receiver, message, encryption_key)

    if encrypted_message:
        # Receiver receives and processes the message
        reconstructed_message = receive_message(encrypted_message, encryption_key)

# Run the main function if the script is executed directly
if __name__ == "__main__":
    main()


# Task 4 Implementation (Ellie Ishii)
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
    
    print(f"Sender: {message.sender}")
    print(f"Receiver: {message.receiver}")
    print(f"Message: {message.body}")
    print(f"Verification: {'✅ Valid' if is_valid else '❌ Invalid'}")

if __name__ == "__main__":
    main()
