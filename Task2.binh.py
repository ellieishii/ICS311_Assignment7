import numpy as np
import random
import heapq
from collections import deque
from scipy.fft import fft, ifft
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Graph Representation (Adjacency List)
class Graph:
    def __init__(self, vertices):
        self.V = vertices  # Number of nodes
        self.adj_list = {i: [] for i in range(vertices)}  # adjacency list

    def add_edge(self, u, v):
        self.adj_list[u].append(v)
        self.adj_list[v].append(u)

# BFS to find the shortest path in the graph
def bfs(graph, start, end):
    visited = [False] * graph.V
    parent = [-1] * graph.V
    queue = deque([start])
    visited[start] = True
    
    while queue:
        node = queue.popleft()
        
        if node == end:
            break
        
        for neighbor in graph.adj_list[node]:
            if not visited[neighbor]:
                visited[neighbor] = True
                parent[neighbor] = node
                queue.append(neighbor)
    
    # Reconstruct the path
    path = []
    current = end
    while current != -1:
        path.append(current)
        current = parent[current]
    
    return path[::-1]  # Reverse to get the correct order

# FFT-based compression (Lossy Compression)
def compress_message(message, compression_level):
    # Convert message to an array of integers (assuming ASCII encoding)
    message_data = np.array([ord(c) for c in message], dtype=float)
    
    # Apply FFT
    freq_data = fft(message_data)
    
    # Keep only the significant frequencies based on compression level
    num_keep = int(len(freq_data) * compression_level)
    compressed_data = np.zeros_like(freq_data)
    compressed_data[:num_keep] = freq_data[:num_keep]
    
    # Apply inverse FFT to get the compressed message
    compressed_message = ifft(compressed_data).real
    compressed_message = np.round(compressed_message).astype(int)
    
    # Convert back to string
    compressed_str = ''.join(chr(x) for x in compressed_message if x > 0 and x < 256)
    
    return compressed_str

# AES Encryption and Decryption
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ct_bytes  # Return IV + Ciphertext

def decrypt_message(encrypted_message, key):
    iv = encrypted_message[:16]  # Extract IV from the start
    ct = encrypted_message[16:]  # Extract the ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ct), AES.block_size).decode()
    return decrypted_message

# Sender function: Finds a path, compresses, encrypts, and sends the message
def send_message(graph, sender, receiver, message, compression_level, encryption_key):
    # Step 1: Find a path using BFS
    path = bfs(graph, sender, receiver)
    
    if not path:
        print("No path found between sender and receiver.")
        return None
    
    print(f"Path found: {path}")
    
    # Step 2: Compress the message using FFT (Lossy Compression)
    compressed_message = compress_message(message, compression_level)
    print(f"Compressed message: {compressed_message}")
    
    # Step 3: Encrypt the message
    encrypted_message = encrypt_message(compressed_message, encryption_key)
    print(f"Encrypted message (Hex): {encrypted_message.hex()}")
    
    return encrypted_message, path

# Receiver function: Decrypts and decompresses the message
def receive_message(encrypted_message, encryption_key):
    # Step 1: Decrypt the message
    decrypted_message = decrypt_message(encrypted_message, encryption_key)
    print(f"Decrypted message: {decrypted_message}")
    
    # Step 2: Decompress the message using FFT (Inverse FFT)
    # (Note: This is a simple approach, and we are assuming the message was compressed using FFT)
    message_data = np.array([ord(c) for c in decrypted_message], dtype=float)
    reconstructed_data = ifft(message_data).real
    reconstructed_message = ''.join(chr(int(round(x))) for x in reconstructed_data if 0 < x < 256)
    
    print(f"Reconstructed message (after lossy compression): {reconstructed_message}")
    return reconstructed_message

# Main
def main():
    # Create a sample graph
    graph = Graph(6)  # 6 people
    graph.add_edge(0, 1)
    graph.add_edge(1, 2)
    graph.add_edge(2, 3)
    graph.add_edge(0, 4)
    graph.add_edge(4, 5)

    # Define the sender, receiver, message, compression level, and encryption key
    sender = 0
    receiver = 5
    message = "This is a secret message!"
    compression_level = 0.5  # Keep 50% of the frequencies
    encryption_key = get_random_bytes(16)  # AES key (16 bytes for AES-128)

    # Sender sends the message
    encrypted_message, path = send_message(graph, sender, receiver, message, compression_level, encryption_key)

    if encrypted_message:
        # Receiver receives and processes the message
        reconstructed_message = receive_message(encrypted_message, encryption_key)

if __name__ == "__main__":
    main()
