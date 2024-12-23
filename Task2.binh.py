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

