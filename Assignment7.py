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
