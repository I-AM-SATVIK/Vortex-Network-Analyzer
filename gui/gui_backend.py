import socket

def start_telemetry_listener():
    # 1. Define the IP and Port to match the C++ engine
    UDP_IP = "127.0.0.1"
    UDP_PORT = 5555

    # 2. Initialize a standard UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # 3. Bind the socket to the port to start listening
    sock.bind((UDP_IP, UDP_PORT))
    
    print(f"[*] Python Backend listening on {UDP_IP}:{UDP_PORT}...\n")
    print(f"{'PROTOCOL':<10} | {'SOURCE':<25} | {'DESTINATION':<25} | {'SIZE'}")
    print("-" * 70)

    try:
        # 4. Infinite loop to catch packets as they arrive in real-time
        while True:
            # Buffer size is 65535 bytes (max standard UDP size)
            data, addr = sock.recvfrom(65535)
            
            # Decode the raw byte array into a string
            payload_str = data.decode('utf-8')
            
            # Split the pipe-delimited string back into an array
            # Format: Protocol|SrcIP|DestIP|SrcPort|DestPort|Size|HexDump
            parts = payload_str.split('|')
            
            if len(parts) >= 6:
                protocol = parts[0]
                source = f"{parts[1]}:{parts[3]}"
                dest = f"{parts[2]}:{parts[4]}"
                size = f"{parts[5]} bytes"
                
                # Print the formatted output
                print(f"{protocol:<10} | {source:<25} | {dest:<25} | {size}")
                
    except KeyboardInterrupt:
        print("\n[*] Listener stopped by user.")
    finally:
        sock.close()

if __name__ == "__main__":
    start_telemetry_listener()