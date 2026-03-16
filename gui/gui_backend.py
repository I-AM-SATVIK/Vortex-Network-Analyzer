import socket
import threading
import queue
import customtkinter as ctk

# 1. Initialize the thread-safe memory queue
packet_queue = queue.Queue()

# 2. The Background Worker (Runs on a separate CPU thread)
def udp_listener_thread():
    UDP_IP = "127.0.0.1"
    UDP_PORT = 5555
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    
    while True:
        try:
            data, _ = sock.recvfrom(65535)
            payload_str = data.decode('utf-8')
            # Push the raw string into the queue safely
            packet_queue.put(payload_str)
        except Exception as e:
            print(f"Socket error: {e}")
            break

# 3. The Main Application (Runs on the primary thread)
class VortexGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Window Setup
        self.title("Vortex Network Analyzer")
        self.geometry("1000x600")
        ctk.set_appearance_mode("dark")
        
        # Header Label
        self.title_label = ctk.CTkLabel(self, text="Live Network Telemetry", font=("Consolas", 20, "bold"))
        self.title_label.pack(pady=10)
        
        # The Packet Ledger (Text Box)
        self.ledger = ctk.CTkTextbox(self, width=950, height=500, font=("Consolas", 14))
        self.ledger.pack(padx=20, pady=10)
        
        # Insert Table Headers
        header = f"{'PROTOCOL':<10} | {'SOURCE':<25} | {'DESTINATION':<25} | {'SIZE'}\n"
        self.ledger.insert("0.0", header + "-"*80 + "\n")
        
        # Launch the background listener thread
        # daemon=True ensures this thread is killed immediately when you close the GUI window
        self.listener = threading.Thread(target=udp_listener_thread, daemon=True)
        self.listener.start()
        
        # Start the non-blocking UI update loop
        self.update_ledger()

    def update_ledger(self):
        # Process up to 50 packets per frame to prevent GUI lag during heavy traffic spikes
        for _ in range(50):
            try:
                # Attempt to pull data from the queue without pausing the program
                packet_data = packet_queue.get_nowait()
                
                parts = packet_data.split('|')
                if len(parts) >= 6:
                    protocol = parts[0]
                    source = f"{parts[1]}:{parts[3]}"
                    dest = f"{parts[2]}:{parts[4]}"
                    size = f"{parts[5]} bytes"
                    
                    formatted_line = f"{protocol:<10} | {source:<25} | {dest:<25} | {size}\n"
                    self.ledger.insert("end", formatted_line)
                    self.ledger.see("end") # Auto-scroll to the bottom
                    
            except queue.Empty:
                break # If the queue is empty, stop checking and let the screen render
        
        # Schedule this function to run again in 100 milliseconds
        self.after(100, self.update_ledger)

if __name__ == "__main__":
    app = VortexGUI()
    app.mainloop()