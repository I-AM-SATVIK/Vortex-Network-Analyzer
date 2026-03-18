import socket
import threading
import queue
import csv
import customtkinter as ctk
from tkinter import ttk, filedialog

packet_queue = queue.Queue()
packet_payloads = {}

def udp_listener_thread():
    UDP_IP = "127.0.0.1"
    UDP_PORT = 5555
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    
    while True:
        try:
            data, _ = sock.recvfrom(65535)
            packet_queue.put(data.decode('utf-8'))
        except Exception as e:
            print(f"Socket error: {e}")
            break

class VortexGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("Vortex Network Analyzer")
        self.geometry("1000x750")
        ctk.set_appearance_mode("dark")
        
        self.active_filter = ""
        self.is_paused = False # State flag for the play/pause toggle
        
        self.title_label = ctk.CTkLabel(self, text="Live Network Telemetry", font=("Consolas", 20, "bold"))
        self.title_label.pack(pady=10)
        
        # --- Top Bar: Controls ---
        self.filter_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.filter_frame.pack(padx=20, pady=(0, 10), fill="x")
        
        self.search_var = ctk.StringVar()
        self.search_entry = ctk.CTkEntry(self.filter_frame, textvariable=self.search_var, placeholder_text="Filter (e.g., 443, TCP)", width=250)
        self.search_entry.pack(side="left", padx=(0, 10))
        
        self.search_btn = ctk.CTkButton(self.filter_frame, text="Search", width=70, command=self.apply_filter)
        self.search_btn.pack(side="left", padx=(0, 10))
        
        self.clear_btn = ctk.CTkButton(self.filter_frame, text="Clear", width=70, command=self.clear_filter, fg_color="#555555", hover_color="#333333")
        self.clear_btn.pack(side="left", padx=(0, 20))

        # Play/Pause and Export Buttons
        self.pause_btn = ctk.CTkButton(self.filter_frame, text="⏸ Pause", width=80, command=self.toggle_pause, fg_color="#b28d00", hover_color="#806500")
        self.pause_btn.pack(side="left", padx=(0, 10))

        self.export_btn = ctk.CTkButton(self.filter_frame, text="💾 Export CSV", width=100, command=self.export_csv, fg_color="#005b9f", hover_color="#004070")
        self.export_btn.pack(side="left")
        
        # --- Top Panel: The Packet Ledger ---
        columns = ("Protocol", "Source", "Destination", "Size")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=225, anchor="center")
            
        self.tree.pack(padx=20, pady=(0, 10), fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.inspect_packet)
        
        # --- Bottom Panel: Deep Inspection ---
        self.inspection_label = ctk.CTkLabel(self, text="Payload Inspection (Hex & ASCII)", font=("Consolas", 14, "bold"))
        self.inspection_label.pack(anchor="w", padx=20)
        
        self.hex_display = ctk.CTkTextbox(self, width=950, height=200, font=("Consolas", 14))
        self.hex_display.pack(padx=20, pady=(0, 20), fill="both", expand=False)
        
        self.listener = threading.Thread(target=udp_listener_thread, daemon=True)
        self.listener.start()
        self.update_ledger()

    def toggle_pause(self):
        self.is_paused = not self.is_paused
        if self.is_paused:
            self.pause_btn.configure(text="▶ Resume", fg_color="#008000", hover_color="#005500")
        else:
            self.pause_btn.configure(text="⏸ Pause", fg_color="#b28d00", hover_color="#806500")

    def export_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not file_path:
            return
            
        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            # Write headers
            writer.writerow(["Protocol", "Source", "Destination", "Size", "Hex Payload"])
            
            # Write data rows
            for item in self.tree.get_children():
                row_values = self.tree.item(item)['values']
                hex_payload = packet_payloads.get(item, "NONE")
                row_data = list(row_values) + [hex_payload]
                writer.writerow(row_data)

    def apply_filter(self):
        self.active_filter = self.search_var.get().lower()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.hex_display.delete("0.0", "end")

    def clear_filter(self):
        self.search_var.set("")
        self.active_filter = ""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.hex_display.delete("0.0", "end")

    def update_ledger(self):
        for _ in range(50):
            try:
                packet_data = packet_queue.get_nowait()
                
                # Discard the packet if the GUI is paused
                if self.is_paused:
                    continue
                    
                parts = packet_data.split('|')
                
                if len(parts) >= 7:
                    protocol = parts[0]
                    source = f"{parts[1]}:{parts[3]}"
                    dest = f"{parts[2]}:{parts[4]}"
                    size = f"{parts[5]} bytes"
                    hex_dump = parts[6]
                    
                    row_string = f"{protocol} {source} {dest}".lower()
                    
                    if self.active_filter and self.active_filter not in row_string:
                        continue 
                    
                    item_id = self.tree.insert("", "end", values=(protocol, source, dest, size))
                    packet_payloads[item_id] = hex_dump
                    self.tree.yview_moveto(1)
                    
            except queue.Empty:
                break
                
        self.after(100, self.update_ledger)

    def inspect_packet(self, event):
        selected_items = self.tree.selection()
        if not selected_items:
            return
            
        item_id = selected_items[0]
        hex_data = packet_payloads.get(item_id, "NO PAYLOAD")
        
        self.hex_display.delete("0.0", "end")
        
        if hex_data == "NONE" or hex_data == "NO PAYLOAD":
            self.hex_display.insert("0.0", "No payload data for this packet.")
            return

        for i in range(0, len(hex_data), 32):
            chunk = hex_data[i:i+32]
            formatted_hex = " ".join([chunk[j:j+2] for j in range(0, len(chunk), 2)])
            
            ascii_str = ""
            for j in range(0, len(chunk), 2):
                byte_val = int(chunk[j:j+2], 16)
                if 32 <= byte_val <= 126: 
                    ascii_str += chr(byte_val)
                else:
                    ascii_str += "."
                    
            self.hex_display.insert("end", f"{formatted_hex:<48}  |  {ascii_str}\n")

if __name__ == "__main__":
    app = VortexGUI()
    app.mainloop()