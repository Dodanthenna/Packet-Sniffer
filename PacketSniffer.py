import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import sniff, hexdump
import threading
from datetime import datetime
import csv
import io
import sys

class PacketSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer GUI")
        self.root.geometry("1000x700")

        self.sniffing = False
        self.packet_list = []
        self.filter_settings = {"protocol": "All", "ip": ""}

        self._build_filter_controls()
        self._build_table_view()
        self._build_hex_view()

    def _build_filter_controls(self):
        filter_frame = tk.Frame(self.root)
        filter_frame.pack(pady=10)

        self.protocol_var = tk.StringVar(value="All")
        self.ip_var = tk.StringVar()

        tk.Label(filter_frame, text="Protocol:").pack(side=tk.LEFT, padx=5)
        protocol_options = ttk.Combobox(filter_frame, textvariable=self.protocol_var, values=["All", "TCP", "UDP", "ICMP"], state="readonly")
        protocol_options.pack(side=tk.LEFT, padx=5)

        tk.Label(filter_frame, text="IP Address:").pack(side=tk.LEFT, padx=5)
        tk.Entry(filter_frame, textvariable=self.ip_var, width=18).pack(side=tk.LEFT, padx=5)

        tk.Button(filter_frame, text="Apply Filter", command=self.apply_filter).pack(side=tk.LEFT, padx=10)
        tk.Button(filter_frame, text="Export to CSV", command=self.export_csv).pack(side=tk.LEFT, padx=10)
        self.toggle_btn = tk.Button(filter_frame, text="Start Capture", command=self.toggle_capture, bg="green", fg="white")
        self.toggle_btn.pack(side=tk.LEFT, padx=10)

    def _build_table_view(self):
        columns = ("Time", "Source", "Destination", "Protocol", "Src Port", "Dst Port")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=16)
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=130, anchor="center")
        self.tree.pack(fill=tk.BOTH)
        self.tree.bind("<<TreeviewSelect>>", self.display_packet_hex)

    def _build_hex_view(self):
        self.hex_output = tk.Text(self.root, height=12, bg="#1e1e1e", fg="white", insertbackground="white")
        self.hex_output.insert("1.0", "Hex view will show here.")
        self.hex_output.config(state=tk.DISABLED)
        self.hex_output.pack(fill=tk.BOTH, expand=True)

    def apply_filter(self):
        self.filter_settings["protocol"] = self.protocol_var.get()
        self.filter_settings["ip"] = self.ip_var.get().strip()

    def toggle_capture(self):
        if not self.sniffing:
            self.sniffing = True
            self.toggle_btn.config(text="Stop Capture", bg="red")
            threading.Thread(target=self.start_sniffing, daemon=True).start()
        else:
            self.sniffing = False
            self.toggle_btn.config(text="Start Capture", bg="green")

    def start_sniffing(self):
        sniff(prn=self.process_packet, store=False, stop_filter=lambda _: not self.sniffing)

    def process_packet(self, packet):
        proto = "-"
        src = dst = sport = dport = "-"
        time_str = datetime.now().strftime("%H:%M:%S")

        if packet.haslayer("IP"):
            src = packet["IP"].src
            dst = packet["IP"].dst
            proto_num = packet["IP"].proto

        if packet.haslayer("TCP"):
            sport = packet["TCP"].sport
            dport = packet["TCP"].dport
            proto = "TCP"
        elif packet.haslayer("UDP"):
            sport = packet["UDP"].sport
            dport = packet["UDP"].dport
            proto = "UDP"
        elif packet.haslayer("ICMP"):
            proto = "ICMP"

        if self.filter_settings["protocol"] != "All" and proto != self.filter_settings["protocol"]:
            return
        if self.filter_settings["ip"] and self.filter_settings["ip"] not in [src, dst]:
            return

        row = (time_str, src, dst, proto, sport, dport)
        self.root.after(0, lambda: self.add_row(row, packet))

    def add_row(self, row, packet):
        if len(self.tree.get_children()) > 100:
            oldest = self.tree.get_children()[0]
            self.tree.delete(oldest)
            self.packet_list.pop(0)

        self.tree.insert("", "end", values=row)
        self.packet_list.append(packet)

    def display_packet_hex(self, event):
        selected = self.tree.selection()
        if not selected:
            return

        idx = self.tree.index(selected[0])
        if idx >= len(self.packet_list):
            return

        packet = self.packet_list[idx]
        self.hex_output.config(state=tk.NORMAL)
        self.hex_output.delete("1.0", tk.END)

        buffer = io.StringIO()
        sys.stdout = buffer
        hexdump(packet)
        sys.stdout = sys.__stdout__

        self.hex_output.insert("1.0", buffer.getvalue())
        self.hex_output.config(state=tk.DISABLED)

    def export_csv(self):
        filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if not filepath:
            return

        try:
            with open(filepath, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Time", "Source", "Destination", "Protocol", "Src Port", "Dst Port"])
                for row_id in self.tree.get_children():
                    writer.writerow(self.tree.item(row_id)['values'])
            messagebox.showinfo("Success", f"Exported to {filepath}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

if __name__ == '__main__':
    root = tk.Tk()
    app = PacketSniffer(root)
    root.mainloop()
