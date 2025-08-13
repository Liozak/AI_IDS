import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import joblib
import numpy as np
import pandas as pd
import threading
import time
from scapy.all import sniff, IP, TCP, UDP


# Load model and encoders
model = joblib.load("models/ids_model.joblib")
scaler = joblib.load("models/scaler.joblib")
le_protocol = joblib.load("encoders/le_protocol_type.joblib")
le_service = joblib.load("encoders/le_service.joblib")
le_flag = joblib.load("encoders/le_flag.joblib")

# Categorical options
protocol_options = le_protocol.classes_
service_options = le_service.classes_
flag_options = le_flag.classes_

# 41 Feature Names (first 3 are encoded)
feature_names = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

# GUI setup
root = tk.Tk()
root.title("AI Intrusion Detection System")
root.geometry("1000x700")

canvas = tk.Canvas(root, bg="black")
scrollbar = tk.Scrollbar(root, command=canvas.yview)
canvas.configure(yscrollcommand=scrollbar.set)

form_frame = tk.Frame(canvas, bg="black")
canvas.create_window((0, 0), window=form_frame, anchor='nw')

inputs = {}

# Create form fields
for idx, feature in enumerate(feature_names):
    label = tk.Label(form_frame, text=feature, fg="white", bg="black")
    label.grid(row=idx, column=0, sticky="w", padx=10, pady=5)

    if feature == "protocol_type":
        cb = ttk.Combobox(form_frame, values=protocol_options)
        cb.set(protocol_options[0])
        cb.grid(row=idx, column=1, padx=10, pady=5)
        inputs[feature] = cb
    elif feature == "service":
        cb = ttk.Combobox(form_frame, values=service_options)
        cb.set(service_options[0])
        cb.grid(row=idx, column=1, padx=10, pady=5)
        inputs[feature] = cb
    elif feature == "flag":
        cb = ttk.Combobox(form_frame, values=flag_options)
        cb.set(flag_options[0])
        cb.grid(row=idx, column=1, padx=10, pady=5)
        inputs[feature] = cb
    else:
        entry = tk.Entry(form_frame)
        entry.insert(0, "0")
        entry.grid(row=idx, column=1, padx=10, pady=5)
        inputs[feature] = entry

# Prediction
def predict():
    try:
        row = []
        for f in feature_names:
            val = inputs[f].get()
            if f == "protocol_type":
                val = le_protocol.transform([val])[0]
            elif f == "service":
                val = le_service.transform([val])[0]
            elif f == "flag":
                val = le_flag.transform([val])[0]
            else:
                val = float(val)
            row.append(val)

        scaled = scaler.transform([row])
        prediction = model.predict(scaled)[0]
        result = "🚨 Attack" if prediction == 1 else "✅ Normal"
        messagebox.showinfo("Prediction", f"Result: {result}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Real-time log area
log_label = tk.Label(form_frame, text="Real-Time Logs", fg="cyan", bg="black", font=("Courier", 12, "bold"))
log_label.grid(row=len(feature_names)+1, column=0, columnspan=2, pady=(20, 5))

log_text = tk.Text(form_frame, height=15, width=80, bg="black", fg="lightgreen")
log_text.grid(row=len(feature_names)+2, column=0, columnspan=2, padx=10)

log_scroll = tk.Scrollbar(form_frame, command=log_text.yview)
log_text.configure(yscrollcommand=log_scroll.set)
log_scroll.grid(row=len(feature_names)+2, column=2, sticky="ns")

# Real-time monitoring thread
def monitor_csv(filepath):
    log_text.insert(tk.END, f"\n📡 Monitoring started...\n")
    df = pd.read_csv(filepath)

    for i, row in df.iterrows():
        try:
            row_list = []
            for f in feature_names:
                val = row[f]
                if f == "protocol_type":
                    val = le_protocol.transform([val])[0]
                elif f == "service":
                    val = le_service.transform([val])[0]
                elif f == "flag":
                    val = le_flag.transform([val])[0]
                row_list.append(val)

            scaled = scaler.transform([row_list])
            prediction = model.predict(scaled)[0]
            status = " Attack" if prediction == 1 else " Normal"
            log_text.insert(tk.END, f"[{i+1}] {status}\n")
            log_text.see(tk.END)
            time.sleep(1)

        except Exception as e:
            log_text.insert(tk.END, f"[{i+1}]  Error: {str(e)}\n")

def extract_features_from_packet(pkt):
    try:
        features = [0] * len(feature_names)

        # Example: Dummy values for simplicity
        features[0] = 0  # duration
        features[1] = le_protocol.transform(["tcp"])[0] if pkt.haslayer(TCP) else le_protocol.transform(["udp"])[0] if pkt.haslayer(UDP) else le_protocol.transform(["icmp"])[0]
        features[2] = le_service.transform(["http"])  # example service, can be improved
        features[3] = le_flag.transform(["SF"])       # dummy flag, improve with logic

        features[4] = len(pkt[IP].payload) if pkt.haslayer(IP) else 0  # src_bytes
        features[5] = 0  # dst_bytes

        # All remaining features default to 0
        scaled = scaler.transform([features])
        pred = model.predict(scaled)[0]
        result = " Attack" if pred == 1 else " Normal"
        log_text.insert(tk.END, f"[LIVE] {pkt[IP].src} → {pkt[IP].dst} : {result}\n")
        log_text.see(tk.END)

    except Exception as e:
        log_text.insert(tk.END, f"[LIVE]  Error: {str(e)}\n")
        log_text.see(tk.END)

def start_packet_sniffing():
    log_text.insert(tk.END, "📡 Live sniffing started...\n")
    log_text.see(tk.END)
    sniff(filter="ip", prn=extract_features_from_packet, store=0)


# Start monitoring
def start_monitoring():
    file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
    if not file_path:
        return
    thread = threading.Thread(target=monitor_csv, args=(file_path,), daemon=True)
    thread.start()

def start_sniffing_thread(s):
    thread = threading.Thread(target=start_packet_sniffing, daemon=True)
    thread.start()


# Buttons
tk.Button(form_frame, text="Predict", command=predict, bg="blue", fg="white").grid(row=len(feature_names), column=0, pady=10)
tk.Button(form_frame, text="Start Monitoring", command=start_monitoring, bg="orange", fg="black").grid(row=len(feature_names), column=1, pady=10)
tk.Button(form_frame, text="Live Sniffing", command=start_sniffing_thread, bg="green", fg="white").grid(row=len(feature_names)+3, column=0, columnspan=2, pady=10)


# Scroll behavior
form_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

root.mainloop()
