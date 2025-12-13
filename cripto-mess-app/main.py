import tkinter as tk
from tkinter import messagebox, scrolledtext
from crypto import generateCSIDHKeys, computeCSIDHSharedSecret, aes256Encrypt, aes256Decrypt, rainbowSign

class CryptoMessApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CryptoMess PQC")
        self.mode = None
        self.username = ""
        self.serverPort = "8888"
        self.clientIP = "localhost"
        self.clientPort = "8888"
        self.sharedSecret = None
        self.csidhKeys = generateCSIDHKeys()
        self.messages = []
        self.onlineUsers = []
        self.keyExchangeCompleted = False

        self.build_mode_selection()

    # --- Mode selection ---
    def build_mode_selection(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        frame = tk.Frame(self.root, padx=20, pady=20)
        frame.pack()

        tk.Label(frame, text="CryptoMess PQC", font=("Arial", 18)).pack(pady=10)

        tk.Button(frame, text="Run as Server", width=20, command=self.start_server).pack(pady=5)
        tk.Button(frame, text="Run as Client", width=20, command=self.build_client_login).pack(pady=5)

    # --- Server ---
    def start_server(self):
        self.mode = "server"
        self.onlineUsers = [{"name": "Client_001", "csidhPublicKey": generateCSIDHKeys()["publicKey"]}]
        self.build_chat_interface()
        self.perform_key_exchange(self.onlineUsers[0])

    # --- Client login ---
    def build_client_login(self):
        self.mode = "client"
        for widget in self.root.winfo_children():
            widget.destroy()

        frame = tk.Frame(self.root, padx=20, pady=20)
        frame.pack()

        tk.Label(frame, text="Client Login", font=("Arial", 16)).pack(pady=10)

        tk.Label(frame, text="Username").pack()
        self.usernameEntry = tk.Entry(frame)
        self.usernameEntry.pack(pady=5)

        tk.Label(frame, text="Server IP").pack()
        self.clientIPEntry = tk.Entry(frame)
        self.clientIPEntry.insert(0, "localhost")
        self.clientIPEntry.pack(pady=5)

        tk.Label(frame, text="Server Port").pack()
        self.clientPortEntry = tk.Entry(frame)
        self.clientPortEntry.insert(0, "8888")
        self.clientPortEntry.pack(pady=5)

        tk.Button(frame, text="Login", command=self.login_client).pack(pady=10)

    def login_client(self):
        self.username = self.usernameEntry.get().strip()
        self.clientIP = self.clientIPEntry.get().strip()
        self.clientPort = self.clientPortEntry.get().strip()

        if not self.username:
            messagebox.showwarning("Warning", "Username cannot be empty")
            return

        self.onlineUsers = [{"name": "Server", "csidhPublicKey": generateCSIDHKeys()["publicKey"]}]
        self.build_chat_interface()
        self.perform_key_exchange(self.onlineUsers[0])

    # --- Chat interface ---
    def build_chat_interface(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        # Chat display
        self.chatDisplay = scrolledtext.ScrolledText(self.root, state="disabled", width=60, height=20)
        self.chatDisplay.pack(padx=10, pady=10)

        # Input
        self.msgEntry = tk.Entry(self.root, width=50)
        self.msgEntry.pack(side="left", padx=10, pady=5)
        self.msgEntry.bind("<Return>", lambda e: self.send_message())

        tk.Button(self.root, text="Send", command=self.send_message).pack(side="left", padx=5)

    # --- Key Exchange Simulation ---
    def perform_key_exchange(self, user):
        self.add_system_message(f"Starting key exchange with {user['name']}...")
        self.sharedSecret = computeCSIDHSharedSecret(self.csidhKeys["privateKey"], user["csidhPublicKey"])
        self.keyExchangeCompleted = True
        self.add_system_message(f"Shared secret established: {self.sharedSecret[:16]}...")

    # --- Send message ---
    def send_message(self):
        if not self.keyExchangeCompleted:
            self.add_system_message("Key exchange not completed yet!")
            return

        msg = self.msgEntry.get().strip()
        if not msg:
            return
        self.msgEntry.delete(0, "end")

        # Sign & Encrypt
        signature = rainbowSign(msg, self.csidhKeys["privateKey"])
        encrypted = aes256Encrypt(msg, self.sharedSecret)

        self.add_message(self.username if self.mode=="client" else "Server", msg, encrypted, signature)
        # Simulate reply
        self.root.after(1000, lambda: self.add_message(
            "Server" if self.mode=="client" else "Client_001",
            f"Received: {msg}", aes256Encrypt(f"Received: {msg}", self.sharedSecret), rainbowSign(f"Received: {msg}", self.csidhKeys["privateKey"])
        ))

    # --- Display messages ---
    def add_message(self, sender, msg, encrypted, signature):
        self.chatDisplay.config(state="normal")
        self.chatDisplay.insert("end", f"{sender}: {msg}\n")
        self.chatDisplay.insert("end", f"  Encrypted: {encrypted['ciphertext'][:20]}...\n")
        self.chatDisplay.insert("end", f"  Signature: {signature[:20]}...\n\n")
        self.chatDisplay.config(state="disabled")
        self.chatDisplay.yview("end")

    def add_system_message(self, msg):
        self.chatDisplay.config(state="normal")
        self.chatDisplay.insert("end", f"[SYSTEM] {msg}\n")
        self.chatDisplay.config(state="disabled")
        self.chatDisplay.yview("end")

# --- Run app ---
if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoMessApp(root)
    root.mainloop()
