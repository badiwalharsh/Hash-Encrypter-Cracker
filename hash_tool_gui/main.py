import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import hashlib
import urllib.request
import threading
import time

# === Functions ===

def generate_hash():
    text = input_text.get()
    algo = hash_algo.get()

    if not text:
        messagebox.showwarning("Input Error", "Please enter text to hash.")
        return

    try:
        hash_func = getattr(hashlib, algo)
        hashed = hash_func(text.encode()).hexdigest()
        output_hash.set(hashed)
    except AttributeError:
        messagebox.showerror("Algorithm Error", "Invalid hashing algorithm.")

def check_hash():
    text = input_text.get()
    hash_value = output_hash.get()
    algo = hash_algo.get()

    if not text or not hash_value:
        messagebox.showwarning("Input Error", "Both input and hash value required.")
        return

    try:
        hash_func = getattr(hashlib, algo)
        computed = hash_func(text.encode()).hexdigest()
        if computed == hash_value:
            messagebox.showinfo("Match Found", "✅ Input matches the hash!")
        else:
            messagebox.showerror("No Match", "❌ Input does NOT match the hash.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def select_file():
    filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if filepath:
        url_input.set(filepath)
        is_url.set(False)

def save_result(found_word, hash_value, algo_used, duration):
    with open("cracked_results.txt", "a") as f:
        f.write(f"Cracked [{algo_used.upper()}]: {hash_value} = '{found_word}' (in {duration:.2f} sec)\n")

def start_crack():
    progress_bar["value"] = 0
    crack_button.config(state="disabled")
    threading.Thread(target=crack_hash).start()

def crack_hash():
    hash_to_crack = crack_hash_input.get().strip()
    algo = hash_algo.get()
    wordlist_source = url_input.get().strip()

    # Autofill from output hash if empty
    if not hash_to_crack and output_hash.get():
        hash_to_crack = output_hash.get()

    if not hash_to_crack:
        messagebox.showwarning("Input Error", "Please enter a hash to crack.")
        crack_button.config(state="normal")
        return

    try:
        hash_func = getattr(hashlib, algo)

        # Load wordlist (from URL or local)
        if is_url.get():
            response = urllib.request.urlopen(wordlist_source)
            wordlist = response.read().decode('utf-8').splitlines()
        else:
            with open(wordlist_source, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = f.read().splitlines()

        total = len(wordlist)
        start_time = time.time()
        for idx, word in enumerate(wordlist):
            computed = hash_func(word.encode()).hexdigest()
            progress_bar["value"] = (idx + 1) / total * 100
            root.update_idletasks()

            if computed == hash_to_crack:
                end_time = time.time()
                duration = end_time - start_time
                messagebox.showinfo("Cracked!", f"✅ Hash matched with: '{word}'\n⏱ Time taken: {duration:.2f} sec")
                save_result(word, hash_to_crack, algo, duration)
                crack_button.config(state="normal")
                return

        end_time = time.time()
        messagebox.showerror("Failed", f"❌ Could not crack the hash.\n⏱ Time taken: {end_time - start_time:.2f} sec")

    except Exception as e:
        messagebox.showerror("Error", str(e))

    crack_button.config(state="normal")

# === GUI Setup ===
root = tk.Tk()
root.title("🔐 Hash Encrypter & Cracker - by Harsh Badiwal")
root.geometry("620x640")
root.resizable(False, False)

# Variables
input_text = tk.StringVar()
output_hash = tk.StringVar()
crack_hash_input = tk.StringVar()
hash_algo = tk.StringVar(value="sha256")
url_input = tk.StringVar()
is_url = tk.BooleanVar(value=True)

# === Styling ===
style = ttk.Style()
style.configure("TButton", font=("Segoe UI", 10), padding=6)
style.configure("TLabel", font=("Segoe UI", 10))
style.configure("TEntry", padding=5)

# === Layout ===
ttk.Label(root, text="🔐 Enter Text to Hash:").pack(pady=5)
ttk.Entry(root, textvariable=input_text, width=70).pack()

ttk.Label(root, text="🧮 Select Hash Algorithm:").pack(pady=5)
ttk.Combobox(root, textvariable=hash_algo, values=["md5", "sha1", "sha256", "sha512"], state="readonly", width=20).pack()

ttk.Button(root, text="🔒 Generate Hash", command=generate_hash).pack(pady=10)

ttk.Label(root, text="📤 Output Hash (from input):").pack(pady=5)
ttk.Entry(root, textvariable=output_hash, width=70).pack()

ttk.Button(root, text="🧾 Check If Input Matches Hash", command=check_hash).pack(pady=5)

ttk.Label(root, text="🔍 Enter Hash to Crack:").pack(pady=5)
ttk.Entry(root, textvariable=crack_hash_input, width=70).pack()

ttk.Label(root, text="🌐 Enter Wordlist URL or Select Local File:").pack(pady=5)
ttk.Entry(root, textvariable=url_input, width=70).pack(pady=3)
ttk.Checkbutton(root, text="Use online URL", variable=is_url).pack()

ttk.Button(root, text="📁 Select Local Wordlist", command=select_file).pack(pady=2)

ttk.Button(root, text="💥 Crack Hash", command=start_crack, style="TButton").pack(pady=10)
crack_button = root.children[list(root.children)[-1]]  # Reference to disable/enable during cracking

ttk.Label(root, text="⏳ Cracking Progress:").pack(pady=5)
progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=5)

ttk.Label(root, text="By Harsh Badiwal | Security Engineer", foreground="gray").pack(side="bottom", pady=20)

root.mainloop()
