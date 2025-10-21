#!/usr/bin/env python
# coding: utf-8

# In[7]:


import os
import time
import statistics
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# ---------------------------
# Utility: Generate test files
# ---------------------------
def generate_test_files(sizes_kb):
    files = []
    for size in sizes_kb:
        filename = f"file_{size}KB.bin"
        with open(filename, "wb") as f:
            f.write(os.urandom(size * 1024))
        files.append(filename)
    return files

# ---------------------------
# Hybrid Encryption (RSA + AES)
# ---------------------------
def hybrid_encrypt(file_path, public_key):
    # Generate random 16-byte AES key
    session_key = AESGCM.generate_key(bit_length=128)
    
    # Encrypt file with AES-GCM
    aesgcm = AESGCM(session_key)
    with open(file_path, "rb") as f:
        plaintext = f.read()
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    # Encrypt AES key with RSA public key
    enc_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return enc_session_key, nonce, ciphertext

# ---------------------------
# Hybrid Decryption (RSA + AES)
# ---------------------------
def hybrid_decrypt(enc_session_key, nonce, ciphertext, private_key):
    # Decrypt AES session key using RSA private key
    session_key = private_key.decrypt(
        enc_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Decrypt file using AES-GCM
    aesgcm = AESGCM(session_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext

# ---------------------------
# Benchmark Encryption
# ---------------------------
def benchmark_encryption(file_path, public_key):
    start = time.time()
    hybrid_encrypt(file_path, public_key)
    return time.time() - start

# ---------------------------
# Benchmark Decryption
# ---------------------------
def benchmark_decryption(file_path, private_key):
    enc_session_key, nonce, ciphertext = hybrid_encrypt(file_path, private_key.public_key())
    start = time.time()
    hybrid_decrypt(enc_session_key, nonce, ciphertext, private_key)
    return time.time() - start

# ---------------------------
# Experiment Runner
# ---------------------------
def run_experiments(output_csv, rsa_sizes=[2048, 3072, 4096], file_sizes_kb=[100, 500, 1000, 3000, 5000],
                    repeats=3, mode="encryption"):
    results = []
    files = generate_test_files(file_sizes_kb)

    for key_size in rsa_sizes:
        print(f"Generating RSA keys with size {key_size} bits...")
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
        public_key = key.public_key()

        for file_path in files:
            print(f"Benchmarking file {file_path} with RSA {key_size}-bit in {mode} mode...")
            times = []

            for _ in range(repeats):
                if mode == "encryption":
                    times.append(benchmark_encryption(file_path, public_key))
                else:
                    times.append(benchmark_decryption(file_path, key))

            avg_time = sum(times) / repeats
            results.append({
                "RSA_Size": key_size,
                "File_Size_KB": os.path.getsize(file_path) / 1024,
                f"{mode.capitalize()}_Time_s": avg_time
            })

    df = pd.DataFrame(results)
    df.to_csv(output_csv, index=False, mode='w')
    print(f"Results saved to {output_csv}")
    return df

# ---------------------------
# Plotting Utility
# ---------------------------
def plot_results(csv_file, title="Encryption Time", ylabel="Time (seconds)", output_file="plot.png"):
    df = pd.read_csv(csv_file)
    plt.figure(figsize=(8, 5))

    rsa_sizes = sorted(df['RSA_Size'].unique())
    for rsa_size in rsa_sizes:
        data = df[df['RSA_Size'] == rsa_size]
        plt.plot(data['File_Size_KB'], data.iloc[:, 2], marker='o', label=f"RSA {rsa_size} bits")

    plt.xlabel("File Size (KB)")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_file)
    print(f"Plot saved as {output_file}")
    plt.close()

# ---------------------------
# Main Execution
# ---------------------------
if __name__ == "__main__":
    repeats = 3

    encryption_csv = "encryption_results.csv"
    print("\n=== Running Encryption Experiments ===")
    run_experiments(output_csv=encryption_csv, repeats=repeats, mode="encryption")
    plot_results(encryption_csv, title="Hybrid RSA + AES Encryption Time", ylabel="Encryption Time (s)",
                 output_file="encryption_plot.png")

    decryption_csv = "decryption_results.csv"
    print("\n=== Running Decryption Experiments ===")
    run_experiments(output_csv=decryption_csv, repeats=repeats, mode="decryption")
    plot_results(decryption_csv, title="Hybrid RSA + AES Decryption Time", ylabel="Decryption Time (s)",
                 output_file="decryption_plot.png")

    print("\nAll experiments completed successfully!")


# In[ ]:




