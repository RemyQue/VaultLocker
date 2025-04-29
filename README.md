# OpenSSL File Locker (AES-256 + RSA Hybrid Encryption)

This project is a C++-based file encryption tool that demonstrates hybrid encryption using AES-256-CBC and RSA via OpenSSL's EVP API. It is designed for educational purposes to explore cryptographic operations, WinAPI usage, and secure key handling.

---

## Disclaimer

This tool is for educational and research purposes **only**. It demonstrates concepts such as file encryption, secure key lifecycle management, and filesystem traversal in C++. Misuse of this tool is strictly discouraged.

---

## Features

- Hybrid Encryption:
  - AES-256-CBC per file.
  - A single session AES key is encrypted using a hardcoded RSA public key (PEM format).
- Per-file Initialization Vectors (IVs):
  - Unique IV per file, prepended to the encrypted data.
- Key Lifecycle Management:
  - AES key is securely cleansed from memory after use with `OPENSSL_cleanse`.
- Targeted File Encryption:
  - Recursively walks user directories and encrypts files matching predefined extensions.
  - Prioritizes key directories (Desktop, Documents, etc.).
  - Walks all drives from A-Z as fallback.
- File Extensions Filter:
  - Only targets files with specific extensions (e.g., `.docx`, `.pdf`, `.jpg`, etc.).
- System Integration:
  - Changes desktop wallpaper from an embedded resource.
  - Drops a `.txt` notification to the desktop.
- Silent Failover:
  - All major operations return gracefully on failure (no crashes).
- Duplicate Protection:
  - Basic mutex prevents duplicate execution.
- Cleanup:
  - Deletes temporary wallpaper file after applying it.

---

## Technical Overview

### Key Handling

- A random 256-bit AES key is generated per session.
- The AES key is encrypted with an RSA public key (hardcoded PEM) and saved to a binary file.
- Per-file AES encryption uses a unique IV generated via OpenSSL’s `RAND_bytes`.

### File Encryption Logic

- Recursively walks directories via `std::filesystem`.
- Only encrypts files matching allowed extensions.
- Appends `.VAULT` to encrypted files.
- Writes encrypted data with the IV prepended to allow future decryption.

### System Modifications

- Wallpaper is changed using `SystemParametersInfo` from a compiled resource.
- Text note is dropped to the user's desktop.

### VSS Removal

- Optional: Deletes Windows Volume Shadow Copies using ShadowCopyManager techniques.
  (Reference: [VSS Removal Thread](https://sinister.ly/Thread-Tutorial-Free-Secure-Stealth-Shadow-Copy-VSS-Removal-On-windows-10-11))

---

## Suggestions for Improvement

- Multithreading:
  - Current implementation is single-threaded.
  - Improve performance by leveraging `std::thread` and querying CPU core count to parallelize encryption.
- Partial Encryption:
  - Instead of encrypting entire files, consider partial encryption (e.g., header + chunks) to increase speed for large files.
- Unicode Support:
  - Text file handling assumes ANSI via `lstrlenA`. Consider supporting UTF-8 or UTF-16.
- Key Storage Security:
  - Key is stored to disk once encrypted, but lifecycle management can be further improved.

---

## Learning Objectives

This project serves as a hands-on example to learn:

- OpenSSL EVP API for AES and RSA
- Safe cryptographic key generation and lifecycle
- Per-file IV handling and hybrid encryption design
- Recursive file system traversal with `std::filesystem`
- WinAPI interactions (wallpaper changes, mutexes, file writing, etc.)
