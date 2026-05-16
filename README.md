# PNASystems: Encryption Website

A secure, client-side encryption and decryption web application. All cryptographic operations run entirely in your browser — no data is ever sent to a server.

## Features

- **Encrypt Text** — Encrypt plaintext with a password using all 8 encryption methods chained together
- **Decrypt Text** — Decrypt Base64-encoded ciphertext back to plaintext
- **Encrypt File** — Encrypt any file and download the encrypted result
- **Decrypt File** — Decrypt a previously encrypted file and download the original
- **License** — View the full OSK License and third-party credits

## Encryption Pipeline

All encryption methods are applied in sequence (chained pipeline). Each layer derives its own unique salt and keys from the password using PBKDF2-HMAC-SHA256 with 100,000 iterations.

**Encryption order:**
```
AES-256-GCM → Fernet → ChaCha20-Poly1305 → XChaCha20-Poly1305 → TripleDES-192-CBC + HMAC → Rabbit + HMAC → Blowfish + HMAC → Base85
```

**Decryption order (reverse):**
```
Base85 decode → Blowfish → Rabbit → TripleDES → XChaCha20 → ChaCha20 → Fernet → AES-256-GCM
```

### Supported Methods

| Method | Description |
|---|---|
| AES-256-GCM | Authenticated encryption using Web Crypto API |
| Fernet | AES-128-CBC + HMAC-SHA256 (Fernet specification) |
| ChaCha20-Poly1305 | Modern stream cipher with authentication (pure JS, RFC 8439) |
| XChaCha20-Poly1305 | Extended-nonce variant of ChaCha20-Poly1305 |
| TripleDES-192-CBC | Triple DES with CBC mode + HMAC-SHA256 |
| Rabbit | Fast stream cipher + HMAC-SHA256 |
| Blowfish | Block cipher + HMAC-SHA256 |
| Base85 | Ascii85 encoding layer (final encoding step) |

## Deployment to GitHub Pages

1. Push the contents of this folder to a GitHub repository
2. Go to **Settings > Pages** in your repository
3. Set the source to your default branch and `/ (root)`
4. Your site will be live at `https://<username>.github.io/<repo>/`

## File Structure

```
index.html          — Main page with tabbed UI (5 tabs)
styles.css          — Dark mode styles with animated gradient background
app.js              — Application logic, event handlers, detailed console logging
crypto-engine.js    — Core encryption/decryption engine with full pipeline
fernet.js           — Fernet algorithm implementation
base85.js           — Base85 (Ascii85) encoding/decoding utility
crypto-js.js        — CryptoJS library (local copy, MIT License)
LICENSE             — OSK License v1.3
README.md           — This file
```

## Dependencies

- **CryptoJS** (v4.2.0) — Local copy included. Provides AES, TripleDES, Rabbit, Blowfish, HMAC, and PBKDF2. MIT License.

All other cryptographic operations (ChaCha20-Poly1305, XChaCha20-Poly1305, AES-256-GCM) are implemented using the Web Crypto API or pure JavaScript. No external network requests are made.

## Security Notes

- All encryption keys are derived from your password using PBKDF2-HMAC-SHA256 with 100,000 iterations
- A unique random salt is generated for each encryption layer
- All authenticated encryption methods include integrity verification
- No data leaves your device — everything runs client-side
- Detailed console logging is available for debugging (open browser DevTools)

## Console Logging

Open your browser's Developer Tools (F12) to see detailed logs including:
- Dependency verification on load
- Every encryption/decryption layer entry/exit with byte counts
- Key derivation details
- HMAC verification results
- Serialization/deserialization parsing
- File read/write operations
- All errors with full stack traces

## License

PNASystems: OSK License Version 1.3
Original Creator: Roblox User "Goplop0959"

See the [LICENSE](LICENSE) file or the **License** tab in the app for full terms.
