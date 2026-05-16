/*
PNASystems: OSK License
Version 1.3
Copyright © Roblox User "Goplop0959"
Original Creator and License Author: Roblox UserName "Goplop0959"
Discord: asherploploto
GitHub: Goplop0959

1. Grant of Permission
Permission is granted to any individual or entity ("the User") to use, copy,
modify, merge, publish, and distribute this software ("the Software"),
including both the original version and any modified versions, subject to
the conditions of this License. These permissions apply to all copies,
derivatives, and redistributions of the Software in any form.

2. Required Attribution
The following attribution requirements apply to all redistributions:
    - The original creator must always be credited as:
          "Original Creator: Roblox User Goplop0959"
    - All credits must appear at the top of the script, before any executable code.
    - If the Software is modified, the modifier must be credited as:
          "Modified By: [Modifier's Name]"
    - If a modified version is further modified and redistributed, all contributors
      in the chain must be credited, including:
          1. The original creator (Goplop0959)
          2. All previous modifiers
          3. The most recent modifier
    - The Credits section is the ONLY part of this License that may be edited,
      and ONLY for the purpose of adding your own name when you modify the
      Software. You may NOT remove, alter, or reorder any existing names.

3. Modification and Redistribution
Users may modify the Software and distribute modified versions only if:
    - All required credits are preserved exactly as described.
    - This License text remains included and unmodified.
    - The modified version clearly indicates that it has been modified.
    - Modification of the License itself is strictly prohibited except by the
      original creator, Roblox User "Goplop0959".
Redistribution is permitted only when these conditions are met.

4. Prohibition on Obfuscation
To preserve transparency and maintain the integrity of the attribution chain:
    - The Software may not be obfuscated in any way that renders the code unreadable,
      partially unreadable, or intentionally difficult to interpret.
    - This includes, but is not limited to:
          * Symbol renaming intended to obscure meaning
          * Control-flow flattening
          * Encoded or encrypted source
          * Automated obfuscation tools
    - Exception:
          Unusual, unconventional, or "questionable" coding style or comment style
          does NOT count as obfuscation, provided the code remains reasonably readable
          by a human.

5. Prohibition on Monetary Sale
The Software, whether original or modified, may not be sold for monetary value of
any kind, including:
    - Real-world currency
    - Virtual currency
    - In-game currency
    - Tokens, credits, or any exchangeable digital asset
Exception:
    The Software may be included as a dependency within a paid product, provided:
        - The Software itself is not sold independently.
        - All required credits remain intact.
        - This License remains included and unmodified.

6. No Warranty
The Software is provided "as is," without warranty of any kind, express or implied.
The original creator and all contributors shall not be liable for any damages
arising from the use of the Software.

7. Acceptance of Terms
By using, modifying, or distributing the Software, the User acknowledges and agrees
to all terms and conditions of the PNAsystems: OSK License. Use of the Software
constitutes full acceptance of this License.

---------------------------------------------------------
Credits:
Original Creator: Roblox User "Goplop0959"
Discord: asherploploto
GitHub: Goplop0959
*/

/**
 * Crypto Engine - Full encryption pipeline.
 *
 * ALL encryption methods are applied in sequence (chained pipeline).
 * Encryption order:  AES-256-GCM → Fernet → ChaCha20-Poly1305 → XChaCha20-Poly1305
 *                    → TripleDES-CBC+HMAC → Rabbit+HMAC → Blowfish+HMAC → Base85
 * Decryption order:  Base85 decode → Blowfish → Rabbit → TripleDES → XChaCha20
 *                    → ChaCha20 → Fernet → AES-256-GCM
 *
 * Each layer derives its own unique salt and keys from the password.
 * All metadata (salts, nonces, tags) is stored in the output header.
 *
 * Binary Output Format:
 *   [PNAE][ver][numLayers]
 *   For each layer: [methodId:1][saltLen:1][salt:var][nonceLen:1][nonce:var][tagLen:2][tag:var]
 *   [finalCiphertext]
 *
 * Key Derivation:
 *   - PBKDF2-HMAC-SHA256 via WebCrypto
 *   - 16-byte random salt per layer
 *   - 100,000 iterations
 *   - Derives 32 bytes encryption key + 32 bytes HMAC key = 64 bytes
 */

(function (global) {
    "use strict";

    // ============================================================
    // Method identifiers and metadata
    // ============================================================

    var METHOD_AES256_GCM = 0;
    var METHOD_FERNET = 1;
    var METHOD_BASE85 = 2;
    var METHOD_CHACHA20_POLY1305 = 3;
    var METHOD_XCHACHA20_POLY1305 = 4;
    var METHOD_TRIPLEDES_CBC = 5;
    var METHOD_RABBIT = 6;
    var METHOD_BLOWFISH = 7;

    // Encryption pipeline order (all methods applied sequentially)
    var ENCRYPT_PIPELINE = [
        METHOD_AES256_GCM,
        METHOD_FERNET,
        METHOD_CHACHA20_POLY1305,
        METHOD_XCHACHA20_POLY1305,
        METHOD_TRIPLEDES_CBC,
        METHOD_RABBIT,
        METHOD_BLOWFISH,
        METHOD_BASE85
    ];

    // Decryption pipeline order (reverse of encryption)
    var DECRYPT_PIPELINE = [
        METHOD_BASE85,
        METHOD_BLOWFISH,
        METHOD_RABBIT,
        METHOD_TRIPLEDES_CBC,
        METHOD_XCHACHA20_POLY1305,
        METHOD_CHACHA20_POLY1305,
        METHOD_FERNET,
        METHOD_AES256_GCM
    ];

    var METHOD_INFO = {
        0: { name: "AES-256-GCM", nonceLen: 12, tagLen: 16, isAEAD: true },
        1: { name: "Fernet", nonceLen: 0, tagLen: 0, isAEAD: true, isFernet: true },
        2: { name: "Base85", nonceLen: 0, tagLen: 0, isAEAD: false, isEncoding: true },
        3: { name: "ChaCha20-Poly1305", nonceLen: 12, tagLen: 16, isAEAD: true },
        4: { name: "XChaCha20-Poly1305", nonceLen: 24, tagLen: 16, isAEAD: true },
        5: { name: "TripleDES-192-CBC", nonceLen: 8, tagLen: 32, isAEAD: false },
        6: { name: "Rabbit", nonceLen: 8, tagLen: 32, isAEAD: false },
        7: { name: "Blowfish", nonceLen: 8, tagLen: 32, isAEAD: false }
    };

    var PBKDF2_ITERATIONS = 100000;
    var SALT_LENGTH = 16;
    var HMAC_KEY_LENGTH = 32;
    var ENCRYPTION_KEY_LENGTH = 32;
    var DERIVED_KEY_LENGTH = ENCRYPTION_KEY_LENGTH + HMAC_KEY_LENGTH;
    var MAGIC = [0x50, 0x4E, 0x41, 0x45]; // "PNAE"
    var VERSION = 0x01;

    // ============================================================
    // Utility Functions
    // ============================================================

    function randomBytes(length) {
        var arr = new Uint8Array(length);
        crypto.getRandomValues(arr);
        return arr;
    }

    function uint8ArrayToBase64(data) {
        var binary = '';
        for (var i = 0; i < data.length; i++) {
            binary += String.fromCharCode(data[i]);
        }
        return btoa(binary);
    }

    function base64ToUint8Array(b64) {
        var binary = atob(b64.trim());
        var arr = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            arr[i] = binary.charCodeAt(i);
        }
        return arr;
    }

    function utf8ToUint8Array(str) {
        return new TextEncoder().encode(str);
    }

    function uint8ArrayToUtf8(arr) {
        return new TextDecoder().decode(arr);
    }

    function concatUint8Arrays() {
        var totalLen = 0;
        for (var i = 0; i < arguments.length; i++) {
            totalLen += arguments[i].length;
        }
        var result = new Uint8Array(totalLen);
        var offset = 0;
        for (var i = 0; i < arguments.length; i++) {
            result.set(arguments[i], offset);
            offset += arguments[i].length;
        }
        return result;
    }

    function log(tag, msg, data) {
        var prefix = "[CryptoEngine:" + tag + "]";
        if (data !== undefined) {
            console.log(prefix, msg, data);
        } else {
            console.log(prefix, msg);
        }
    }

    function logError(tag, msg, err) {
        var prefix = "[CryptoEngine:" + tag + "]";
        if (err instanceof Error) {
            console.error(prefix, msg, err.message, err.stack);
        } else {
            console.error(prefix, msg, err);
        }
    }

    // ============================================================
    // Key Derivation (PBKDF2-HMAC-SHA256 via WebCrypto)
    // ============================================================

    async function deriveKeys(password, salt) {
        try {
            log("deriveKeys", "Deriving keys with PBKDF2-HMAC-SHA256, iterations=" + PBKDF2_ITERATIONS + ", salt=" + uint8ArrayToBase64(salt).substring(0, 20) + "...");

            var keyMaterial = await crypto.subtle.importKey(
                "raw",
                utf8ToUint8Array(password),
                "PBKDF2",
                false,
                ["deriveBits"]
            );

            var derivedBits = await crypto.subtle.deriveBits(
                {
                    name: "PBKDF2",
                    salt: salt,
                    iterations: PBKDF2_ITERATIONS,
                    hash: "SHA-256"
                },
                keyMaterial,
                DERIVED_KEY_LENGTH * 8
            );

            var derived = new Uint8Array(derivedBits);
            log("deriveKeys", "Key derivation successful. Derived " + derived.length + " bytes.");

            return {
                encryptionKey: derived.slice(0, ENCRYPTION_KEY_LENGTH),
                hmacKey: derived.slice(ENCRYPTION_KEY_LENGTH)
            };
        } catch (err) {
            logError("deriveKeys", "Key derivation failed", err);
            throw err;
        }
    }

    // ============================================================
    // HMAC-SHA256 (via WebCrypto)
    // ============================================================

    async function computeHMAC(key, data) {
        try {
            var cryptoKey = await crypto.subtle.importKey(
                "raw",
                key,
                { name: "HMAC", hash: "SHA-256" },
                false,
                ["sign"]
            );
            var signature = await crypto.subtle.sign("HMAC", cryptoKey, data);
            return new Uint8Array(signature);
        } catch (err) {
            logError("computeHMAC", "HMAC computation failed", err);
            throw err;
        }
    }

    async function verifyHMAC(key, data, expectedTag) {
        try {
            var actualTag = await computeHMAC(key, data);
            if (actualTag.length !== expectedTag.length) {
                log("verifyHMAC", "HMAC length mismatch: expected " + expectedTag.length + ", got " + actualTag.length);
                return false;
            }
            var diff = 0;
            for (var i = 0; i < actualTag.length; i++) {
                diff |= actualTag[i] ^ expectedTag[i];
            }
            var result = diff === 0;
            log("verifyHMAC", "HMAC verification: " + (result ? "PASSED" : "FAILED"));
            return result;
        } catch (err) {
            logError("verifyHMAC", "HMAC verification failed", err);
            throw err;
        }
    }

    // ============================================================
    // AES-256-GCM (WebCrypto)
    // ============================================================

    async function aes256GcmEncrypt(data, key, nonce) {
        try {
            log("aes256GcmEncrypt", "Encrypting " + data.length + " bytes with AES-256-GCM");
            var cryptoKey = await crypto.subtle.importKey(
                "raw", key, { name: "AES-GCM" }, false, ["encrypt"]
            );
            var encrypted = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv: nonce },
                cryptoKey,
                data
            );
            var result = new Uint8Array(encrypted);
            var ciphertext = result.slice(0, result.length - 16);
            var tag = result.slice(result.length - 16);
            log("aes256GcmEncrypt", "Encryption successful. Ciphertext: " + ciphertext.length + " bytes, Tag: " + tag.length + " bytes");
            return { ciphertext: ciphertext, tag: tag };
        } catch (err) {
            logError("aes256GcmEncrypt", "AES-256-GCM encryption failed", err);
            throw err;
        }
    }

    async function aes256GcmDecrypt(data, key, nonce, tag) {
        try {
            log("aes256GcmDecrypt", "Decrypting " + data.length + " bytes with AES-256-GCM");
            var cryptoKey = await crypto.subtle.importKey(
                "raw", key, { name: "AES-GCM" }, false, ["decrypt"]
            );
            var combined = concatUint8Arrays(data, tag);
            var decrypted = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: nonce },
                cryptoKey,
                combined
            );
            var result = new Uint8Array(decrypted);
            log("aes256GcmDecrypt", "Decryption successful. Plaintext: " + result.length + " bytes");
            return result;
        } catch (err) {
            logError("aes256GcmDecrypt", "AES-256-GCM decryption failed — wrong password or corrupted data", err);
            throw new Error("Decryption failed at AES-256-GCM layer: wrong password or corrupted data");
        }
    }

    // ============================================================
    // ChaCha20-Poly1305 (Pure JS, IETF variant - RFC 8439)
    // ============================================================

    function chacha20QuarterRound(state, a, b, c, d) {
        var mask32 = 0xFFFFFFFF;
        state[a] = (state[a] + state[b]) & mask32; state[d] ^= state[a]; state[d] = ((state[d] << 16) | (state[d] >>> 16)) & mask32;
        state[c] = (state[c] + state[d]) & mask32; state[b] ^= state[c]; state[b] = ((state[b] << 12) | (state[b] >>> 20)) & mask32;
        state[a] = (state[a] + state[b]) & mask32; state[d] ^= state[a]; state[d] = ((state[d] << 8) | (state[d] >>> 24)) & mask32;
        state[c] = (state[c] + state[d]) & mask32; state[b] ^= state[c]; state[b] = ((state[b] << 7) | (state[b] >>> 25)) & mask32;
    }

    function chacha20Block(key, counter, nonce) {
        var mask32 = 0xFFFFFFFF;
        var state = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0
        ];

        for (var i = 0; i < 8; i++) {
            state[4 + i] = (key[i * 4]) | (key[i * 4 + 1] << 8) | (key[i * 4 + 2] << 16) | (key[i * 4 + 3] << 24);
        }

        state[12] = counter & mask32;

        state[13] = (nonce[0]) | (nonce[1] << 8) | (nonce[2] << 16) | (nonce[3] << 24);
        state[14] = (nonce[4]) | (nonce[5] << 8) | (nonce[6] << 16) | (nonce[7] << 24);
        state[15] = (nonce[8]) | (nonce[9] << 8) | (nonce[10] << 16) | (nonce[11] << 24);

        var workingState = state.slice();

        for (var r = 0; r < 10; r++) {
            chacha20QuarterRound(workingState, 0, 4, 8, 12);
            chacha20QuarterRound(workingState, 1, 5, 9, 13);
            chacha20QuarterRound(workingState, 2, 6, 10, 14);
            chacha20QuarterRound(workingState, 3, 7, 11, 15);
            chacha20QuarterRound(workingState, 0, 5, 10, 15);
            chacha20QuarterRound(workingState, 1, 6, 11, 12);
            chacha20QuarterRound(workingState, 2, 7, 8, 13);
            chacha20QuarterRound(workingState, 3, 4, 9, 14);
        }

        var output = new Uint8Array(64);
        for (var i = 0; i < 16; i++) {
            var sum = (workingState[i] + state[i]) & mask32;
            output[i * 4] = sum & 0xFF;
            output[i * 4 + 1] = (sum >>> 8) & 0xFF;
            output[i * 4 + 2] = (sum >>> 16) & 0xFF;
            output[i * 4 + 3] = (sum >>> 24) & 0xFF;
        }

        return output;
    }

    function chacha20Crypt(key, nonce, data, initialCounter) {
        if (initialCounter === undefined) initialCounter = 1;
        var output = new Uint8Array(data.length);
        var counter = initialCounter;

        for (var offset = 0; offset < data.length; offset += 64) {
            var block = chacha20Block(key, counter, nonce);
            var chunkLen = Math.min(64, data.length - offset);
            for (var i = 0; i < chunkLen; i++) {
                output[offset + i] = data[offset + i] ^ block[i];
            }
            counter++;
        }

        return output;
    }

    function poly1305(key, data) {
        var r0 = (key[0]) | (key[1] << 8) | (key[2] << 16) | (key[3] << 24);
        var r1 = (key[4]) | (key[5] << 8) | (key[6] << 16) | (key[7] << 24);
        var r2 = (key[8]) | (key[9] << 8) | (key[10] << 16) | (key[11] << 24);
        var r3 = (key[12]) | (key[13] << 8) | (key[14] << 16) | (key[15] << 24);
        var r4 = (key[16]) | (key[17] << 8) | (key[18] << 16) | (key[19] << 24);

        r0 &= 0x3ffffff; r1 &= 0x3ffff03; r2 &= 0x3ffff03; r3 &= 0x3ffff03; r4 &= 0x3ffff03;

        var s0 = (key[20]) | (key[21] << 8) | (key[22] << 16) | (key[23] << 24);
        var s1 = (key[24]) | (key[25] << 8) | (key[26] << 16) | (key[27] << 24);
        var s2 = (key[28]) | (key[29] << 8) | (key[30] << 16) | (key[31] << 24);
        var s3 = (key[32]) | (key[33] << 8) | (key[34] << 16) | (key[35] << 24);

        var h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

        for (var offset = 0; offset < data.length; offset += 16) {
            var blockLen = Math.min(16, data.length - offset);

            var fullBlock = new Uint8Array(17);
            for (var fi = 0; fi < blockLen; fi++) {
                fullBlock[fi] = data[offset + fi];
            }
            fullBlock[blockLen] = 1;

            var b0 = (fullBlock[0]) | (fullBlock[1] << 8) | (fullBlock[2] << 16) | (fullBlock[3] << 24);
            var b1 = (fullBlock[4]) | (fullBlock[5] << 8) | (fullBlock[6] << 16) | (fullBlock[7] << 24);
            var b2 = (fullBlock[8]) | (fullBlock[9] << 8) | (fullBlock[10] << 16) | (fullBlock[11] << 24);
            var b3 = (fullBlock[12]) | (fullBlock[13] << 8) | (fullBlock[14] << 16) | (fullBlock[15] << 24);
            var b4 = (fullBlock[16]);

            b0 &= 0x3ffffff;
            b1 = (b1 >>> 0) & 0x1ffffff;
            b2 &= 0x3ffffff;
            b3 = (b3 >>> 0) & 0x1ffffff;
            b4 &= 0x3ffffff;

            var d0 = h0 * r0 + h1 * (4 * r4) + h2 * (4 * r3) + h3 * (4 * r2) + h4 * (4 * r1) + b0;
            var d1 = h0 * r1 + h1 * r0 + h2 * (4 * r4) + h3 * (4 * r3) + h4 * (4 * r2) + b1;
            var d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * (4 * r4) + h4 * (4 * r3) + b2;
            var d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * (4 * r4) + b3;
            var d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0 + b4;

            var c;
            c = d0 >>> 26; h0 = d0 & 0x3ffffff; d1 += c;
            c = d1 >>> 27; h1 = d1 & 0x1ffffff; d2 += c;
            c = d2 >>> 26; h2 = d2 & 0x3ffffff; d3 += c;
            c = d3 >>> 27; h3 = d3 & 0x1ffffff; d4 += c;
            c = d4 >>> 26; h4 = d4 & 0x3ffffff; h0 += c * 5;
            c = h0 >>> 26; h0 = h0 & 0x3ffffff; h1 += c;
        }

        var cc;
        cc = h0 >>> 26; h0 = h0 & 0x3ffffff; h1 += cc;
        cc = h1 >>> 27; h1 = h1 & 0x1ffffff; h2 += cc;
        cc = h2 >>> 26; h2 = h2 & 0x3ffffff; h3 += cc;
        cc = h3 >>> 27; h3 = h3 & 0x1ffffff; h4 += cc;
        cc = h4 >>> 26; h4 = h4 & 0x3ffffff; h0 += cc * 5;
        cc = h0 >>> 26; h0 = h0 & 0x3ffffff; h1 += cc;

        var g0, g1, g2, g3, g4;
        g0 = h0 + 5; cc = g0 >>> 26; g0 &= 0x3ffffff; g1 = h1 + cc;
        cc = g1 >>> 27; g1 &= 0x1ffffff; g2 = h2 + cc;
        cc = g2 >>> 26; g2 &= 0x3ffffff; g3 = h3 + cc;
        cc = g3 >>> 27; g3 &= 0x1ffffff; g4 = h4 + cc - (1 << 26);

        var borrow = (g4 < 0) ? 1 : 0;
        if (!borrow) { h0 = g0; h1 = g1; h2 = g2; h3 = g3; h4 = g4; }

        var t0 = h0 | (h1 << 26);
        var t1 = (h1 >>> 6) | (h2 << 20);
        var t2 = (h2 >>> 12) | (h3 << 14);
        var t3 = (h3 >>> 18) | (h4 << 8);

        t0 = (t0 + s0) >>> 0;
        t1 = (t1 + s1) >>> 0;
        t2 = (t2 + s2) >>> 0;
        t3 = (t3 + s3) >>> 0;

        var tag = new Uint8Array(16);
        tag[0] = t0 & 0xFF; tag[1] = (t0 >>> 8) & 0xFF; tag[2] = (t0 >>> 16) & 0xFF; tag[3] = (t0 >>> 24) & 0xFF;
        tag[4] = t1 & 0xFF; tag[5] = (t1 >>> 8) & 0xFF; tag[6] = (t1 >>> 16) & 0xFF; tag[7] = (t1 >>> 24) & 0xFF;
        tag[8] = t2 & 0xFF; tag[9] = (t2 >>> 8) & 0xFF; tag[10] = (t2 >>> 16) & 0xFF; tag[11] = (t2 >>> 24) & 0xFF;
        tag[12] = t3 & 0xFF; tag[13] = (t3 >>> 8) & 0xFF; tag[14] = (t3 >>> 16) & 0xFF; tag[15] = (t3 >>> 24) & 0xFF;

        return tag;
    }

    function chacha20Poly1305Encrypt(key, nonce, plaintext, aad) {
        try {
            log("chacha20Poly1305Encrypt", "Encrypting " + plaintext.length + " bytes");
            var polyKey = chacha20Block(key, 0, nonce).slice(0, 32);
            var ciphertext = chacha20Crypt(key, nonce, plaintext, 1);

            var aadLen = aad ? aad.length : 0;
            var aadPadded = aad ? concatUint8Arrays(aad, new Uint8Array((16 - (aadLen % 16)) % 16)) : new Uint8Array(0);
            var ctPadded = concatUint8Arrays(ciphertext, new Uint8Array((16 - (ciphertext.length % 16)) % 16));

            var lenBlock = new Uint8Array(16);
            for (var i = 0; i < 8; i++) lenBlock[i] = (aadLen >>> (i * 8)) & 0xFF;
            for (var i = 0; i < 8; i++) lenBlock[8 + i] = (ciphertext.length >>> (i * 8)) & 0xFF;

            var macData = concatUint8Arrays(aadPadded, ctPadded, lenBlock);
            var tag = poly1305(polyKey, macData);

            log("chacha20Poly1305Encrypt", "Encryption successful. Ciphertext: " + ciphertext.length + " bytes");
            return { ciphertext: ciphertext, tag: tag };
        } catch (err) {
            logError("chacha20Poly1305Encrypt", "ChaCha20-Poly1305 encryption failed", err);
            throw err;
        }
    }

    function chacha20Poly1305Decrypt(key, nonce, ciphertext, tag, aad) {
        try {
            log("chacha20Poly1305Decrypt", "Decrypting " + ciphertext.length + " bytes");
            var polyKey = chacha20Block(key, 0, nonce).slice(0, 32);

            var aadLen = aad ? aad.length : 0;
            var aadPadded = aad ? concatUint8Arrays(aad, new Uint8Array((16 - (aadLen % 16)) % 16)) : new Uint8Array(0);
            var ctPadded = concatUint8Arrays(ciphertext, new Uint8Array((16 - (ciphertext.length % 16)) % 16));

            var lenBlock = new Uint8Array(16);
            for (var i = 0; i < 8; i++) lenBlock[i] = (aadLen >>> (i * 8)) & 0xFF;
            for (var i = 0; i < 8; i++) lenBlock[8 + i] = (ciphertext.length >>> (i * 8)) & 0xFF;

            var macData = concatUint8Arrays(aadPadded, ctPadded, lenBlock);
            var computedTag = poly1305(polyKey, macData);

            var diff = 0;
            for (var i = 0; i < 16; i++) diff |= computedTag[i] ^ tag[i];
            if (diff !== 0) {
                log("chacha20Poly1305Decrypt", "Poly1305 tag verification FAILED");
                throw new Error("Decryption failed at ChaCha20-Poly1305 layer: wrong password or corrupted data");
            }
            log("chacha20Poly1305Decrypt", "Poly1305 tag verification PASSED");

            var result = chacha20Crypt(key, nonce, ciphertext, 1);
            log("chacha20Poly1305Decrypt", "Decryption successful. Plaintext: " + result.length + " bytes");
            return result;
        } catch (err) {
            logError("chacha20Poly1305Decrypt", "ChaCha20-Poly1305 decryption failed", err);
            throw err;
        }
    }

    // HChaCha20 (for XChaCha20)
    function hcha20(key, nonce128) {
        var mask32 = 0xFFFFFFFF;
        var state = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0
        ];

        for (var i = 0; i < 8; i++) {
            state[4 + i] = (key[i * 4]) | (key[i * 4 + 1] << 8) | (key[i * 4 + 2] << 16) | (key[i * 4 + 3] << 24);
        }

        state[12] = (nonce128[0]) | (nonce128[1] << 8) | (nonce128[2] << 16) | (nonce128[3] << 24);
        state[13] = (nonce128[4]) | (nonce128[5] << 8) | (nonce128[6] << 16) | (nonce128[7] << 24);
        state[14] = (nonce128[8]) | (nonce128[9] << 8) | (nonce128[10] << 16) | (nonce128[11] << 24);
        state[15] = (nonce128[12]) | (nonce128[13] << 8) | (nonce128[14] << 16) | (nonce128[15] << 24);

        var working = state.slice();
        for (var r = 0; r < 10; r++) {
            chacha20QuarterRound(working, 0, 4, 8, 12);
            chacha20QuarterRound(working, 1, 5, 9, 13);
            chacha20QuarterRound(working, 2, 6, 10, 14);
            chacha20QuarterRound(working, 3, 7, 11, 15);
            chacha20QuarterRound(working, 0, 5, 10, 15);
            chacha20QuarterRound(working, 1, 6, 11, 12);
            chacha20QuarterRound(working, 2, 7, 8, 13);
            chacha20QuarterRound(working, 3, 4, 9, 14);
        }

        var subkey = new Uint8Array(32);
        for (var i = 0; i < 4; i++) {
            var w = working[i];
            subkey[i * 4] = w & 0xFF;
            subkey[i * 4 + 1] = (w >>> 8) & 0xFF;
            subkey[i * 4 + 2] = (w >>> 16) & 0xFF;
            subkey[i * 4 + 3] = (w >>> 24) & 0xFF;
        }
        for (var i = 0; i < 4; i++) {
            var w = working[12 + i];
            subkey[16 + i * 4] = w & 0xFF;
            subkey[16 + i * 4 + 1] = (w >>> 8) & 0xFF;
            subkey[16 + i * 4 + 2] = (w >>> 16) & 0xFF;
            subkey[16 + i * 4 + 3] = (w >>> 24) & 0xFF;
        }

        return subkey;
    }

    function xchacha20Poly1305Encrypt(key, nonce, plaintext, aad) {
        try {
            log("xchacha20Poly1305Encrypt", "Encrypting " + plaintext.length + " bytes with XChaCha20-Poly1305");
            var subkey = hcha20(key, nonce.slice(0, 16));
            var shortNonce = nonce.slice(16, 24);
            var result = chacha20Poly1305Encrypt(subkey, shortNonce, plaintext, aad);
            log("xchacha20Poly1305Encrypt", "XChaCha20-Poly1305 encryption successful");
            return result;
        } catch (err) {
            logError("xchacha20Poly1305Encrypt", "XChaCha20-Poly1305 encryption failed", err);
            throw err;
        }
    }

    function xchacha20Poly1305Decrypt(key, nonce, ciphertext, tag, aad) {
        try {
            log("xchacha20Poly1305Decrypt", "Decrypting " + ciphertext.length + " bytes with XChaCha20-Poly1305");
            var subkey = hcha20(key, nonce.slice(0, 16));
            var shortNonce = nonce.slice(16, 24);
            var result = chacha20Poly1305Decrypt(subkey, shortNonce, ciphertext, tag, aad);
            log("xchacha20Poly1305Decrypt", "XChaCha20-Poly1305 decryption successful");
            return result;
        } catch (err) {
            logError("xchacha20Poly1305Decrypt", "XChaCha20-Poly1305 decryption failed", err);
            throw err;
        }
    }

    // ============================================================
    // CBC + HMAC (for TripleDES, Rabbit, Blowfish via CryptoJS)
    // ============================================================

    function uint8ArrayToWordArray(uint8Array) {
        var words = [];
        for (var i = 0; i < uint8Array.length; i += 4) {
            words.push(
                ((uint8Array[i]) << 24) |
                ((uint8Array[i + 1] || 0) << 16) |
                ((uint8Array[i + 2] || 0) << 8) |
                (uint8Array[i + 3] || 0)
            );
        }
        return CryptoJS.lib.WordArray.create(words, uint8Array.length);
    }

    function wordArrayToUint8Array(wordArray, length) {
        var len = length !== undefined ? length : wordArray.sigBytes;
        var words = wordArray.words;
        var result = new Uint8Array(len);
        for (var i = 0; i < len; i++) {
            result[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xFF;
        }
        return result;
    }

    async function cbcHmacEncrypt(cipherFn, cipherName, data, key, iv) {
        try {
            log("cbcHmacEncrypt", "Encrypting " + data.length + " bytes with " + cipherName + "-CBC + HMAC");
            var dataWA = uint8ArrayToWordArray(data);
            var keyWA = uint8ArrayToWordArray(key);
            var ivWA = uint8ArrayToWordArray(iv);

            var encrypted = cipherFn.encrypt(dataWA, keyWA, {
                iv: ivWA,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            });

            var ciphertext = wordArrayToUint8Array(encrypted.ciphertext);

            var hmacInput = concatUint8Arrays(iv, ciphertext);
            var tag = await computeHMAC(key, hmacInput);

            log("cbcHmacEncrypt", cipherName + " encryption successful. Ciphertext: " + ciphertext.length + " bytes");
            return { ciphertext: ciphertext, tag: tag };
        } catch (err) {
            logError("cbcHmacEncrypt", cipherName + "-CBC encryption failed", err);
            throw err;
        }
    }

    async function cbcHmacDecrypt(cipherFn, cipherName, ciphertext, key, iv, tag) {
        try {
            log("cbcHmacDecrypt", "Decrypting " + ciphertext.length + " bytes with " + cipherName + "-CBC + HMAC");
            var hmacInput = concatUint8Arrays(iv, ciphertext);
            var valid = await verifyHMAC(key, hmacInput, tag);
            if (!valid) {
                log("cbcHmacDecrypt", "HMAC verification FAILED for " + cipherName);
                throw new Error("Decryption failed at " + cipherName + " layer: wrong password or corrupted data");
            }

            var ctWA = uint8ArrayToWordArray(ciphertext);
            var keyWA = uint8ArrayToWordArray(key);
            var ivWA = uint8ArrayToWordArray(iv);

            var decrypted = cipherFn.decrypt(
                { ciphertext: ctWA },
                keyWA,
                {
                    iv: ivWA,
                    mode: CryptoJS.mode.CBC,
                    padding: CryptoJS.pad.Pkcs7
                }
            );

            var result = wordArrayToUint8Array(decrypted);
            log("cbcHmacDecrypt", cipherName + " decryption successful. Plaintext: " + result.length + " bytes");
            return result;
        } catch (err) {
            logError("cbcHmacDecrypt", cipherName + "-CBC decryption failed", err);
            throw err;
        }
    }

    // ============================================================
    // Method-specific encrypt/decrypt
    // ============================================================

    async function encryptLayer(methodId, data, password) {
        var info = METHOD_INFO[methodId];
        if (!info) {
            logError("encryptLayer", "Unknown method ID: " + methodId, null);
            throw new Error("Unknown method ID: " + methodId);
        }

        log("encryptLayer", "=== Starting layer: " + info.name + " (ID=" + methodId + "), input size: " + data.length + " bytes ===");

        var salt = randomBytes(SALT_LENGTH);
        var keys = await deriveKeys(password, salt);

        if (info.isEncoding) {
            // Base85 encoding layer
            log("encryptLayer", "Applying Base85 encoding");
            var encoded = Base85.encode(data);
            var encodedBytes = utf8ToUint8Array(encoded);
            log("encryptLayer", "Base85 encoding complete. Output size: " + encodedBytes.length + " bytes");
            return {
                salt: salt,
                nonce: new Uint8Array(0),
                tag: new Uint8Array(0),
                ciphertext: encodedBytes
            };
        }

        if (info.isFernet) {
            log("encryptLayer", "Applying Fernet encryption");
            var fernetKeyInput = concatUint8Arrays(keys.encryptionKey, keys.hmacKey);
            var fernetKeyWA = await computeHMAC(keys.hmacKey, fernetKeyInput);
            var fernetKey = fernetKeyWA.slice(0, 32);

            var token = Fernet.encrypt(data, fernetKey);
            var tokenBytes = base64ToUint8Array(token);
            log("encryptLayer", "Fernet encryption complete. Token size: " + tokenBytes.length + " bytes");
            return {
                salt: salt,
                nonce: new Uint8Array(0),
                tag: new Uint8Array(0),
                ciphertext: tokenBytes
            };
        }

        var nonce = randomBytes(info.nonceLen);

        if (methodId === METHOD_AES256_GCM) {
            var result = await aes256GcmEncrypt(data, keys.encryptionKey, nonce);
            log("encryptLayer", "AES-256-GCM layer complete. Output: " + result.ciphertext.length + " bytes");
            return { salt: salt, nonce: nonce, tag: result.tag, ciphertext: result.ciphertext };
        }

        if (methodId === METHOD_CHACHA20_POLY1305) {
            var result = chacha20Poly1305Encrypt(keys.encryptionKey, nonce, data, null);
            log("encryptLayer", "ChaCha20-Poly1305 layer complete. Output: " + result.ciphertext.length + " bytes");
            return { salt: salt, nonce: nonce, tag: result.tag, ciphertext: result.ciphertext };
        }

        if (methodId === METHOD_XCHACHA20_POLY1305) {
            var result = xchacha20Poly1305Encrypt(keys.encryptionKey, nonce, data, null);
            log("encryptLayer", "XChaCha20-Poly1305 layer complete. Output: " + result.ciphertext.length + " bytes");
            return { salt: salt, nonce: nonce, tag: result.tag, ciphertext: result.ciphertext };
        }

        if (methodId === METHOD_TRIPLEDES_CBC) {
            var result = await cbcHmacEncrypt(CryptoJS.TripleDES, "TripleDES", data, keys.encryptionKey, nonce);
            log("encryptLayer", "TripleDES-CBC layer complete. Output: " + result.ciphertext.length + " bytes");
            return { salt: salt, nonce: nonce, tag: result.tag, ciphertext: result.ciphertext };
        }

        if (methodId === METHOD_RABBIT) {
            var result = await cbcHmacEncrypt(CryptoJS.Rabbit, "Rabbit", data, keys.encryptionKey, nonce);
            log("encryptLayer", "Rabbit layer complete. Output: " + result.ciphertext.length + " bytes");
            return { salt: salt, nonce: nonce, tag: result.tag, ciphertext: result.ciphertext };
        }

        if (methodId === METHOD_BLOWFISH) {
            var result = await cbcHmacEncrypt(CryptoJS.Blowfish, "Blowfish", data, keys.encryptionKey, nonce);
            log("encryptLayer", "Blowfish layer complete. Output: " + result.ciphertext.length + " bytes");
            return { salt: salt, nonce: nonce, tag: result.tag, ciphertext: result.ciphertext };
        }

        throw new Error("Unsupported method: " + info.name);
    }

    async function decryptLayer(methodId, ciphertext, salt, nonce, tag, password) {
        var info = METHOD_INFO[methodId];
        if (!info) {
            logError("decryptLayer", "Unknown method ID: " + methodId, null);
            throw new Error("Unknown method ID: " + methodId);
        }

        log("decryptLayer", "=== Starting layer: " + info.name + " (ID=" + methodId + "), input size: " + ciphertext.length + " bytes ===");

        var keys = await deriveKeys(password, salt);

        if (info.isEncoding) {
            // Base85 decoding layer
            log("decryptLayer", "Applying Base85 decoding");
            var encodedStr = uint8ArrayToUtf8(ciphertext);
            var decoded = Base85.decode(encodedStr);
            log("decryptLayer", "Base85 decoding complete. Output size: " + decoded.length + " bytes");
            return decoded;
        }

        if (info.isFernet) {
            log("decryptLayer", "Applying Fernet decryption");
            var token = uint8ArrayToBase64(ciphertext);
            var fernetKeyInput = concatUint8Arrays(keys.encryptionKey, keys.hmacKey);
            var fernetKeyWA = await computeHMAC(keys.hmacKey, fernetKeyInput);
            var fernetKey = fernetKeyWA.slice(0, 32);

            try {
                var result = Fernet.decrypt(token, fernetKey);
                log("decryptLayer", "Fernet decryption complete. Output: " + result.length + " bytes");
                return result;
            } catch (e) {
                logError("decryptLayer", "Fernet decryption failed", e);
                throw new Error("Decryption failed at Fernet layer: wrong password or corrupted data");
            }
        }

        if (methodId === METHOD_AES256_GCM) {
            var result = await aes256GcmDecrypt(ciphertext, keys.encryptionKey, nonce, tag);
            log("decryptLayer", "AES-256-GCM layer complete. Output: " + result.length + " bytes");
            return result;
        }

        if (methodId === METHOD_CHACHA20_POLY1305) {
            var result = chacha20Poly1305Decrypt(keys.encryptionKey, nonce, ciphertext, tag, null);
            log("decryptLayer", "ChaCha20-Poly1305 layer complete. Output: " + result.length + " bytes");
            return result;
        }

        if (methodId === METHOD_XCHACHA20_POLY1305) {
            var result = xchacha20Poly1305Decrypt(keys.encryptionKey, nonce, ciphertext, tag, null);
            log("decryptLayer", "XChaCha20-Poly1305 layer complete. Output: " + result.length + " bytes");
            return result;
        }

        if (methodId === METHOD_TRIPLEDES_CBC) {
            var result = await cbcHmacDecrypt(CryptoJS.TripleDES, "TripleDES", ciphertext, keys.encryptionKey, nonce, tag);
            log("decryptLayer", "TripleDES-CBC layer complete. Output: " + result.length + " bytes");
            return result;
        }

        if (methodId === METHOD_RABBIT) {
            var result = await cbcHmacDecrypt(CryptoJS.Rabbit, "Rabbit", ciphertext, keys.encryptionKey, nonce, tag);
            log("decryptLayer", "Rabbit layer complete. Output: " + result.length + " bytes");
            return result;
        }

        if (methodId === METHOD_BLOWFISH) {
            var result = await cbcHmacDecrypt(CryptoJS.Blowfish, "Blowfish", ciphertext, keys.encryptionKey, nonce, tag);
            log("decryptLayer", "Blowfish layer complete. Output: " + result.length + " bytes");
            return result;
        }

        throw new Error("Unsupported method: " + info.name);
    }

    // ============================================================
    // Binary serialization
    // ============================================================

    function serialize(layers, finalCiphertext) {
        // Calculate total size
        var headerSize = 4 + 1 + 1; // magic + version + numLayers
        for (var i = 0; i < layers.length; i++) {
            var layer = layers[i];
            headerSize += 1 + 1 + layer.salt.length + 1 + layer.nonce.length + 2 + layer.tag.length;
        }

        var result = new Uint8Array(headerSize + finalCiphertext.length);
        var offset = 0;

        // Magic
        result[offset++] = MAGIC[0];
        result[offset++] = MAGIC[1];
        result[offset++] = MAGIC[2];
        result[offset++] = MAGIC[3];

        // Version
        result[offset++] = VERSION;

        // Number of layers
        result[offset++] = layers.length;

        // Layer metadata
        for (var i = 0; i < layers.length; i++) {
            var layer = layers[i];

            // Method ID (1 byte)
            result[offset++] = layer.methodId;

            // Salt length (1 byte) + salt
            result[offset++] = layer.salt.length;
            result.set(layer.salt, offset);
            offset += layer.salt.length;

            // Nonce length (1 byte) + nonce
            result[offset++] = layer.nonce.length;
            result.set(layer.nonce, offset);
            offset += layer.nonce.length;

            // Tag length (2 bytes, big-endian) + tag
            result[offset++] = (layer.tag.length >>> 8) & 0xFF;
            result[offset++] = layer.tag.length & 0xFF;
            result.set(layer.tag, offset);
            offset += layer.tag.length;
        }

        // Final ciphertext
        result.set(finalCiphertext, offset);

        log("serialize", "Serialized " + layers.length + " layers. Total output: " + result.length + " bytes");
        return result;
    }

    function deserialize(data) {
        log("deserialize", "Deserializing " + data.length + " bytes");

        if (data.length < 7) {
            logError("deserialize", "Data too short: " + data.length + " bytes (minimum 7)", null);
            throw new Error("Invalid encrypted data: too short");
        }

        // Check magic
        for (var i = 0; i < 4; i++) {
            if (data[i] !== MAGIC[i]) {
                logError("deserialize", "Magic mismatch at byte " + i + ": expected " + MAGIC[i] + ", got " + data[i], null);
                throw new Error("Invalid encrypted data: wrong magic header (not a PNASystems encrypted file)");
            }
        }

        var offset = 4;
        var version = data[offset++];
        log("deserialize", "Version: " + version);
        if (version !== VERSION) {
            logError("deserialize", "Unsupported version: " + version + " (expected " + VERSION + ")", null);
            throw new Error("Unsupported encrypted data version: " + version);
        }

        var numLayers = data[offset++];
        log("deserialize", "Number of layers: " + numLayers);

        var layers = [];
        for (var i = 0; i < numLayers; i++) {
            var methodId = data[offset++];
            var info = METHOD_INFO[methodId];
            if (!info) {
                logError("deserialize", "Unknown method ID " + methodId + " in layer " + i, null);
                throw new Error("Unknown encryption method ID: " + methodId + " in layer " + (i + 1));
            }

            var saltLen = data[offset++];
            var salt = data.slice(offset, offset + saltLen);
            offset += saltLen;

            var nonceLen = data[offset++];
            var nonce = data.slice(offset, offset + nonceLen);
            offset += nonceLen;

            var tagLen = (data[offset] << 8) | data[offset + 1];
            offset += 2;
            var tag = data.slice(offset, offset + tagLen);
            offset += tagLen;

            layers.push({
                methodId: methodId,
                methodName: info.name,
                salt: salt,
                nonce: nonce,
                tag: tag
            });

            log("deserialize", "Layer " + (i + 1) + ": " + info.name + ", salt=" + saltLen + "B, nonce=" + nonceLen + "B, tag=" + tagLen + "B");
        }

        var ciphertext = data.slice(offset);
        log("deserialize", "Ciphertext size: " + ciphertext.length + " bytes");

        return { layers: layers, ciphertext: ciphertext };
    }

    // ============================================================
    // High-level Pipeline API
    // ============================================================

    async function encryptBytes(data, password) {
        log("encryptBytes", "========== STARTING ENCRYPTION PIPELINE ==========");
        log("encryptBytes", "Input data size: " + data.length + " bytes");
        log("encryptBytes", "Pipeline order: " + ENCRYPT_PIPELINE.map(function(id) { return METHOD_INFO[id].name; }).join(" → "));

        var currentData = data;
        var layerMetadata = [];

        for (var i = 0; i < ENCRYPT_PIPELINE.length; i++) {
            var methodId = ENCRYPT_PIPELINE[i];
            try {
                var result = await encryptLayer(methodId, currentData, password);
                layerMetadata.push({
                    methodId: methodId,
                    salt: result.salt,
                    nonce: result.nonce,
                    tag: result.tag
                });
                currentData = result.ciphertext;
                log("encryptBytes", "Layer " + (i + 1) + "/" + ENCRYPT_PIPELINE.length + " (" + METHOD_INFO[methodId].name + ") complete. Output: " + currentData.length + " bytes");
            } catch (err) {
                logError("encryptBytes", "Pipeline failed at layer " + (i + 1) + " (" + METHOD_INFO[methodId].name + ")", err);
                throw new Error("Encryption failed at " + METHOD_INFO[methodId].name + " layer: " + err.message);
            }
        }

        var output = serialize(layerMetadata, currentData);
        log("encryptBytes", "========== ENCRYPTION PIPELINE COMPLETE ==========");
        log("encryptBytes", "Final output size: " + output.length + " bytes");
        return output;
    }

    async function decryptBytes(data, password) {
        log("decryptBytes", "========== STARTING DECRYPTION PIPELINE ==========");
        log("decryptBytes", "Input data size: " + data.length + " bytes");

        var parsed;
        try {
            parsed = deserialize(data);
        } catch (err) {
            logError("decryptBytes", "Failed to parse encrypted data header", err);
            throw err;
        }

        log("decryptBytes", "Parsed " + parsed.layers.length + " layers from header");
        log("decryptBytes", "Decryption pipeline order: " + DECRYPT_PIPELINE.map(function(id) { return METHOD_INFO[id].name; }).join(" → "));

        // Reverse layers array so it matches decryption order (last encrypted = first decrypted)
        parsed.layers.reverse();
        log("decryptBytes", "Reversed layers for decryption. First layer to decrypt: " + parsed.layers[0].methodName);

        var currentData = parsed.ciphertext;

        for (var i = 0; i < DECRYPT_PIPELINE.length; i++) {
            var methodId = DECRYPT_PIPELINE[i];
            var layerInfo = parsed.layers[i];

            if (!layerInfo) {
                logError("decryptBytes", "Missing layer metadata for step " + (i + 1), null);
                throw new Error("Corrupted data: missing layer metadata for decryption step " + (i + 1));
            }

            if (layerInfo.methodId !== methodId) {
                logError("decryptBytes", "Method mismatch at step " + (i + 1) + ": expected " + METHOD_INFO[methodId].name + ", got " + METHOD_INFO[layerInfo.methodId].name, null);
                throw new Error("Corrupted data: expected " + METHOD_INFO[methodId].name + " but found " + METHOD_INFO[layerInfo.methodId].name);
            }

            try {
                currentData = await decryptLayer(methodId, currentData, layerInfo.salt, layerInfo.nonce, layerInfo.tag, password);
                log("decryptBytes", "Layer " + (i + 1) + "/" + DECRYPT_PIPELINE.length + " (" + METHOD_INFO[methodId].name + ") complete. Output: " + currentData.length + " bytes");
            } catch (err) {
                logError("decryptBytes", "Pipeline failed at layer " + (i + 1) + " (" + METHOD_INFO[methodId].name + ")", err);
                throw err;
            }
        }

        log("decryptBytes", "========== DECRYPTION PIPELINE COMPLETE ==========");
        log("decryptBytes", "Final plaintext size: " + currentData.length + " bytes");
        return currentData;
    }

    async function encryptText(plaintext, password) {
        log("encryptText", "Encrypting text (" + plaintext.length + " characters)");
        var data = utf8ToUint8Array(plaintext);
        var encrypted = await encryptBytes(data, password);
        var b64 = uint8ArrayToBase64(encrypted);
        log("encryptText", "Encrypted text output: " + b64.length + " Base64 characters");
        return b64;
    }

    async function decryptText(b64, password) {
        log("decryptText", "Decrypting text from " + b64.length + " Base64 characters");
        var data = base64ToUint8Array(b64);
        var decrypted = await decryptBytes(data, password);
        var plaintext = uint8ArrayToUtf8(decrypted);
        log("decryptText", "Decrypted text: " + plaintext.length + " characters");
        return plaintext;
    }

    // ============================================================
    // Public API
    // ============================================================

    global.CryptoEngine = {
        ENCRYPT_PIPELINE: ENCRYPT_PIPELINE,
        DECRYPT_PIPELINE: DECRYPT_PIPELINE,
        METHOD_INFO: METHOD_INFO,
        encryptText: encryptText,
        decryptText: decryptText,
        encryptBytes: encryptBytes,
        decryptBytes: decryptBytes
    };

    log("init", "CryptoEngine initialized with " + ENCRYPT_PIPELINE.length + " pipeline layers");
    log("init", "Pipeline: " + ENCRYPT_PIPELINE.map(function(id) { return METHOD_INFO[id].name; }).join(" → "));

})(typeof window !== "undefined" ? window : typeof global !== "undefined" ? global : this);
