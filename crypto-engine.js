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
 * Crypto Engine - Core encryption/decryption operations.
 *
 * Supported methods:
 *   0: AES-256-GCM (WebCrypto) - Authenticated encryption
 *   1: Fernet (CryptoJS AES-128-CBC + HMAC-SHA256) - Authenticated encryption
 *   2: Base85 (encoding layer, not standalone encryption)
 *   3: ChaCha20-Poly1305 (pure JS, IETF variant) - Authenticated encryption
 *   4: XChaCha20-Poly1305 (pure JS) - Authenticated encryption with extended nonce
 *   5: TripleDES-192-CBC + HMAC-SHA256 (CryptoJS) - Authenticated encryption
 *   6: Rabbit + HMAC-SHA256 (CryptoJS) - Authenticated encryption
 *   7: Blowfish + HMAC-SHA256 (CryptoJS) - Authenticated encryption
 *
 * Key Derivation:
 *   - Uses PBKDF2-HMAC-SHA256 via WebCrypto
 *   - 16-byte random salt generated per encryption operation
 *   - 100,000 iterations for key stretching
 *   - Derives 32 bytes for encryption + 32 bytes for HMAC = 64 bytes total
 *
 * Binary Output Format:
 *   [PNAE][ver][methodId][salt:16][nonceLen][nonce][tag][ciphertext]
 *   - PNAE: 4-byte magic header
 *   - ver: 1-byte version (0x01)
 *   - methodId: 1-byte method identifier
 *   - salt: 16 bytes random salt
 *   - nonceLen: 1 byte indicating nonce length
 *   - nonce: variable length (method-dependent)
 *   - tag: authentication tag (16 bytes for AEAD, 32 bytes for HMAC-based)
 *   - ciphertext: encrypted data
 *
 * Text Output:
 *   The binary format above is Base64-encoded for text mode.
 */

(function (global) {
    "use strict";

    // Method identifiers
    var METHOD_AES256_GCM = 0;
    var METHOD_FERNET = 1;
    var METHOD_BASE85 = 2;
    var METHOD_CHACHA20_POLY1305 = 3;
    var METHOD_XCHACHA20_POLY1305 = 4;
    var METHOD_TRIPLEDES_CBC = 5;
    var METHOD_RABBIT = 6;
    var METHOD_BLOWFISH = 7;

    // Method metadata
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

    // ============================================================
    // Key Derivation (PBKDF2-HMAC-SHA256 via WebCrypto)
    // ============================================================

    async function deriveKeys(password, salt) {
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
        return {
            encryptionKey: derived.slice(0, ENCRYPTION_KEY_LENGTH),
            hmacKey: derived.slice(ENCRYPTION_KEY_LENGTH)
        };
    }

    // ============================================================
    // HMAC-SHA256 (via WebCrypto)
    // ============================================================

    async function computeHMAC(key, data) {
        var cryptoKey = await crypto.subtle.importKey(
            "raw",
            key,
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"]
        );
        var signature = await crypto.subtle.sign("HMAC", cryptoKey, data);
        return new Uint8Array(signature);
    }

    async function verifyHMAC(key, data, expectedTag) {
        var actualTag = await computeHMAC(key, data);
        if (actualTag.length !== expectedTag.length) return false;
        var diff = 0;
        for (var i = 0; i < actualTag.length; i++) {
            diff |= actualTag[i] ^ expectedTag[i];
        }
        return diff === 0;
    }

    // ============================================================
    // AES-256-GCM (WebCrypto)
    // ============================================================

    async function aes256GcmEncrypt(data, key, nonce) {
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
        return { ciphertext: ciphertext, tag: tag };
    }

    async function aes256GcmDecrypt(data, key, nonce, tag) {
        var cryptoKey = await crypto.subtle.importKey(
            "raw", key, { name: "AES-GCM" }, false, ["decrypt"]
        );
        var combined = concatUint8Arrays(data, tag);
        try {
            var decrypted = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: nonce },
                cryptoKey,
                combined
            );
            return new Uint8Array(decrypted);
        } catch (e) {
            throw new Error("Decryption failed: wrong password or corrupted data");
        }
    }

    // ============================================================
    // ChaCha20-Poly1305 (Pure JS, IETF variant - RFC 8439)
    // ============================================================

    // ChaCha20 quarter round
    function chacha20QuarterRound(state, a, b, c, d) {
        var mask32 = 0xFFFFFFFF;
        state[a] = (state[a] + state[b]) & mask32; state[d] ^= state[a]; state[d] = ((state[d] << 16) | (state[d] >>> 16)) & mask32;
        state[c] = (state[c] + state[d]) & mask32; state[b] ^= state[c]; state[b] = ((state[b] << 12) | (state[b] >>> 20)) & mask32;
        state[a] = (state[a] + state[b]) & mask32; state[d] ^= state[a]; state[d] = ((state[d] << 8) | (state[d] >>> 24)) & mask32;
        state[c] = (state[c] + state[d]) & mask32; state[b] ^= state[c]; state[b] = ((state[b] << 7) | (state[b] >>> 25)) & mask32;
    }

    // ChaCha20 block function
    function chacha20Block(key, counter, nonce) {
        var mask32 = 0xFFFFFFFF;
        // Constants "expand 32-byte k"
        var state = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            0, 0, 0, 0, 0, 0, 0, 0,  // key (8 words)
            0, 0, 0, 0               // counter (1 word), nonce (3 words)
        ];

        // Load key (8 x 32-bit words, little-endian)
        for (var i = 0; i < 8; i++) {
            state[4 + i] = (key[i * 4]) | (key[i * 4 + 1] << 8) | (key[i * 4 + 2] << 16) | (key[i * 4 + 3] << 24);
        }

        // Load counter
        state[12] = counter & mask32;

        // Load nonce (12 bytes = 3 words, little-endian)
        state[13] = (nonce[0]) | (nonce[1] << 8) | (nonce[2] << 16) | (nonce[3] << 24);
        state[14] = (nonce[4]) | (nonce[5] << 8) | (nonce[6] << 16) | (nonce[7] << 24);
        state[15] = (nonce[8]) | (nonce[9] << 8) | (nonce[10] << 16) | (nonce[11] << 24);

        var workingState = state.slice();

        // 20 rounds (10 double rounds)
        for (var r = 0; r < 10; r++) {
            // Column rounds
            chacha20QuarterRound(workingState, 0, 4, 8, 12);
            chacha20QuarterRound(workingState, 1, 5, 9, 13);
            chacha20QuarterRound(workingState, 2, 6, 10, 14);
            chacha20QuarterRound(workingState, 3, 7, 11, 15);
            // Diagonal rounds
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

    // ChaCha20 stream cipher
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

    // Poly1305 MAC (RFC 8439)
    function poly1305(key, data) {
        // Clamp the key
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

        // Accumulator (using 5 x 64-bit limbs for 130-bit arithmetic)
        var h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

        // Process 16-byte blocks
        for (var offset = 0; offset < data.length; offset += 16) {
            var blockLen = Math.min(16, data.length - offset);

            // Load block as little-endian limbs, add high bit
            var b0, b1, b2, b3, b4;
            if (blockLen >= 4) b0 = (data[offset]) | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);
            else {
                b0 = 0;
                for (var bi = 0; bi < blockLen && bi < 4; bi++) b0 |= data[offset + bi] << (bi * 8);
            }
            if (blockLen >= 8) b1 = (data[offset + 4]) | (data[offset + 5] << 8) | (data[offset + 6] << 16) | (data[offset + 7] << 24);
            else {
                b1 = 0;
                for (var bi = 4; bi < blockLen && bi < 8; bi++) b1 |= data[offset + bi] << ((bi - 4) * 8);
            }
            if (blockLen >= 12) b2 = (data[offset + 8]) | (data[offset + 9] << 8) | (data[offset + 10] << 16) | (data[offset + 11] << 24);
            else {
                b2 = 0;
                for (var bi = 8; bi < blockLen && bi < 12; bi++) b2 |= data[offset + bi] << ((bi - 8) * 8);
            }
            if (blockLen >= 16) b3 = (data[offset + 12]) | (data[offset + 13] << 8) | (data[offset + 14] << 16) | (data[offset + 15] << 24);
            else {
                b3 = 0;
                for (var bi = 12; bi < blockLen && bi < 16; bi++) b3 |= data[offset + bi] << ((bi - 12) * 8);
            }

            b0 &= 0x3ffffff;
            b1 = (b1 >>> 0) & 0x1ffffff;
            b2 &= 0x3ffffff;
            b3 = (b3 >>> 0) & 0x1ffffff;
            b4 = blockLen === 16 ? 0 : (1 << (blockLen * 8 % 26 === 0 ? 26 : (blockLen * 8 % 26)));

            // Actually, the high bit is at position blockLen * 8
            // Let me redo this properly
            b4 = blockLen < 16 ? (1 << (blockLen * 8)) : 0;

            // Wait, I need to be more careful. In Poly1305, each 16-byte block is
            // interpreted as a little-endian number with an extra 1 bit appended.
            // The limbs are: 26, 27, 26, 27, 26 bits.
            // Let me recompute:

            var fullBlock = new Uint8Array(17);
            for (var fi = 0; fi < blockLen; fi++) {
                fullBlock[fi] = data[offset + fi];
            }
            fullBlock[blockLen] = 1; // Append 1 bit (at byte position blockLen)

            b0 = (fullBlock[0]) | (fullBlock[1] << 8) | (fullBlock[2] << 16) | (fullBlock[3] << 24);
            b1 = (fullBlock[4]) | (fullBlock[5] << 8) | (fullBlock[6] << 16) | (fullBlock[7] << 24);
            b2 = (fullBlock[8]) | (fullBlock[9] << 8) | (fullBlock[10] << 16) | (fullBlock[11] << 24);
            b3 = (fullBlock[12]) | (fullBlock[13] << 8) | (fullBlock[14] << 16) | (fullBlock[15] << 24);
            b4 = (fullBlock[16]);

            b0 &= 0x3ffffff;
            b1 = (b1 >>> 0) & 0x1ffffff;
            b2 &= 0x3ffffff;
            b3 = (b3 >>> 0) & 0x1ffffff;
            b4 &= 0x3ffffff;

            // Multiply and add to accumulator
            var d0 = h0 * r0 + h1 * (4 * r4) + h2 * (4 * r3) + h3 * (4 * r2) + h4 * (4 * r1) + b0;
            var d1 = h0 * r1 + h1 * r0 + h2 * (4 * r4) + h3 * (4 * r3) + h4 * (4 * r2) + b1;
            var d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * (4 * r4) + h4 * (4 * r3) + b2;
            var d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * (4 * r4) + b3;
            var d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0 + b4;

            // Carry propagation
            var c;
            c = d0 >>> 26; h0 = d0 & 0x3ffffff; d1 += c;
            c = d1 >>> 27; h1 = d1 & 0x1ffffff; d2 += c;
            c = d2 >>> 26; h2 = d2 & 0x3ffffff; d3 += c;
            c = d3 >>> 27; h3 = d3 & 0x1ffffff; d4 += c;
            c = d4 >>> 26; h4 = d4 & 0x3ffffff; h0 += c * 5;
            c = h0 >>> 26; h0 = h0 & 0x3ffffff; h1 += c;
        }

        // Final reduction
        var g0, g1, g2, g3, g4;
        var cc;
        cc = h0 >>> 26; h0 = h0 & 0x3ffffff; h1 += cc;
        cc = h1 >>> 27; h1 = h1 & 0x1ffffff; h2 += cc;
        cc = h2 >>> 26; h2 = h2 & 0x3ffffff; h3 += cc;
        cc = h3 >>> 27; h3 = h3 & 0x1ffffff; h4 += cc;
        cc = h4 >>> 26; h4 = h4 & 0x3ffffff; h0 += cc * 5;
        cc = h0 >>> 26; h0 = h0 & 0x3ffffff; h1 += cc;

        // Check if h >= p and subtract if so
        g0 = h0 + 5; cc = g0 >>> 26; g0 &= 0x3ffffff; g1 = h1 + cc;
        cc = g1 >>> 27; g1 &= 0x1ffffff; g2 = h2 + cc;
        cc = g2 >>> 26; g2 &= 0x3ffffff; g3 = h3 + cc;
        cc = g3 >>> 27; g3 &= 0x1ffffff; g4 = h4 + cc - (1 << 26);

        var borrow = (g4 < 0) ? 1 : 0;
        if (!borrow) { h0 = g0; h1 = g1; h2 = g2; h3 = g3; h4 = g4; }

        // Pack into 16-byte tag
        var t0 = h0 | (h1 << 26);
        var t1 = (h1 >>> 6) | (h2 << 20);
        var t2 = (h2 >>> 12) | (h3 << 14);
        var t3 = (h3 >>> 18) | (h4 << 8);

        // Add s
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

    // ChaCha20-Poly1305 AEAD (RFC 8439)
    function chacha20Poly1305Encrypt(key, nonce, plaintext, aad) {
        // Generate Poly1305 key by encrypting a zero block with counter=0
        var polyKey = chacha20Block(key, 0, nonce).slice(0, 32);

        // Encrypt plaintext with counter starting at 1
        var ciphertext = chacha20Crypt(key, nonce, plaintext, 1);

        // Compute Poly1305 tag over AAD || padding || ciphertext || padding || lengths
        var aadLen = aad ? aad.length : 0;
        var aadPadded = aad ? concatUint8Arrays(aad, new Uint8Array((16 - (aadLen % 16)) % 16)) : new Uint8Array(0);
        var ctPadded = concatUint8Arrays(ciphertext, new Uint8Array((16 - (ciphertext.length % 16)) % 16));

        var lenBlock = new Uint8Array(16);
        // AAD length (8 bytes, little-endian)
        for (var i = 0; i < 8; i++) lenBlock[i] = (aadLen >>> (i * 8)) & 0xFF;
        // Ciphertext length (8 bytes, little-endian)
        for (var i = 0; i < 8; i++) lenBlock[8 + i] = (ciphertext.length >>> (i * 8)) & 0xFF;

        var macData = concatUint8Arrays(aadPadded, ctPadded, lenBlock);
        var tag = poly1305(polyKey, macData);

        return { ciphertext: ciphertext, tag: tag };
    }

    function chacha20Poly1305Decrypt(key, nonce, ciphertext, tag, aad) {
        // Generate Poly1305 key
        var polyKey = chacha20Block(key, 0, nonce).slice(0, 32);

        // Verify tag
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
            throw new Error("Decryption failed: wrong password or corrupted data");
        }

        // Decrypt
        return chacha20Crypt(key, nonce, ciphertext, 1);
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

    // XChaCha20-Poly1305
    function xchacha20Poly1305Encrypt(key, nonce, plaintext, aad) {
        var subkey = hcha20(key, nonce.slice(0, 16));
        var shortNonce = nonce.slice(16, 24);
        return chacha20Poly1305Encrypt(subkey, shortNonce, plaintext, aad);
    }

    function xchacha20Poly1305Decrypt(key, nonce, ciphertext, tag, aad) {
        var subkey = hcha20(key, nonce.slice(0, 16));
        var shortNonce = nonce.slice(16, 24);
        return chacha20Poly1305Decrypt(subkey, shortNonce, ciphertext, tag, aad);
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

    async function cbcHmacEncrypt(cipherFn, data, key, iv) {
        // Encrypt with CBC + PKCS7
        var dataWA = uint8ArrayToWordArray(data);
        var keyWA = uint8ArrayToWordArray(key);
        var ivWA = uint8ArrayToWordArray(iv);

        var encrypted = cipherFn.encrypt(dataWA, keyWA, {
            iv: ivWA,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });

        var ciphertext = wordArrayToUint8Array(encrypted.ciphertext);

        // Compute HMAC-SHA256 over IV || ciphertext
        var hmacInput = concatUint8Arrays(iv, ciphertext);
        var tag = await computeHMAC(key, hmacInput);

        return { ciphertext: ciphertext, tag: tag };
    }

    async function cbcHmacDecrypt(cipherFn, ciphertext, key, iv, tag) {
        // Verify HMAC
        var hmacInput = concatUint8Arrays(iv, ciphertext);
        var valid = await verifyHMAC(key, hmacInput, tag);
        if (!valid) {
            throw new Error("Decryption failed: wrong password or corrupted data");
        }

        // Decrypt
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

        return wordArrayToUint8Array(decrypted);
    }

    // ============================================================
    // Method-specific encrypt/decrypt
    // ============================================================

    async function encryptData(methodId, data, encryptionKey, hmacKey) {
        var info = METHOD_INFO[methodId];
        if (!info) throw new Error("Unknown method ID: " + methodId);

        // Base85 is encoding-only, not encryption
        if (info.isEncoding) {
            throw new Error("Base85 is an encoding layer, not a standalone encryption method");
        }

        // Fernet uses its own key derivation (32 bytes: 16 signing + 16 encryption)
        if (info.isFernet) {
            var fernetKey = new Uint8Array(32);
            // Derive Fernet key from our encryption key + hmac key
            var fernetKeyInput = concatUint8Arrays(encryptionKey, hmacKey);
            // Use HMAC to derive a deterministic 32-byte key
            var fernetKeyWA = await computeHMAC(hmacKey, fernetKeyInput);
            fernetKey = fernetKeyWA.slice(0, 32);

            var token = Fernet.encrypt(data, fernetKey);
            var tokenBytes = base64ToUint8Array(token);
            return {
                ciphertext: tokenBytes,
                tag: new Uint8Array(0),
                nonce: new Uint8Array(0)
            };
        }

        var nonce = randomBytes(info.nonceLen);

        if (methodId === METHOD_AES256_GCM) {
            var result = await aes256GcmEncrypt(data, encryptionKey, nonce);
            return { ciphertext: result.ciphertext, tag: result.tag, nonce: nonce };
        }

        if (methodId === METHOD_CHACHA20_POLY1305) {
            var result = chacha20Poly1305Encrypt(encryptionKey, nonce, data, null);
            return { ciphertext: result.ciphertext, tag: result.tag, nonce: nonce };
        }

        if (methodId === METHOD_XCHACHA20_POLY1305) {
            var result = xchacha20Poly1305Encrypt(encryptionKey, nonce, data, null);
            return { ciphertext: result.ciphertext, tag: result.tag, nonce: nonce };
        }

        // CBC + HMAC methods
        if (methodId === METHOD_TRIPLEDES_CBC) {
            var result = await cbcHmacEncrypt(CryptoJS.TripleDES, data, encryptionKey, nonce);
            return { ciphertext: result.ciphertext, tag: result.tag, nonce: nonce };
        }

        if (methodId === METHOD_RABBIT) {
            var result = await cbcHmacEncrypt(CryptoJS.Rabbit, data, encryptionKey, nonce);
            return { ciphertext: result.ciphertext, tag: result.tag, nonce: nonce };
        }

        if (methodId === METHOD_BLOWFISH) {
            var result = await cbcHmacEncrypt(CryptoJS.Blowfish, data, encryptionKey, nonce);
            return { ciphertext: result.ciphertext, tag: result.tag, nonce: nonce };
        }

        throw new Error("Unsupported method: " + info.name);
    }

    async function decryptData(methodId, ciphertext, tag, nonce, encryptionKey, hmacKey) {
        var info = METHOD_INFO[methodId];
        if (!info) throw new Error("Unknown method ID: " + methodId);

        if (info.isEncoding) {
            throw new Error("Base85 is an encoding layer, not a standalone encryption method");
        }

        if (info.isFernet) {
            var token = uint8ArrayToBase64(ciphertext);
            var fernetKeyInput = concatUint8Arrays(encryptionKey, hmacKey);
            var fernetKeyWA = await computeHMAC(hmacKey, fernetKeyInput);
            var fernetKey = fernetKeyWA.slice(0, 32);

            try {
                return Fernet.decrypt(token, fernetKey);
            } catch (e) {
                throw new Error("Decryption failed: wrong password or corrupted data");
            }
        }

        if (methodId === METHOD_AES256_GCM) {
            return await aes256GcmDecrypt(ciphertext, encryptionKey, nonce, tag);
        }

        if (methodId === METHOD_CHACHA20_POLY1305) {
            return chacha20Poly1305Decrypt(encryptionKey, nonce, ciphertext, tag, null);
        }

        if (methodId === METHOD_XCHACHA20_POLY1305) {
            return xchacha20Poly1305Decrypt(encryptionKey, nonce, ciphertext, tag, null);
        }

        if (methodId === METHOD_TRIPLEDES_CBC) {
            return await cbcHmacDecrypt(CryptoJS.TripleDES, ciphertext, encryptionKey, nonce, tag);
        }

        if (methodId === METHOD_RABBIT) {
            return await cbcHmacDecrypt(CryptoJS.Rabbit, ciphertext, encryptionKey, nonce, tag);
        }

        if (methodId === METHOD_BLOWFISH) {
            return await cbcHmacDecrypt(CryptoJS.Blowfish, ciphertext, encryptionKey, nonce, tag);
        }

        throw new Error("Unsupported method: " + info.name);
    }

    // ============================================================
    // Binary serialization
    // ============================================================

    function serialize(methodId, salt, nonce, tag, ciphertext) {
        var parts = [
            new Uint8Array(MAGIC),
            new Uint8Array([VERSION]),
            new Uint8Array([methodId]),
            salt,
            new Uint8Array([nonce.length]),
            nonce,
            tag,
            ciphertext
        ];
        return concatUint8Arrays.apply(null, parts);
    }

    function deserialize(data) {
        if (data.length < 24) {
            throw new Error("Invalid encrypted data: too short");
        }

        // Check magic
        for (var i = 0; i < 4; i++) {
            if (data[i] !== MAGIC[i]) {
                throw new Error("Invalid encrypted data: wrong magic header");
            }
        }

        var offset = 4;
        var version = data[offset++];
        if (version !== VERSION) {
            throw new Error("Unsupported version: " + version);
        }

        var methodId = data[offset++];
        var info = METHOD_INFO[methodId];
        if (!info) {
            throw new Error("Unknown method ID: " + methodId);
        }

        var salt = data.slice(offset, offset + SALT_LENGTH);
        offset += SALT_LENGTH;

        var nonceLen = data[offset++];
        var nonce = data.slice(offset, offset + nonceLen);
        offset += nonceLen;

        var tagLen = info.tagLen;
        var tag = data.slice(offset, offset + tagLen);
        offset += tagLen;

        var ciphertext = data.slice(offset);

        return { methodId: methodId, salt: salt, nonce: nonce, tag: tag, ciphertext: ciphertext };
    }

    // ============================================================
    // High-level API
    // ============================================================

    /**
     * Encrypt text with the given method and password.
     * Returns Base64-encoded binary output.
     */
    async function encryptText(methodId, plaintext, password) {
        var data = utf8ToUint8Array(plaintext);
        return encryptBytes(methodId, data, password);
    }

    /**
     * Decrypt text from Base64-encoded binary output.
     * Returns UTF-8 plaintext string.
     */
    async function decryptText(b64, password) {
        var decrypted = await decryptBytes(b64, password);
        return uint8ArrayToUtf8(decrypted);
    }

    /**
     * Encrypt file bytes with the given method and password.
     * Returns raw encrypted bytes (for download).
     */
    async function encryptBytes(methodId, data, password) {
        var salt = randomBytes(SALT_LENGTH);
        var keys = await deriveKeys(password, salt);
        var result = await encryptData(methodId, data, keys.encryptionKey, keys.hmacKey);
        var serialized = serialize(methodId, salt, result.nonce, result.tag, result.ciphertext);
        return serialized;
    }

    /**
     * Decrypt file bytes from Base64-encoded binary output.
     * Returns raw decrypted bytes.
     */
    async function decryptBytes(b64, password) {
        var data = base64ToUint8Array(b64);
        var parsed = deserialize(data);
        var keys = await deriveKeys(password, parsed.salt);
        return decryptData(parsed.methodId, parsed.ciphertext, parsed.tag, parsed.nonce, keys.encryptionKey, keys.hmacKey);
    }

    /**
     * Get method info by ID.
     */
    function getMethodInfo(methodId) {
        return METHOD_INFO[methodId];
    }

    /**
     * Get all available methods.
     */
    function getMethods() {
        var methods = [];
        for (var id in METHOD_INFO) {
            var info = METHOD_INFO[id];
            if (!info.isEncoding) {
                methods.push({ id: parseInt(id), name: info.name });
            }
        }
        return methods;
    }

    // Export
    global.CryptoEngine = {
        METHOD_AES256_GCM: METHOD_AES256_GCM,
        METHOD_FERNET: METHOD_FERNET,
        METHOD_BASE85: METHOD_BASE85,
        METHOD_CHACHA20_POLY1305: METHOD_CHACHA20_POLY1305,
        METHOD_XCHACHA20_POLY1305: METHOD_XCHACHA20_POLY1305,
        METHOD_TRIPLEDES_CBC: METHOD_TRIPLEDES_CBC,
        METHOD_RABBIT: METHOD_RABBIT,
        METHOD_BLOWFISH: METHOD_BLOWFISH,
        encryptText: encryptText,
        decryptText: decryptText,
        encryptBytes: encryptBytes,
        decryptBytes: decryptBytes,
        getMethodInfo: getMethodInfo,
        getMethods: getMethods
    };

})(typeof window !== "undefined" ? window : typeof global !== "undefined" ? global : this);
