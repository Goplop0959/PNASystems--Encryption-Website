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
 * Fernet symmetric encryption implementation.
 * Follows the Fernet specification: https://github.com/fernet/spec/blob/master/Spec.md
 *
 * Fernet token structure:
 *   - Version (1 byte): 0x80
 *   - Timestamp (8 bytes): big-endian, seconds since Unix epoch
 *   - IV (16 bytes): random initialization vector
 *   - Ciphertext: AES-128-CBC with PKCS7 padding
 *   - HMAC-SHA256 (32 bytes): signature over version || timestamp || IV || ciphertext
 *
 * The 256-bit key is split:
 *   - First 16 bytes: signing key (HMAC-SHA256)
 *   - Last 16 bytes: encryption key (AES-128-CBC)
 *
 * The final token is base64url-encoded (without padding).
 *
 * This implementation uses CryptoJS for AES-CBC and HMAC-SHA256 operations.
 * It expects CryptoJS to be loaded globally before this script.
 */

(function (global) {
    "use strict";

    var FERNET_VERSION = 0x80;

    /**
     * Generate cryptographically secure random bytes.
     * @param {number} length - Number of random bytes to generate
     * @returns {Uint8Array} Random bytes
     */
    function randomBytes(length) {
        var array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return array;
    }

    /**
     * Convert a number to an 8-byte big-endian Uint8Array.
     * @param {number} num - Number to convert (seconds since epoch)
     * @returns {Uint8Array} 8-byte big-endian representation
     */
    function numberToUint64(num) {
        var arr = new Uint8Array(8);
        // Handle large numbers using string-based approach for timestamps
        var high = Math.floor(num / 0x100000000);
        var low = num % 0x100000000;
        if (low < 0) low += 0x100000000;
        arr[0] = (high >>> 24) & 0xFF;
        arr[1] = (high >>> 16) & 0xFF;
        arr[2] = (high >>> 8) & 0xFF;
        arr[3] = high & 0xFF;
        arr[4] = (low >>> 24) & 0xFF;
        arr[5] = (low >>> 16) & 0xFF;
        arr[6] = (low >>> 8) & 0xFF;
        arr[7] = low & 0xFF;
        return arr;
    }

    /**
     * Convert 8 bytes (big-endian) to a number.
     * @param {Uint8Array} arr - 8-byte array
     * @returns {number} The decoded number
     */
    function uint64ToNumber(arr) {
        var high = (arr[0] << 24) | (arr[1] << 16) | (arr[2] << 8) | arr[3];
        var low = (arr[4] << 24) | (arr[5] << 16) | (arr[6] << 8) | arr[7];
        // Handle unsigned
        if (low < 0) low += 0x100000000;
        return high * 0x100000000 + low;
    }

    /**
     * Standard Base64 encoding (not URL-safe).
     * Fernet uses standard base64, not base64url.
     * @param {Uint8Array} data - Bytes to encode
     * @returns {string} Base64 string
     */
    function base64Encode(data) {
        var binary = '';
        for (var i = 0; i < data.length; i++) {
            binary += String.fromCharCode(data[i]);
        }
        return btoa(binary);
    }

    /**
     * Standard Base64 decoding.
     * @param {string} str - Base64 string
     * @returns {Uint8Array} Decoded bytes
     */
    function base64Decode(str) {
        var binary = atob(str);
        var arr = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            arr[i] = binary.charCodeAt(i);
        }
        return arr;
    }

    /**
     * Convert a Uint8Array to a CryptoJS WordArray.
     * @param {Uint8Array} uint8Array - Input bytes
     * @returns {CryptoJS.lib.WordArray} CryptoJS WordArray
     */
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

    /**
     * Convert a CryptoJS WordArray to a Uint8Array.
     * @param {CryptoJS.lib.WordArray} wordArray - Input WordArray
     * @param {number} [length] - Exact byte length (uses sigBytes if not provided)
     * @returns {Uint8Array} Output bytes
     */
    function wordArrayToUint8Array(wordArray, length) {
        var len = length !== undefined ? length : wordArray.sigBytes;
        var words = wordArray.words;
        var result = new Uint8Array(len);
        for (var i = 0; i < len; i++) {
            result[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xFF;
        }
        return result;
    }

    /**
     * Encrypt data using the Fernet algorithm.
     * @param {Uint8Array} data - Plaintext data to encrypt
     * @param {Uint8Array} key - 32-byte key (first 16 = signing, last 16 = encryption)
     * @returns {string} Base64-encoded Fernet token
     */
    function encrypt(data, key) {
        if (key.length !== 32) {
            throw new Error("Fernet key must be 32 bytes");
        }

        var signingKey = key.slice(0, 16);
        var encryptionKey = key.slice(16, 32);

        // Generate random IV (16 bytes for AES-CBC)
        var iv = randomBytes(16);

        // Get current timestamp
        var timestamp = Math.floor(Date.now() / 1000);
        var timestampBytes = numberToUint64(timestamp);

        // Build the payload: version || timestamp || IV || ciphertext
        var versionByte = new Uint8Array([FERNET_VERSION]);

        // Encrypt with AES-128-CBC using PKCS7 padding (CryptoJS default)
        var dataWordArray = uint8ArrayToWordArray(data);
        var keyWordArray = uint8ArrayToWordArray(encryptionKey);
        var ivWordArray = uint8ArrayToWordArray(iv);

        var encrypted = CryptoJS.AES.encrypt(dataWordArray, keyWordArray, {
            iv: ivWordArray,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });

        var ciphertext = wordArrayToUint8Array(encrypted.ciphertext);

        // Build the message to sign: version || timestamp || IV || ciphertext
        var messageToSign = new Uint8Array(
            versionByte.length + timestampBytes.length + iv.length + ciphertext.length
        );
        var offset = 0;
        messageToSign.set(versionByte, offset); offset += versionByte.length;
        messageToSign.set(timestampBytes, offset); offset += timestampBytes.length;
        messageToSign.set(iv, offset); offset += iv.length;
        messageToSign.set(ciphertext, offset);

        // Compute HMAC-SHA256
        var messageWordArray = uint8ArrayToWordArray(messageToSign);
        var signingKeyWordArray = uint8ArrayToWordArray(signingKey);
        var hmac = CryptoJS.HmacSHA256(messageWordArray, signingKeyWordArray);
        var hmacBytes = wordArrayToUint8Array(hmac);

        // Build the full token: messageToSign || HMAC
        var token = new Uint8Array(messageToSign.length + hmacBytes.length);
        token.set(messageToSign, 0);
        token.set(hmacBytes, messageToSign.length);

        return base64Encode(token);
    }

    /**
     * Decrypt a Fernet token.
     * @param {string} token - Base64-encoded Fernet token
     * @param {Uint8Array} key - 32-byte key (first 16 = signing, last 16 = encryption)
     * @param {number} [ttl] - Time-to-live in seconds (optional, 0 = no expiry check)
     * @returns {Uint8Array} Decrypted plaintext data
     */
    function decrypt(token, key, ttl) {
        if (key.length !== 32) {
            throw new Error("Fernet key must be 32 bytes");
        }

        var signingKey = key.slice(0, 16);
        var encryptionKey = key.slice(16, 32);

        // Decode the token
        var tokenBytes;
        try {
            tokenBytes = base64Decode(token);
        } catch (e) {
            throw new Error("Invalid Fernet token: not valid base64");
        }

        // Minimum token size: version(1) + timestamp(8) + IV(16) + HMAC(32) = 57 bytes
        if (tokenBytes.length < 57) {
            throw new Error("Invalid Fernet token: too short");
        }

        // Extract components
        var version = tokenBytes[0];
        if (version !== FERNET_VERSION) {
            throw new Error("Invalid Fernet token: wrong version byte");
        }

        var timestampBytes = tokenBytes.slice(1, 9);
        var iv = tokenBytes.slice(9, 25);
        var hmacBytes = tokenBytes.slice(tokenBytes.length - 32);
        var ciphertext = tokenBytes.slice(25, tokenBytes.length - 32);

        // Verify HMAC
        var messageToVerify = tokenBytes.slice(0, tokenBytes.length - 32);
        var messageWordArray = uint8ArrayToWordArray(messageToVerify);
        var signingKeyWordArray = uint8ArrayToWordArray(signingKey);
        var expectedHmac = CryptoJS.HmacSHA256(messageWordArray, signingKeyWordArray);
        var expectedHmacBytes = wordArrayToUint8Array(expectedHmac);

        // Constant-time comparison
        if (hmacBytes.length !== expectedHmacBytes.length) {
            throw new Error("Invalid Fernet token: HMAC verification failed");
        }
        var diff = 0;
        for (var i = 0; i < hmacBytes.length; i++) {
            diff |= hmacBytes[i] ^ expectedHmacBytes[i];
        }
        if (diff !== 0) {
            throw new Error("Invalid Fernet token: HMAC verification failed");
        }

        // Check timestamp TTL if provided
        if (ttl && ttl > 0) {
            var timestamp = uint64ToNumber(timestampBytes);
            var now = Math.floor(Date.now() / 1000);
            if (Math.abs(now - timestamp) > ttl) {
                throw new Error("Fernet token has expired");
            }
        }

        // Decrypt with AES-128-CBC
        var ciphertextWordArray = uint8ArrayToWordArray(ciphertext);
        var keyWordArray = uint8ArrayToWordArray(encryptionKey);
        var ivWordArray = uint8ArrayToWordArray(iv);

        var decrypted = CryptoJS.AES.decrypt(
            { ciphertext: ciphertextWordArray },
            keyWordArray,
            {
                iv: ivWordArray,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            }
        );

        return wordArrayToUint8Array(decrypted);
    }

    // Export to global scope
    global.Fernet = {
        encrypt: encrypt,
        decrypt: decrypt
    };

})(typeof window !== "undefined" ? window : typeof global !== "undefined" ? global : this);
