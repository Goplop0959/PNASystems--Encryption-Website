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
 * Base85 (Ascii85) encoding and decoding utilities.
 * Implements the Ascii85 variant used in Adobe PostScript/PDF.
 * The ASCII85 alphabet: ! " # $ % & ' ( ) * + , - . / 0-9 : ; < = > ? @ A-Z [ \ ] ^ _ ` a-z { | } ~
 * Character codes 33 (!) through 117 (u), plus special handling for 'z' (all-zero shorthand)
 * and <~ ~> delimiters.
 *
 * This module provides encode and decode functions that operate on Uint8Array.
 */

(function (global) {
    "use strict";

    // Standard ASCII85 charset: 85 consecutive characters from '!' (ASCII 33) to 'u' (ASCII 117)
    // This is the Adobe/PostScript/PDF standard Ascii85 alphabet.
    // 'z' (index 51) is special shorthand for 4 zero bytes.
    var ASCII85_CHARSET = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu";

    /**
     * Encode a Uint8Array to Ascii85 string.
     * Processes input in 4-byte chunks, outputting 5 characters per chunk.
     * Special case: 4 zero bytes are encoded as single 'z'.
     * Handles remaining 1-3 bytes with padding.
     *
     * @param {Uint8Array} data - The binary data to encode
     * @returns {string} The Ascii85 encoded string (without <~ ~> delimiters)
     */
    function encode(data) {
        if (!(data instanceof Uint8Array)) {
            throw new TypeError("Input must be a Uint8Array");
        }

        var result = [];
        var len = data.length;
        var i = 0;

        while (i < len) {
            // Read up to 4 bytes
            var chunkSize = Math.min(4, len - i);
            var value = 0;
            for (var j = 0; j < 4; j++) {
                value = (value << 8) | (j < chunkSize ? data[i + j] : 0);
            }

            // Special case: 4 zero bytes -> 'z'
            if (value === 0 && chunkSize === 4) {
                result.push('z');
                i += 4;
                continue;
            }

            // Encode 5 characters (base-85 digits, reversed)
            var chars = [];
            for (var k = 0; k < 5; k++) {
                chars.push(ASCII85_CHARSET.charAt(value % 85));
                value = Math.floor(value / 85);
            }
            chars.reverse();

            // For partial chunks, output only the needed characters
            // 1 byte remaining -> 2 chars, 2 bytes -> 3 chars, 3 bytes -> 4 chars
            var outputCount = chunkSize + 1;
            result.push(chars.slice(0, outputCount).join(''));

            i += chunkSize;
        }

        return result.join('');
    }

    /**
     * Decode an Ascii85 string back to Uint8Array.
     * Handles 'z' shorthand, whitespace stripping, and partial final groups.
     *
     * @param {string} str - The Ascii85 encoded string
     * @returns {Uint8Array} The decoded binary data
     */
    function decode(str) {
        if (typeof str !== "string") {
            throw new TypeError("Input must be a string");
        }

        // Strip <~ and ~> delimiters if present
        var s = str;
        if (s.substring(0, 2) === "<~") {
            s = s.substring(2);
        }
        if (s.length >= 2 && s.substring(s.length - 2) === "~>") {
            s = s.substring(0, s.length - 2);
        }

        // Remove whitespace
        s = s.replace(/\s/g, '');

        if (s.length === 0) {
            return new Uint8Array(0);
        }

        // Calculate output size: each 5 chars -> 4 bytes
        // 'z' counts as 1 char -> 4 bytes
        var outputSize = 0;
        var temp = s;
        while (temp.length > 0) {
            if (temp[0] === 'z') {
                outputSize += 4;
                temp = temp.substring(1);
            } else {
                var groupLen = Math.min(5, temp.length);
                outputSize += groupLen - 1;
                temp = temp.substring(groupLen);
            }
        }

        var result = new Uint8Array(outputSize);
        var outIdx = 0;
        var idx = 0;

        while (idx < s.length) {
            if (s[idx] === 'z') {
                // 'z' shorthand for 4 zero bytes
                result[outIdx++] = 0;
                result[outIdx++] = 0;
                result[outIdx++] = 0;
                result[outIdx++] = 0;
                idx++;
            } else {
                // Read group of up to 5 characters
                var groupLen = Math.min(5, s.length - idx);
                var group = s.substring(idx, idx + groupLen);

                // Pad with 'u' (last char, value 84) to make 5 chars
                var padded = group;
                while (padded.length < 5) {
                    padded += 'u';
                }

                // Decode 5 chars to a 32-bit value
                var value = 0;
                for (var k = 0; k < 5; k++) {
                    var charIdx = ASCII85_CHARSET.indexOf(padded[k]);
                    if (charIdx === -1) {
                        throw new Error("Invalid Ascii85 character: " + padded[k]);
                    }
                    value = value * 85 + charIdx;
                }

                // Extract bytes (only the number of bytes corresponding to the group length)
                var byteCount = groupLen - 1;
                for (var j = 0; j < byteCount; j++) {
                    result[outIdx++] = (value >> (24 - j * 8)) & 0xFF;
                }

                idx += groupLen;
            }
        }

        return result;
    }

    // Export to global scope
    global.Base85 = {
        encode: encode,
        decode: decode
    };

})(typeof window !== "undefined" ? window : typeof global !== "undefined" ? global : this);
