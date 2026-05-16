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
 * Application Logic - UI event handling, tab navigation, and crypto operations.
 *
 * This file handles:
 *   - Tab switching between Encrypt Text, Decrypt Text, Encrypt File, Decrypt File
 *   - Button click handlers for all crypto operations
 *   - File reading and download triggers
 *   - Clipboard copy functionality
 *   - Toast notifications for user feedback
 *   - Loading state management during crypto operations
 */

(function () {
    "use strict";

    // ============================================================
    // DOM Element References
    // ============================================================

    // Tab navigation
    var tabButtons = document.querySelectorAll(".tab-btn");
    var tabContents = document.querySelectorAll(".tab-content");

    // Encrypt Text elements
    var etPlaintext = document.getElementById("et-plaintext");
    var etPassword = document.getElementById("et-password");
    var etMethod = document.getElementById("et-method");
    var etEncryptBtn = document.getElementById("et-encrypt-btn");
    var etOutput = document.getElementById("et-output");
    var etCopyBtn = document.getElementById("et-copy-btn");

    // Decrypt Text elements
    var dtCiphertext = document.getElementById("dt-ciphertext");
    var dtPassword = document.getElementById("dt-password");
    var dtDecryptBtn = document.getElementById("dt-decrypt-btn");
    var dtOutput = document.getElementById("dt-output");
    var dtCopyBtn = document.getElementById("dt-copy-btn");

    // Encrypt File elements
    var efFile = document.getElementById("ef-file");
    var efPassword = document.getElementById("ef-password");
    var efMethod = document.getElementById("ef-method");
    var efEncryptBtn = document.getElementById("ef-encrypt-btn");

    // Decrypt File elements
    var dfFile = document.getElementById("df-file");
    var dfPassword = document.getElementById("df-password");
    var dfDecryptBtn = document.getElementById("df-decrypt-btn");

    // Toast container
    var toastContainer = document.getElementById("toast-container");

    // ============================================================
    // Tab Navigation
    // ============================================================

    tabButtons.forEach(function (btn) {
        btn.addEventListener("click", function () {
            var tabId = btn.getAttribute("data-tab");

            // Deactivate all tabs
            tabButtons.forEach(function (b) {
                b.classList.remove("active");
                b.setAttribute("aria-selected", "false");
            });
            tabContents.forEach(function (c) {
                c.classList.remove("active");
            });

            // Activate selected tab
            btn.classList.add("active");
            btn.setAttribute("aria-selected", "true");
            document.getElementById(tabId).classList.add("active");
        });
    });

    // ============================================================
    // Toast Notifications
    // ============================================================

    function showToast(message, type) {
        var toast = document.createElement("div");
        toast.className = "toast " + (type || "info");
        toast.textContent = message;
        toastContainer.appendChild(toast);

        // Remove after animation completes (3 seconds)
        setTimeout(function () {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 3000);
    }

    // ============================================================
    // Loading State
    // ============================================================

    function setLoading(btn, loading) {
        if (loading) {
            btn.classList.add("loading");
            btn.dataset.originalText = btn.textContent;
            btn.innerHTML = '<span class="spinner"></span>' + btn.textContent;
            btn.disabled = true;
        } else {
            btn.classList.remove("loading");
            btn.textContent = btn.dataset.originalText || btn.textContent;
            btn.disabled = false;
        }
    }

    // ============================================================
    // Output Display Helpers
    // ============================================================

    function setOutput(outputEl, text, isError) {
        outputEl.textContent = text;
        outputEl.classList.remove("has-content", "error");
        if (isError) {
            outputEl.classList.add("error");
        } else if (text) {
            outputEl.classList.add("has-content");
        }
    }

    // ============================================================
    // Clipboard Copy
    // ============================================================

    function copyToClipboard(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(function () {
                showToast("Copied to clipboard", "success");
            }).catch(function () {
                fallbackCopy(text);
            });
        } else {
            fallbackCopy(text);
        }
    }

    function fallbackCopy(text) {
        var textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand("copy");
            showToast("Copied to clipboard", "success");
        } catch (e) {
            showToast("Failed to copy", "error");
        }
        document.body.removeChild(textarea);
    }

    // ============================================================
    // File Download Helper
    // ============================================================

    function downloadFile(data, filename) {
        var blob = new Blob([data], { type: "application/octet-stream" });
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // ============================================================
    // Read File as ArrayBuffer
    // ============================================================

    function readFileAsArrayBuffer(file) {
        return new Promise(function (resolve, reject) {
            var reader = new FileReader();
            reader.onload = function () {
                resolve(new Uint8Array(reader.result));
            };
            reader.onerror = function () {
                reject(new Error("Failed to read file"));
            };
            reader.readAsArrayBuffer(file);
        });
    }

    // ============================================================
    // Encrypt Text Handler
    // ============================================================

    etEncryptBtn.addEventListener("click", async function () {
        var plaintext = etPlaintext.value.trim();
        var password = etPassword.value;
        var methodId = parseInt(etMethod.value, 10);

        if (!plaintext) {
            showToast("Please enter text to encrypt", "error");
            return;
        }
        if (!password) {
            showToast("Please enter a password", "error");
            return;
        }

        setLoading(etEncryptBtn, true);
        setOutput(etOutput, "", false);

        try {
            var encrypted = await CryptoEngine.encryptBytes(methodId, new TextEncoder().encode(plaintext), password);
            var b64 = btoa(String.fromCharCode.apply(null, encrypted));
            setOutput(etOutput, b64, false);
            showToast("Encryption successful", "success");
        } catch (e) {
            setOutput(etOutput, "Error: " + e.message, true);
            showToast("Encryption failed", "error");
        } finally {
            setLoading(etEncryptBtn, false);
        }
    });

    // ============================================================
    // Decrypt Text Handler
    // ============================================================

    dtDecryptBtn.addEventListener("click", async function () {
        var ciphertext = dtCiphertext.value.trim();
        var password = dtPassword.value;

        if (!ciphertext) {
            showToast("Please enter encrypted text", "error");
            return;
        }
        if (!password) {
            showToast("Please enter a password", "error");
            return;
        }

        setLoading(dtDecryptBtn, true);
        setOutput(dtOutput, "", false);

        try {
            var decrypted = await CryptoEngine.decryptBytes(ciphertext, password);
            var plaintext = new TextDecoder().decode(decrypted);
            setOutput(dtOutput, plaintext, false);
            showToast("Decryption successful", "success");
        } catch (e) {
            setOutput(dtOutput, "Error: " + e.message, true);
            showToast("Decryption failed", "error");
        } finally {
            setLoading(dtDecryptBtn, false);
        }
    });

    // ============================================================
    // Encrypt File Handler
    // ============================================================

    efEncryptBtn.addEventListener("click", async function () {
        var file = efFile.files[0];
        var password = efPassword.value;
        var methodId = parseInt(efMethod.value, 10);

        if (!file) {
            showToast("Please select a file", "error");
            return;
        }
        if (!password) {
            showToast("Please enter a password", "error");
            return;
        }

        setLoading(efEncryptBtn, true);

        try {
            var fileData = await readFileAsArrayBuffer(file);
            var encrypted = await CryptoEngine.encryptBytes(methodId, fileData, password);

            // Construct output filename
            var originalName = file.name;
            var encFilename = originalName + ".pnae";

            downloadFile(encrypted, encFilename);
            showToast("File encrypted and downloaded", "success");
        } catch (e) {
            showToast("Encryption failed: " + e.message, "error");
        } finally {
            setLoading(efEncryptBtn, false);
        }
    });

    // ============================================================
    // Decrypt File Handler
    // ============================================================

    dfDecryptBtn.addEventListener("click", async function () {
        var file = dfFile.files[0];
        var password = dfPassword.value;

        if (!file) {
            showToast("Please select an encrypted file", "error");
            return;
        }
        if (!password) {
            showToast("Please enter a password", "error");
            return;
        }

        setLoading(dfDecryptBtn, true);

        try {
            var fileData = await readFileAsArrayBuffer(file);
            var b64 = btoa(String.fromCharCode.apply(null, fileData));
            var decrypted = await CryptoEngine.decryptBytes(b64, password);

            // Construct output filename by stripping .pnae extension
            var originalName = file.name;
            var decFilename;
            if (originalName.toLowerCase().endsWith(".pnae")) {
                decFilename = originalName.slice(0, -5);
            } else {
                decFilename = "decrypted_" + originalName;
            }

            downloadFile(decrypted, decFilename);
            showToast("File decrypted and downloaded", "success");
        } catch (e) {
            showToast("Decryption failed: " + e.message, "error");
        } finally {
            setLoading(dfDecryptBtn, false);
        }
    });

    // ============================================================
    // Copy Button Handlers
    // ============================================================

    etCopyBtn.addEventListener("click", function () {
        var text = etOutput.textContent.trim();
        if (text && !etOutput.classList.contains("error")) {
            copyToClipboard(text);
        } else {
            showToast("Nothing to copy", "info");
        }
    });

    dtCopyBtn.addEventListener("click", function () {
        var text = dtOutput.textContent.trim();
        if (text && !dtOutput.classList.contains("error")) {
            copyToClipboard(text);
        } else {
            showToast("Nothing to copy", "info");
        }
    });

    // ============================================================
    // Keyboard Shortcuts
    // ============================================================

    document.addEventListener("keydown", function (e) {
        // Ctrl/Cmd + Enter to trigger active tab's primary action
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
            e.preventDefault();
            var activeTab = document.querySelector(".tab-content.active");
            if (activeTab) {
                var btn = activeTab.querySelector(".btn-primary");
                if (btn && !btn.disabled) {
                    btn.click();
                }
            }
        }
    });

})();
