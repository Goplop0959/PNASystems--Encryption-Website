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
 * All encryption methods are applied in a chained pipeline automatically.
 * Detailed console.error logging is included throughout for debugging.
 */

(function () {
    "use strict";

    // ============================================================
    // Console Logging Helpers
    // ============================================================

    function appLog(tag, msg, data) {
        var prefix = "[App:" + tag + "]";
        if (data !== undefined) {
            console.log(prefix, msg, data);
        } else {
            console.log(prefix, msg);
        }
    }

    function appError(tag, msg, err) {
        var prefix = "[App:" + tag + "]";
        if (err instanceof Error) {
            console.error(prefix, msg, err.message, err.stack);
        } else {
            console.error(prefix, msg, err);
        }
    }

    function appWarn(tag, msg) {
        console.warn("[App:" + tag + "]", msg);
    }

    // ============================================================
    // DOM Element References
    // ============================================================

    var tabButtons = document.querySelectorAll(".tab-btn");
    var tabContents = document.querySelectorAll(".tab-content");

    // Encrypt Text elements
    var etPlaintext = document.getElementById("et-plaintext");
    var etPassword = document.getElementById("et-password");
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
    var efEncryptBtn = document.getElementById("ef-encrypt-btn");

    // Decrypt File elements
    var dfFile = document.getElementById("df-file");
    var dfPassword = document.getElementById("df-password");
    var dfDecryptBtn = document.getElementById("df-decrypt-btn");

    // Toast container
    var toastContainer = document.getElementById("toast-container");

    // ============================================================
    // Dependency Verification
    // ============================================================

    (function verifyDependencies() {
        appLog("init", "Verifying dependencies...");

        if (typeof CryptoJS === "undefined") {
            appError("init", "CryptoJS is not loaded. The CDN script may have failed to load.", null);
            showToast("Error: CryptoJS library failed to load. Check your internet connection.", "error");
        } else {
            appLog("init", "CryptoJS loaded successfully. Version info:", typeof CryptoJS.lib !== "undefined" ? "lib present" : "lib missing");
            appLog("init", "CryptoJS.AES available: " + (typeof CryptoJS.AES !== "undefined"));
            appLog("init", "CryptoJS.TripleDES available: " + (typeof CryptoJS.TripleDES !== "undefined"));
            appLog("init", "CryptoJS.Rabbit available: " + (typeof CryptoJS.Rabbit !== "undefined"));
            appLog("init", "CryptoJS.Blowfish available: " + (typeof CryptoJS.Blowfish !== "undefined"));
            appLog("init", "CryptoJS.HmacSHA256 available: " + (typeof CryptoJS.HmacSHA256 !== "undefined"));
        }

        if (typeof CryptoEngine === "undefined") {
            appError("init", "CryptoEngine is not loaded. crypto-engine.js may have failed.", null);
            showToast("Error: Crypto engine failed to load.", "error");
        } else {
            appLog("init", "CryptoEngine loaded successfully.");
            appLog("init", "Encryption pipeline: " + CryptoEngine.ENCRYPT_PIPELINE.map(function(id) {
                return CryptoEngine.METHOD_INFO[id].name;
            }).join(" → "));
        }

        if (typeof Fernet === "undefined") {
            appError("init", "Fernet module is not loaded.", null);
        } else {
            appLog("init", "Fernet module loaded successfully.");
        }

        if (typeof Base85 === "undefined") {
            appError("init", "Base85 module is not loaded.", null);
        } else {
            appLog("init", "Base85 module loaded successfully.");
        }

        if (typeof crypto === "undefined" || typeof crypto.subtle === "undefined") {
            appError("init", "Web Crypto API is not available. This browser may not support encryption.", null);
            showToast("Warning: Web Crypto API not available. Encryption may not work.", "error");
        } else {
            appLog("init", "Web Crypto API available.");
        }

        appLog("init", "Application initialization complete.");
    })();

    // ============================================================
    // Tab Navigation
    // ============================================================

    tabButtons.forEach(function (btn) {
        btn.addEventListener("click", function () {
            var tabId = btn.getAttribute("data-tab");
            appLog("tabs", "Switching to tab: " + tabId);

            tabButtons.forEach(function (b) {
                b.classList.remove("active");
                b.setAttribute("aria-selected", "false");
            });
            tabContents.forEach(function (c) {
                c.classList.remove("active");
            });

            btn.classList.add("active");
            btn.setAttribute("aria-selected", "true");
            var target = document.getElementById(tabId);
            if (target) {
                target.classList.add("active");
            } else {
                appError("tabs", "Tab content element not found for ID: " + tabId, null);
            }
        });
    });

    // ============================================================
    // Toast Notifications
    // ============================================================

    function showToast(message, type) {
        appLog("toast", "Showing toast: " + message + " (type: " + (type || "info") + ")");
        var toast = document.createElement("div");
        toast.className = "toast " + (type || "info");
        toast.textContent = message;
        toastContainer.appendChild(toast);

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
            appLog("ui", "Button set to loading state: " + btn.id);
        } else {
            btn.classList.remove("loading");
            btn.textContent = btn.dataset.originalText || btn.textContent;
            btn.disabled = false;
            appLog("ui", "Button loading state cleared: " + btn.id);
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
                appLog("clipboard", "Copied to clipboard successfully via navigator.clipboard");
                showToast("Copied to clipboard", "success");
            }).catch(function (err) {
                appError("clipboard", "navigator.clipboard.writeText failed, falling back", err);
                fallbackCopy(text);
            });
        } else {
            appWarn("clipboard", "navigator.clipboard not available, using fallback");
            fallbackCopy(text);
        }
    }

    function fallbackCopy(text) {
        try {
            var textarea = document.createElement("textarea");
            textarea.value = text;
            textarea.style.position = "fixed";
            textarea.style.opacity = "0";
            document.body.appendChild(textarea);
            textarea.select();
            var success = document.execCommand("copy");
            document.body.removeChild(textarea);
            if (success) {
                appLog("clipboard", "Copied to clipboard via fallback execCommand");
                showToast("Copied to clipboard", "success");
            } else {
                appError("clipboard", "execCommand('copy') returned false", null);
                showToast("Failed to copy to clipboard", "error");
            }
        } catch (err) {
            appError("clipboard", "Fallback copy failed", err);
            showToast("Failed to copy to clipboard", "error");
        }
    }

    // ============================================================
    // File Download Helper
    // ============================================================

    function downloadFile(data, filename) {
        try {
            appLog("download", "Triggering download: " + filename + " (" + data.length + " bytes)");
            var blob = new Blob([data], { type: "application/octet-stream" });
            var url = URL.createObjectURL(blob);
            var a = document.createElement("a");
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            appLog("download", "Download triggered successfully");
        } catch (err) {
            appError("download", "Failed to trigger download", err);
            showToast("Failed to download file: " + err.message, "error");
            throw err;
        }
    }

    // ============================================================
    // Read File as ArrayBuffer
    // ============================================================

    function readFileAsArrayBuffer(file) {
        return new Promise(function (resolve, reject) {
            appLog("file", "Reading file: " + file.name + " (" + file.size + " bytes, type: " + file.type + ")");
            var reader = new FileReader();
            reader.onload = function () {
                var result = new Uint8Array(reader.result);
                appLog("file", "File read successfully: " + result.length + " bytes");
                resolve(result);
            };
            reader.onerror = function () {
                var err = new Error("FileReader error: " + (reader.error ? reader.error.message : "unknown error"));
                appError("file", "Failed to read file: " + file.name, err);
                reject(err);
            };
            reader.readAsArrayBuffer(file);
        });
    }

    // ============================================================
    // Encrypt Text Handler
    // ============================================================

    etEncryptBtn.addEventListener("click", async function () {
        appLog("encryptText", "Encrypt text button clicked");
        var plaintext = etPlaintext.value;
        var password = etPassword.value;

        if (!plaintext || plaintext.trim().length === 0) {
            appWarn("encryptText", "Validation failed: plaintext is empty");
            showToast("Please enter text to encrypt", "error");
            return;
        }
        if (!password || password.length === 0) {
            appWarn("encryptText", "Validation failed: password is empty");
            showToast("Please enter a password", "error");
            return;
        }

        appLog("encryptText", "Input validation passed. Plaintext length: " + plaintext.length + " chars, Password length: " + password.length + " chars");

        setLoading(etEncryptBtn, true);
        setOutput(etOutput, "", false);

        try {
            appLog("encryptText", "Calling CryptoEngine.encryptText...");
            var b64 = await CryptoEngine.encryptText(plaintext, password);
            setOutput(etOutput, b64, false);
            appLog("encryptText", "Encryption successful. Output length: " + b64.length + " Base64 characters");
            showToast("Encryption successful", "success");
        } catch (err) {
            setOutput(etOutput, "Error: " + err.message, true);
            appError("encryptText", "Encryption failed", err);
            showToast("Encryption failed: " + err.message, "error");
        } finally {
            setLoading(etEncryptBtn, false);
        }
    });

    // ============================================================
    // Decrypt Text Handler
    // ============================================================

    dtDecryptBtn.addEventListener("click", async function () {
        appLog("decryptText", "Decrypt text button clicked");
        var ciphertext = dtCiphertext.value.trim();
        var password = dtPassword.value;

        if (!ciphertext || ciphertext.length === 0) {
            appWarn("decryptText", "Validation failed: ciphertext is empty");
            showToast("Please enter encrypted text", "error");
            return;
        }
        if (!password || password.length === 0) {
            appWarn("decryptText", "Validation failed: password is empty");
            showToast("Please enter a password", "error");
            return;
        }

        appLog("decryptText", "Input validation passed. Ciphertext length: " + ciphertext.length + " chars");

        setLoading(dtDecryptBtn, true);
        setOutput(dtOutput, "", false);

        try {
            appLog("decryptText", "Calling CryptoEngine.decryptText...");
            var plaintext = await CryptoEngine.decryptText(ciphertext, password);
            setOutput(dtOutput, plaintext, false);
            appLog("decryptText", "Decryption successful. Plaintext length: " + plaintext.length + " chars");
            showToast("Decryption successful", "success");
        } catch (err) {
            setOutput(dtOutput, "Error: " + err.message, true);
            appError("decryptText", "Decryption failed", err);
            showToast("Decryption failed: " + err.message, "error");
        } finally {
            setLoading(dtDecryptBtn, false);
        }
    });

    // ============================================================
    // Encrypt File Handler
    // ============================================================

    efEncryptBtn.addEventListener("click", async function () {
        appLog("encryptFile", "Encrypt file button clicked");
        var file = efFile.files[0];
        var password = efPassword.value;

        if (!file) {
            appWarn("encryptFile", "Validation failed: no file selected");
            showToast("Please select a file", "error");
            return;
        }
        if (!password || password.length === 0) {
            appWarn("encryptFile", "Validation failed: password is empty");
            showToast("Please enter a password", "error");
            return;
        }

        appLog("encryptFile", "Input validation passed. File: " + file.name + " (" + file.size + " bytes)");

        setLoading(efEncryptBtn, true);

        try {
            appLog("encryptFile", "Reading file data...");
            var fileData = await readFileAsArrayBuffer(file);
            appLog("encryptFile", "Calling CryptoEngine.encryptBytes...");
            var encrypted = await CryptoEngine.encryptBytes(fileData, password);

            var encFilename = file.name + ".pnae";
            appLog("encryptFile", "Encrypted size: " + encrypted.length + " bytes. Downloading as: " + encFilename);

            downloadFile(encrypted, encFilename);
            showToast("File encrypted and downloaded", "success");
        } catch (err) {
            appError("encryptFile", "File encryption failed", err);
            showToast("Encryption failed: " + err.message, "error");
        } finally {
            setLoading(efEncryptBtn, false);
        }
    });

    // ============================================================
    // Decrypt File Handler
    // ============================================================

    dfDecryptBtn.addEventListener("click", async function () {
        appLog("decryptFile", "Decrypt file button clicked");
        var file = dfFile.files[0];
        var password = dfPassword.value;

        if (!file) {
            appWarn("decryptFile", "Validation failed: no file selected");
            showToast("Please select an encrypted file", "error");
            return;
        }
        if (!password || password.length === 0) {
            appWarn("decryptFile", "Validation failed: password is empty");
            showToast("Please enter a password", "error");
            return;
        }

        appLog("decryptFile", "Input validation passed. File: " + file.name + " (" + file.size + " bytes)");

        setLoading(dfDecryptBtn, true);

        try {
            appLog("decryptFile", "Reading encrypted file data...");
            var fileData = await readFileAsArrayBuffer(file);
            var b64 = btoa(String.fromCharCode.apply(null, fileData));
            appLog("decryptFile", "File converted to Base64: " + b64.length + " chars");

            appLog("decryptFile", "Calling CryptoEngine.decryptBytes...");
            var decrypted = await CryptoEngine.decryptBytes(b64, password);

            var decFilename;
            if (file.name.toLowerCase().endsWith(".pnae")) {
                decFilename = file.name.slice(0, -5);
            } else {
                decFilename = "decrypted_" + file.name;
            }

            appLog("decryptFile", "Decrypted size: " + decrypted.length + " bytes. Downloading as: " + decFilename);

            downloadFile(decrypted, decFilename);
            showToast("File decrypted and downloaded", "success");
        } catch (err) {
            appError("decryptFile", "File decryption failed", err);
            showToast("Decryption failed: " + err.message, "error");
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
            appLog("copy", "Copying encrypted text output (" + text.length + " chars)");
            copyToClipboard(text);
        } else {
            appWarn("copy", "Nothing to copy from encrypt text output");
            showToast("Nothing to copy", "info");
        }
    });

    dtCopyBtn.addEventListener("click", function () {
        var text = dtOutput.textContent.trim();
        if (text && !dtOutput.classList.contains("error")) {
            appLog("copy", "Copying decrypted text output (" + text.length + " chars)");
            copyToClipboard(text);
        } else {
            appWarn("copy", "Nothing to copy from decrypt text output");
            showToast("Nothing to copy", "info");
        }
    });

    // ============================================================
    // Keyboard Shortcuts
    // ============================================================

    document.addEventListener("keydown", function (e) {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
            e.preventDefault();
            appLog("keyboard", "Ctrl+Enter detected, triggering active tab action");
            var activeTab = document.querySelector(".tab-content.active");
            if (activeTab) {
                var btn = activeTab.querySelector(".btn-primary");
                if (btn && !btn.disabled) {
                    appLog("keyboard", "Clicking button: " + btn.id);
                    btn.click();
                } else {
                    appWarn("keyboard", "No active button found or button is disabled");
                }
            } else {
                appWarn("keyboard", "No active tab found");
            }
        }
    });

    // ============================================================
    // Global Error Handler
    // ============================================================

    window.addEventListener("error", function (e) {
        appError("global", "Uncaught error: " + e.message, e.error);
    });

    window.addEventListener("unhandledrejection", function (e) {
        appError("global", "Unhandled promise rejection: " + e.reason, e.reason instanceof Error ? e.reason : null);
    });

    appLog("init", "App.js event handlers registered successfully.");

})();
