const CRYPTO_SALT = new TextEncoder().encode("anon-static-salt-v1");

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function deriveKeyFromPassword(password) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: CRYPTO_SALT,
      iterations: 250000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptMessage(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );
  return {
    ciphertext: bufferToBase64(ciphertextBuffer),
    iv: bufferToBase64(iv.buffer),
  };
}

async function decryptMessage(key, ciphertextB64, ivB64) {
  try {
    const ciphertext = base64ToBuffer(ciphertextB64);
    const iv = base64ToBuffer(ivB64);
    const plainBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) },
      key,
      ciphertext
    );
    return new TextDecoder().decode(plainBuffer);
  } catch (e) {
    return "[decryption failed]";
  }
}

function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function getDeviceId() {
  const stored = localStorage.getItem("anon_device_id");
  if (stored) return stored;
  const fresh = crypto.randomUUID();
  localStorage.setItem("anon_device_id", fresh);
  return fresh;
}
