![image](https://github.com/JWally/BrowserPrivateKeyDemo/assets/2482935/b55c569a-b7dc-4731-a11d-d441a92e4297)

# Secure Private Key Creation and Storage in the Browser

## What Is This?
The following code snippet shows how to store a private key that can be _USED_ in your browser, but _CANNOT_ be extracted or stolen.

## Why Should I Care?
You (or FireBase, SupaBase, Cognito, etc) can use this approach to make session-token-theft _EXTREMELY_ difficult.

## Prove It!
In your browser, open the dev console (`CTRL+SHFT+I`), then copy and paste the following code snippet in:

```javascript
/**
 * Name of the IndexedDB database.
 * @type {string}
 */
const dbName = "CryptoKeys";

/**
 * Name of the object store within the IndexedDB.
 * @type {string}
 */
const storeName = "keys";

/**
 * Identifier for the key pair stored in the database.
 * @type {string}
 */
const keyPairName = "ecdsaKeyPair";

/**
 * Opens or creates an IndexedDB database and ensures it contains the required object store.
 * @returns {Promise<IDBDatabase>} A promise that resolves with the database object on success.
 */
function openDatabase() {
  return new Promise((resolve, reject) => {
    // Attempt to open the database
    const request = indexedDB.open(dbName, 1);

    // Create the store if this is the first time the database is being opened (i.e., on upgrade)
    request.onupgradeneeded = function(event) {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(storeName)) {
        db.createObjectStore(storeName);
      }
    };

    // Resolve the promise with the database instance on successful opening
    request.onsuccess = () => resolve(request.result);

    // Reject the promise with the error on failure
    request.onerror = () => reject(request.error);
  });
}

/**
 * Retrieves an existing ECDSA key pair from the database or generates a new one if not found.
 * @param {IDBDatabase} db - The database instance.
 * @returns {Promise<CryptoKeyPair>} A promise that resolves with the key pair.
 */
async function getKeyPair(db) {
  return new Promise(async (resolve, reject) => {
    const transaction = db.transaction([storeName], "readwrite");
    const store = transaction.objectStore(storeName);
    const request = store.get(keyPairName);

    request.onsuccess = async (event) => {
      if (request.result) {
        // Resolve with the found key pair
        resolve(request.result);
      } else {
        // Generate a new key pair if not found
        try {
          const keyPair = await crypto.subtle.generateKey(
            { name: "ECDSA", namedCurve: "P-256" },
            false, // THIS MUST BE FALSE!!! OTHERWISE THE PRIVATE KEY IS EXPOSED!!!
            ["sign", "verify"]
          );

          // Save the new key pair in the database
          const putTransaction = db.transaction([storeName], "readwrite");
          const putStore = putTransaction.objectStore(storeName);
          const putRequest = putStore.put(keyPair, keyPairName);
          putRequest.onsuccess = () => resolve(keyPair);
          putRequest.onerror = () => reject(putRequest.error);
        } catch (error) {
          reject(error);
        }
      }
    };
    request.onerror = () => reject(request.error);
  });
}

/**
 * Signs a message using a given ECDSA private key.
 * @param {CryptoKey} privateKey - The private key to sign the message with.
 * @param {string} message - The message to sign.
 * @returns {Promise<ArrayBuffer>} The signature as an ArrayBuffer.
 */
async function signMessage(privateKey, message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  return crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    privateKey,
    data
  );
}

/**
 * Verifies a signature against the given message using an ECDSA public key.
 * @param {CryptoKey} publicKey - The public key to verify the signature with.
 * @param {ArrayBuffer} signature - The signature to verify.
 * @param {string} message - The message that was signed.
 * @returns {Promise<boolean>} A boolean indicating whether the signature is valid.
 */
async function verifySignature(publicKey, signature, message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  return crypto.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    publicKey,
    signature,
    data
  );
}

/**
 * Converts an ArrayBuffer into a base64 encoded string.
 * @param {ArrayBuffer} buffer - The ArrayBuffer to convert.
 * @returns {string} The base64 encoded string.
 */
function bufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

/**
 * Converts a CryptoKey into a PEM-formatted string.
 * @param {CryptoKey} key - The CryptoKey to convert.
 * @returns {Promise<string>} The PEM-formatted string of the key.
 */
async function exportPublicKey(key) {
  // Export the public key in the SPKI (Subject Public Key Info) format
  const exported = await crypto.subtle.exportKey('spki', key);
  // Convert the exported ArrayBuffer to a Base64 string
  const base64 = window.btoa(String.fromCharCode(...new Uint8Array(exported)));
  // Format the Base64 string as PEM
  return base64;
}

/**
 * Main function that orchestrates the creation or retrieval of a key pair,
 * signs a message, exports the public key, and verifies the signature, logging the results to the console.
 */
async function main() {
  const db = await openDatabase();
  const keyPair = await getKeyPair(db);

  const message = "base_64_of_jwt";
  const signatureBuffer = await signMessage(keyPair.privateKey, message);
  const signatureBase64 = bufferToBase64(signatureBuffer);

  // Export and log the public key in PEM format
  const publicKeyPEM = await exportPublicKey(keyPair.publicKey);

  const instructions = `
  ------------------------------------------
  ------------------------------------------
  Below are:
    1. Your public-key (which should be the same after reloading the browser)
    2. A message being signed with your _PRIVATE_KEY_
    3. The Message's Signature with your _PRIVATE_KEY_
    4. The Signature's verification with your _public_key_

  Try Extracting or viewing your private key data!!!
  If I did this right...YOU CAN'T!

  ------------------------------------------
  ------------------------------------------
  `;
  console.log(instructions);
  console.log(`Message: ${message}`);
  console.log(`Public Key: ${publicKeyPEM}`);
  console.log(`Signature: ${signatureBase64}`);

  const isValid = await verifySignature(keyPair.publicKey, signatureBuffer, message);
  console.log(`Verification: ${isValid ? "Successful" : "Failed"}`);
}

// Run the main function and log errors to the console
main().catch(console.error);

```

## How Does This Help With Session-Token Theft?

1. When the user is authenticating, have them sign their public-key with their private-key and send it to you.
2. Put the user's public-key inside of a JWT
3. For extra protection, put the user's IP-Address in the JWT as well

Every time the user makes a request to something protected, in addition to sending the JWT, the user should send the following headers:
```
x-base64-jwt: {a base 64 encoded, stringifed version of the JWT being sent}
x-base64-jwt-signature: {the ECDSA Signature of the x-base64-jwt}
```

Because the JWT contains the server-verified public key; I can verify the current signature (x-base64-jwt-signature) with it. If it fails, I proceed _exactly_ as if someone tampered a JWT in any other framework.

If I want to be _extra_ secure, I can refuse request whose IP Address is different than what's in the JWT. 
