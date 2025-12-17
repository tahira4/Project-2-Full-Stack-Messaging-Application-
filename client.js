/**
 * client.js
 * ----------
 * Role: Secure client for the full-stack messaging project.
 *
 * What the client does (mapped to steps):
 *   Step 1  (serialization demo): Fetch the Student JSON and build a Student object
 *   Step 2  (connectivity): Talk to the REST server endpoints
 *   Step 3  (keygen): Generate a fresh AES-256 session key
 *   Step 4  (key exchange): Fetch server's RSA public key (DER Base64)
 *   Step 5  (key exchange): RSA-encrypt the AES key with OAEP-SHA256, POST /session
 *   Step 6  (encryption):  AES-GCM encrypt serialized Student JSON
 *   Step 7  (integrity):   Compute HMAC-SHA256 over the ciphertext
 *   Step 8–10: Send to /message → server verifies HMAC and decrypts →
 *              client receives plaintext and deserializes back to Student
 *
 * Run (in a separate terminal from the server):
 *   node client.js
 */

const crypto  = require("crypto");
const Student = require("./student");


const SERVER = "http://localhost:8080";

/** Pretty fingerprint helper (SHA256 over public key DER). */
const sha256Base64 = (buf) => crypto.createHash("sha256").update(buf).digest("base64");

/** HMAC helper used in Step 7. */
const computeHMACSHA256 = (key, data) =>
  crypto.createHmac("sha256", key).update(data).digest();

/**
 * AES-256-GCM encryption.
 * - key:   32-byte Buffer
 * - nonce: randomly generated 12-byte Buffer (GCM standard)
 * Output:
 *   { nonce, ciphertext }, where ciphertext = <encrypted data || 16-byte tag>
 */
function encryptAESGCM(key, plaintextBuf) {
  const nonce  = crypto.randomBytes(12);               // Create a fresh 12-byte IV (nonce) for this message (GCM standard).
  const cipher = crypto.createCipheriv("aes-256-gcm",  // Build a streaming cipher instance:
                                       key,            //   - 32-byte AES key (AES-256)
                                       nonce);         //   - per-message nonce (must be unique for the key)

  const enc1   = cipher.update(plaintextBuf);          // Encrypt the bulk of the plaintext (returns a Buffer chunk).
  const enc2   = cipher.final();                       // Flush and finalize encryption; returns any remaining bytes.

  const tag    = cipher.getAuthTag();                  // Get the 16-byte authentication tag (integrity + authenticity).

  const ciphertext = Buffer.concat([enc1, enc2, tag]); // Package as <ciphertext || tag> so we can send/store in one blob.

  return { nonce, ciphertext };                        // Caller will Base64-encode these to transmit over JSON/HTTP.
}
async function main() {
/*-------------------------------------------------------------------
                    Step 1: Deserialize JSON 
---------------------------------------------------------------------*/
// The server serializes a Student (Step 1 demo). We fetch it and create a
// Student instance on the client side (also proves connectivity).

const sResp = await fetch(`${SERVER}/student`); 
// ^ Make an HTTP GET request to the server's /student endpoint.

// If the server didn't return 2xx, throw an error with status + body text.
if (!sResp.ok) throw new Error(`server error: ${sResp.status} ${await sResp.text()}`);

// Parse the HTTP response body as JSON into a plain JS object.
// THIS LINE turns the raw response into a regular JavaScript object (not a class).
const sJson = await sResp.json(); 

// Construct a Student CLASS INSTANCE using fields from the parsed JSON.
// THIS LINE is where we "call Student" (the constructor) and convert JSON -> Student object.
const stu   = new Student(sJson.id, sJson.name, sJson.gpa);

// Log the Student instance so we can verify it looks right.
console.log("[client] Step 1 — deserialized Student from /student:", stu);

// Also show the request ID for tracing. Some servers send it in the header,
// and we also fall back to JSON body if the server puts requestId there.
console.log("[client]       requestId from server:", 
            sResp.headers.get("X-Request-ID") || sJson.requestId);

/* ----------------------------------------------------------------
                      Step 4 — Get RSA public key (DER Base64) 
---------------------------------------------------------------------*/
  // Request the server's RSA public key (as Base64-encoded DER bytes).
const pkResp = await fetch(`${SERVER}/publicKey`);

// If the server didn't return a 200 status, throw with details (status + body text).
if (!pkResp.ok) throw new Error(`server error: ${pkResp.status} ${await pkResp.text()}`);

// Parse the JSON body into a plain JS object (e.g., { publicKey: "...", fingerprint: "..." }).
const pkJson = await pkResp.json();

// Decode the Base64-encoded DER public key string into raw bytes (Node Buffer).
const der = Buffer.from(pkJson.publicKey, "base64");

// Turn the DER bytes into a real Node.js KeyObject we can use for RSA operations.
// - format: "der" says the input is DER-encoded
// - type: "spki" says it's a SubjectPublicKeyInfo public key
const serverPubKey = crypto.createPublicKey({ key: der, format: "der", type: "spki" });

// Log a fingerprint so we can visually verify the key we received.
// Prefer the server-supplied fingerprint if present; otherwise compute SHA256 over DER locally.
console.log("[client] Step 4 — pubkey fingerprint (SHA256 b64):", pkJson.fingerprint || sha256Base64(der));

// Also log the request ID for traceability (from response header or JSON body fallback).
console.log(
  "[client]       requestId from server:",
  pkResp.headers.get("X-Request-ID") || pkJson.requestId
);

/* --------------------------------------------------------------
   Step 3 — Generate AES-256 session key 
   -------------------------------------------------------------- */

// Generate a cryptographically secure random 32-byte key.
// 32 bytes = 256 bits → required length for AES-256.
const symmKey = crypto.randomBytes(32); // Buffer(32)

// Log the number of bytes to confirm we really produced a 32-byte key.
console.log("[client] Step 3 — generated symmetric key (len bytes):", symmKey.length);


/* --------------------------------------------------------------
   Step 5 — RSA-OAEP(sha256) encrypt the AES key and create a session
   -------------------------------------------------------------- */

// Encrypt the *symmetric* key using the server’s RSA *public* key.
// - OAEP with SHA-256 is used for padding/hash (modern, secure choice).
// - Result is an RSA ciphertext Buffer that only the server can decrypt
//   (because only the server holds the matching *private* key).
const encKey = crypto.publicEncrypt(
  { key: serverPubKey, oaepHash: "sha256" }, // RSA-OAEP(SHA-256) params
  symmKey                                     // plaintext = our AES key
);

// Make a POST request to the server’s /session endpoint.
// We send JSON containing the encrypted key as Base64 text.
// The server will:
//   1) RSA-decrypt it with its private key,
//   2) validate it’s exactly 32 bytes,
//   3) stash it in a session store, and
//   4) reply with a sessionID we’ll use for later messages.
const sessRes = await fetch(`${SERVER}/session`, {
  method:  "POST",                              // HTTP verb
  headers: { "Content-Type": "application/json" }, // JSON body
  body:    JSON.stringify({
    // Send RSA ciphertext as Base64 so it’s safe for JSON transport.
    encryptedKey: encKey.toString("base64"),
  }),
});

// If the server did not return a 2xx status, throw with details.
if (!sessRes.ok) throw new Error(`session error: ${sessRes.status} ${await sessRes.text()}`);

// Parse the server’s JSON response into a plain object.
const sessJson = await sessRes.json();

// Log the sessionID granted by the server; this ties your future
// encrypted/HMAC’d messages to the specific AES key stored server-side.
console.log("[client] Step 5 — sessionID:", sessJson.sessionID);

// Also log the request ID (from header or body) for end-to-end traceability.
console.log(
  "[client]       requestId from server:",
  sessRes.headers.get("X-Request-ID") || sessJson.requestId
);

/* ---------------------- Step 6 — AES-GCM encrypt JSON ----------------------- */
// We take the Student instance `stu`, serialize it to JSON bytes,
// then encrypt those bytes with AES-256-GCM using the session key `symmKey`.

// Turn the Student instance into a UTF-8 JSON byte buffer.
// 1) JSON.stringify(stu) -> JSON string like {"id":1,"name":"...","gpa":3.9}
// 2) Buffer.from(... )   -> raw bytes (UTF-8) ready for crypto APIs.
const studentJSON = Buffer.from(JSON.stringify(stu));  // UTF-8 JSON

// Call our helper to perform AES-256-GCM encryption.
// Inputs : symmKey (32-byte AES key), studentJSON (plaintext bytes)
// Outputs: 
//    nonce      -> 12-byte random IV required by GCM
//    ciphertext -> encrypted bytes followed by a 16-byte auth tag (data||tag)
const { nonce, ciphertext } = encryptAESGCM(symmKey, studentJSON);

// Log that encryption succeeded (useful when demoing flow).
console.log("[client] Step 6 — AES-GCM encrypted student JSON");

// Show the nonce in Base64 so it’s easy to transmit/inspect.
// The server will need the same nonce to decrypt.
console.log("          nonce (b64):",      nonce.toString("base64"));

// Show the ciphertext length in bytes (includes the 16-byte GCM tag at the end).
console.log("     ciphertext length:",     ciphertext.length);


/* ------------------- Step 7 — HMAC-SHA256 over ciphertext ------------------ */
// Integrity protection is computed over the *ciphertext* bytes (not plaintext).
// We use the shared symmetric key (symmKey) as the HMAC secret.
const mac = computeHMACSHA256(symmKey, ciphertext);   // => Buffer(32) HMAC tag

// Log that we produced an HMAC and show it in Base64 (safe for printing/transmission).
console.log("[client] Step 7 — HMAC computed");
console.log("          hmac (b64):", mac.toString("base64"));

/* ---------------- Steps 8–10 — Send, verify, decrypt, deserialize ---------- */
// We POST JSON to the server's /message endpoint containing:
//   - sessionID:   which tells the server which symmetric key to use
//   - nonce:       AES-GCM nonce (Base64)
//   - ciphertext:  AES-GCM output (data||tag) in Base64
//   - hmac:        HMAC-SHA256 over ciphertext in Base64
// Server does:
//   Step 8: Recompute HMAC and compare (integrity check).
//   Step 9: Decrypt AES-GCM using the stored session key + nonce.
//   Step 10: (In our design) it returns plaintext as Base64 so the *client*
//            can deserialize to a Student object.
const msgRes = await fetch(`${SERVER}/message`, {
  method:  "POST",                                   // HTTP verb
  headers: { "Content-Type": "application/json" },   // tell server we’re sending JSON
  body: JSON.stringify({                             // serialize our request body
    sessionID:  sessJson.sessionID,                  // session handle from /session
    nonce:      nonce.toString("base64"),            // send nonce as Base64 text
    ciphertext: ciphertext.toString("base64"),       // send ciphertext+tag as Base64
    hmac:       mac.toString("base64"),              // send HMAC as Base64
  }),
});

// If server didn’t return 2xx, throw an error with status + body text (good debuggability).
if (!msgRes.ok) throw new Error(`message error: ${msgRes.status} ${await msgRes.text()}`);

// Parse the JSON reply. Expected fields include:
//   - requestId   (for traceability)
//   - validHMAC   (boolean integrity result)
//   - message     (human-readable status)
//   - plaintextB64 (optional; when validHMAC=true and decrypt OK)
const msgJson = await msgRes.json();

// Show the server’s request ID (prefer header; fall back to JSON field if present).
console.log("[client] Server response requestId:", msgRes.headers.get("X-Request-ID") || msgJson.requestId);

// Log integrity result and server’s message so we can narrate the outcome.
console.log("[client] validHMAC:", msgJson.validHMAC);
console.log("[client] message  :", msgJson.message);


  // Step 10 — Client deserializes plaintext JSON into a Student object.
if (msgJson.validHMAC && msgJson.plaintextB64) {
  // Convert the Base64 string returned by the server into raw bytes (Buffer).
  const plaintext = Buffer.from(msgJson.plaintextB64, "base64");

  // Interpret those bytes as a UTF-8 string, then parse JSON
  // → this turns the plaintext JSON text into a plain JavaScript object.
  const obj2 = JSON.parse(plaintext.toString("utf8"));

  // Create a real Student class instance from the plain object’s fields.
  // THIS LINE calls the Student constructor and performs the JSON → Student conversion.
  const stu2 = new Student(obj2.id, obj2.name, obj2.gpa);

  // Show the reconstructed Student so we can confirm the data looks correct.
  console.log("[client] Step 10 — deserialized plaintext -> Student:", stu2);
} else {
  // If HMAC failed or decryption failed, the server won’t return plaintext.
  console.log("[client] No plaintext returned (HMAC failed or decryption error).");
}
}
// Top-level error handler for the main() promise.
// If anything throws inside main(), we log and exit with a non-zero status.
main().catch(err => {
  console.error(err);
  process.exit(1);
});

