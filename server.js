/**  server.js
 * ----------
 * Role: Secure REST server for the full-stack messaging project.
 *
 * What this server does (Steps 1 -10):
 *   Step 1  (demo only): Provide a serialized Student JSON at GET /student
 *   Step 2  (connectivity): Serve HTTP endpoints (REST)
 *   Step 3  (keygen): Generate an RSA keypair at startup
 *   Step 4  (key exchange): Expose the RSA public key at GET /publicKey
 *   Step 5  (key exchange): Receive client’s RSA-encrypted AES session key at POST /session
 *   Step 8  (integrity):   Verify HMAC over ciphertext at POST /message
 *   Step 9  (decryption):  Decrypt AES-GCM to recover plaintext JSON at POST /message
 *   Step 10 (deser):       Return plaintext (base64) so the client deserializes to Student
 *
 * Security hygiene included:
 *   • Request IDs for audit & traceability (header + JSON body)
 *   • Body size limit, Base64 length caps
 *   • Constant-time HMAC compare (timingSafeEqual)
 *   • AES-256-GCM with 12-byte nonce and 16-byte tag (ciphertext||tag format)
 * Run:
 *   node server.js
 */

const express = require("express");
const crypto  = require("crypto");
const Student = require("./student"); // tiny class with { id, name, gpa }

const app = express();

/* -------------------------------------------------------------------------- */
/*                            GLOBAL SAFETY CONTROLS                           */
/* -------------------------------------------------------------------------- */
/**
 * Parse JSON bodies with a conservative size cap.
 * - Protects against accidental huge posts.
 * - 8 KB is way more than we need for this lab.
 */
app.use(express.json({ limit: "8kb" }));

/** add a middleware
 * Attach a unique request ID to every request for logging and tracing.
 * - We also mirror the ID back via 'X-Request-ID' response header
 *   and include it in the JSON response body for the client to log.
 */
app.use((req, res, next) => {
  const reqId = crypto.randomBytes(8).toString("hex"); // 16 hex chars
  req.reqId = reqId;
  res.setHeader("X-Request-ID", reqId);
  console.log(`[req ${reqId}] ${req.method} ${req.originalUrl}`);
  next();
});

/**
 * Helper to send a consistent JSON response that always includes requestId.
 * @param {express.Response} res
 * @param {number} status - HTTP status code
 * @param {object} body   - JSON payload (we’ll add requestId)
 */
function reply(res, status, body) { // The reply() helper centralizes that behavior
  res.status(status).json({ requestId: res.getHeader("X-Request-ID"), ...body });
}

/* -------------------------------------------------------------------------- */
/*                         STEP 3 — RSA KEYPAIR (SERVER)                      */
/* -------------------------------------------------------------------------- */

/**
 * Generate a 2048-bit RSA keypair.
 * - publicKey: DER (binary, ASN.1 SubjectPublicKeyInfo)
 * - privateKey: PEM (PKCS#8)
 * Note: keep the private key only on the server.
 */
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "der" },   // DER (Buffer)
  privateKeyEncoding: { type: "pkcs8", format: "pem" }, // PEM (string)
});

/** Fingerprint for debugging/demos (SHA256 over DER public key). */
const sha256Base64 = (buf) => crypto.createHash("sha256").update(buf).digest("base64");
const pubKeyDER = Buffer.from(publicKey);
const pubKeyB64 = pubKeyDER.toString("base64");
const pubKeyFP  = sha256Base64(pubKeyDER);

/** In-memory map of active sessions → AES keys (Buffer). */
const sessions = new Map();

/* -------------------------------------------------------------------------- */
/*                       BASE64 INPUT CAPS (DEFENSE-IN-DEPTH)                 */
/* -------------------------------------------------------------------------- */

// Rough upper bounds for Base64 inputs (defense-in-depth):

const CAPS = {
  encryptedKeyB64Max: 600, //- RSA-2048 ciphertext: 256 bytes → ~344 Base64 chars (we cap at 600)
  nonceB64Max:        64,  // - AES-GCM nonce:        12 bytes → 16 Base64 chars (cap 64)
  hmacB64Max:        128,  // - HMAC-SHA256:          32 bytes → 44 Base64 chars (cap 128)
  ciphertextB64Max: 8192,  //  - Ciphertext (data||tag): small for our demo → cap 8192 chars
 
};

/**
 * Validates and decodes a Base64 field.
 * @returns {Buffer|null} decoded Buffer or null if invalid (and responds 4xx).
 */
function requireB64(name, value, maxLen, res) {
  if (typeof value !== "string" || value.length === 0) {
    reply(res, 400, { error: `missing ${name}` });
    return null;
  }
  if (value.length > maxLen) {
    reply(res, 413, { error: `${name} too large` }); // 413: Payload Too Large
    return null;
  }
  try {
    return Buffer.from(value, "base64");
  } catch {
    reply(res, 400, { error: `${name} is not valid Base64` });
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/*                    STEP 1 — SERVER-SIDE SERIALIZATION (DEMO)               */
/* -------------------------------------------------------------------------- */

/**
 * We expose a serialized Student object for the client to fetch.
 * In the full flow, the client later sends an encrypted version and
 * deserializes the plaintext returned by the server.
 */
const student = new Student(1, "Alice Quantum", 3.9);

app.get("/student", (req, res) => {
  reply(res, 200, student);
});

/* -------------------------------------------------------------------------- */
/*                   STEP 4 — SHARE PUBLIC KEY (DER BASE64)                   */
/* -------------------------------------------------------------------------- */

app.get("/publicKey", (req, res) => {
  reply(res, 200, { publicKey: pubKeyB64, fingerprint: pubKeyFP });
});

/* -------------------------------------------------------------------------- */
/*        STEP 5 — RECEIVE RSA-ENCRYPTED AES KEY & CREATE SESSION             */
/* -------------------------------------------------------------------------- */
/**
 * Body: { encryptedKey: "<base64 RSA-OAEP(sha256) ciphertext>" }
 * Returns: { sessionID: "<hex>" }
 */
app.post("/session", (req, res) => {
  try {
    const encryptedKey = req.body?.encryptedKey;
    const ciphertext   = requireB64("encryptedKey", encryptedKey, CAPS.encryptedKeyB64Max, res);
    if (!ciphertext) return; // response already sent

    // Decrypt session key with server's private RSA key (OAEP-SHA256).
    const symmKey = crypto.privateDecrypt(
      { key: privateKey, oaepHash: "sha256" }, //  Decrypt with the private key → only the server can unwrap the symmetric key.
      ciphertext
    ); //Uses RSA-OAEP with SHA-256 (secure padding & hash). Because this is private key decryption,
    //  only the server can recover the inner plaintext (which should be the client’s symmetric AES key).

    // Expect that the recovered key is exactly 32 bytes (AES-256).
    if (symmKey.length !== 32) {
      return reply(res, 400, { error: "invalid symmetric key length (need 32 bytes for AES-256)" });
    }

    // Generates a random session ID and maps it to the validated 32-byte AES key.
    const sessionID = crypto.randomBytes(16).toString("hex"); // map it to 32 bytes AES key, 32 hex chars
    sessions.set(sessionID, symmKey);

    console.log(`[req ${req.reqId}] new session ${sessionID} (keyLen=${symmKey.length})`);
    reply(res, 200, { sessionID }); // reply() helper also includes the requestId header in the JSON for traceability.
  } catch (err) {
    console.error(`[req ${req.reqId}] /session error:`, err.message);
    reply(res, 400, { error: "failed to decrypt/store session key" });
  }
});

/* -------------------------------------------------------------------------- */
/*                     HELPERS — HMAC + AES-GCM DECRYPTION                    */
/* -------------------------------------------------------------------------- */
/** HMAC-SHA256(key, data) → Buffer(32) */
const computeHMACSHA256 = (key, data) =>
  crypto.createHmac("sha256", key      //  create an HMAC object that will use SHA-256 secret key (the shared AES session key)
    //  .update(data): feed the exact bytes we want to protect (ciphertext).
                   ).update(data).digest();  // .digest(): finish and return the 32-byte HMAC value (Buffer length 32).
/**
 * AES-256-GCM decryption where ciphertext is (data || 16-byte tag).
 * @param {Buffer} key   32-byte AES key
 * @param {Buffer} nonce 12-byte GCM nonce (IV)
 * @param {Buffer} cipherAndTag concatenated data + tag
 * @returns {Buffer} plaintext
 */
function decryptAESGCM(key, nonce, cipherAndTag) {
  if (cipherAndTag.length < 16) throw new Error("ciphertext too short");  // there must be at least room for the tag
  const tag  = cipherAndTag.slice(-16);      // extract the last 16 bytes as the GCM tag.
  const data = cipherAndTag.slice(0, -16);   // everything before the tag is the ciphertext bytes.
  // set up a GCM decryptor with key and nonce.
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);  // give it the tag so GCM can verify integrity during decrypt.
  const p1 = decipher.update(data); // decrypt. If the tag is wrong (message/nonce/key corrupted), .final() throws.
  const p2 = decipher.final();
  return Buffer.concat([p1, p2]); //  combine the partial/plaintext chunks into the final plaintext.
}
/* -------------------------------------------------------------------------- */
/*            STEPS 8 & 9 — VERIFY HMAC, THEN DECRYPT AES-GCM                 */
/* -------------------------------------------------------------------------- */
/**
 * Body:
 *   {
 *     "sessionID":  "<hex>",
 *     "ciphertext": "<base64 (data||tag)>",
 *     "nonce":      "<base64>",
 *     "hmac":       "<base64>"
 *   }
 *
 * On success:
 *   {
 *     requestId:   "...",
 *     validHMAC:   true,
 *     message:     "HMAC verified; decryption successful",
 *     plaintextB64:"<base64 of JSON>"
 *   }*/
app.post("/message", (req, res) => {                 // Define POST /message endpoint to receive encrypted payloads
  try {                                              // Start try/catch so any runtime error returns a clean JSON error
    const { sessionID, ciphertext, nonce, hmac } =   // Destructure expected fields from the JSON body (or {} if body missing)
      req.body || {};

    // Quick sanity check for session ID (32 hex chars).
    if (typeof sessionID !== "string" ||             // Validate sessionID is a string
        !/^[a-f0-9]{32}$/i.test(sessionID)) {        // Ensure it matches exactly 32 hex characters
      return reply(res, 400, { error: "invalid sessionID" }); // Early exit if invalid
    }

    // Load session key
    const key = sessions.get(sessionID);             // Look up the symmetric AES key for this sessionID
    if (!key) return reply(res, 400, {               // If not found, the client used an unknown or expired session
      error: "unknown session ID"
    });

    // Decode + cap Base64 inputs
    const ctBuf = requireB64(                        // Decode Base64 ciphertext (cipherData||tag) with size cap
      "ciphertext", ciphertext, CAPS.ciphertextB64Max, res
    );
    if (!ctBuf) return;                              // requireB64 already sent an error response if null

    const ivBuf = requireB64(                        // Decode Base64 nonce (IV) with size cap
      "nonce", nonce, CAPS.nonceB64Max, res
    );
    if (!ivBuf) return;                              // Stop if invalid or too large

    const macR = requireB64(                         // Decode Base64 HMAC with size cap
      "hmac", hmac, CAPS.hmacB64Max, res
    );
    if (!macR) return;                               // Stop if invalid or too large

    // Step 8 — recompute HMAC and compare in constant time.
    const macE = computeHMACSHA256(key, ctBuf);      // Recompute HMAC-SHA256 over the ciphertext using the session key
    if (macE.length !== macR.length ||               // If lengths differ, fail fast (prevents timing issues)
        !crypto.timingSafeEqual(macE, macR)) {       // Constant-time compare to avoid timing attacks
      return reply(res, 200, {                       // Return success HTTP (200) but mark integrity failure in JSON
        validHMAC: false,
        message: "HMAC verification failed (tampered?)"
      });
    }
    // Step 9 — decrypt AES-GCM
    const plaintext = decryptAESGCM(                 // Decrypt with AES-256-GCM using key + nonce; verifies GCM tag
      key, ivBuf, ctBuf
    );

    // Return plaintext back to client (base64) so client does Step 10 (deserialize).
    reply(res, 200, {                                // Send JSON with requestId (via reply helper) and success fields
      validHMAC: true,                               // HMAC check passed
      message: "HMAC verified; decryption successful", // Friendly status
      plaintextB64: plaintext.toString("base64"),    // Base64-encode plaintext so client can decode + JSON.parse
    });
  } catch (err) {                                    // Any thrown error (e.g., bad GCM tag) is handled here
    console.error(`[req ${req.reqId}] /message error:`, err.message); // Log with requestId for traceability
    reply(res, 400, {                                // Return a structured JSON error
      validHMAC: true,                               // We got past HMAC step if we’re here (usually), but decryption failed
      message: `decryption failed: ${err.message}`,  // Include error message for debugging the demo
    });
  }
});
/* -------------------------------------------------------------------------- */
/*                                  BOOT                                      */
/* -------------------------------------------------------------------------- */

const PORT = 8080;                                   // Port number this server will listen on
app.listen(PORT, () => {                             // Start the HTTP server
  console.log(`[server] listening on http://localhost:${PORT}`); // Log where to reach the server
  console.log(`[server] RSA pubkey fingerprint (SHA256 b64): ${pubKeyFP}`); // Show public key fingerprint for audit
  console.log(`[server] try: curl http://localhost:${PORT}/publicKey`);     // Quick test hint for the demo
});
module.exports = { sessions };
