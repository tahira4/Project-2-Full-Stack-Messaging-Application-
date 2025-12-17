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
// If you are on Node < 18, install node-fetch@2 and uncomment the next line:
// const fetch = require("node-fetch");

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
  const nonce  = crypto.randomBytes(12);               // Step 6: unique per message
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  const enc1   = cipher.update(plaintextBuf);
  const enc2   = cipher.final();
  const tag    = cipher.getAuthTag();                  // 16 bytes
  const ciphertext = Buffer.concat([enc1, enc2, tag]); // store as data||tag
  return { nonce, ciphertext };
}

async function main() {
  /* ------------------------- Step 1 — Deserialize JSON ------------------------ */
  // The server serializes a Student (Step 1 demo). We fetch it and create a
  // Student object on the client side (this also proves connectivity).
  const sResp = await fetch(`${SERVER}/student`);
  if (!sResp.ok) throw new Error(`server error: ${sResp.status} ${await sResp.text()}`);
  const sJson = await sResp.json();
  const stu   = new Student(sJson.id, sJson.name, sJson.gpa);
  console.log("[client] Step 1 — deserialized Student from /student:", stu);
  console.log("[client]       requestId from server:", sResp.headers.get("X-Request-ID") || sJson.requestId);

  /* ----------------- Step 4 — Get RSA public key (DER Base64) ---------------- */
  const pkResp = await fetch(`${SERVER}/publicKey`);
  if (!pkResp.ok) throw new Error(`server error: ${pkResp.status} ${await pkResp.text()}`);
  const pkJson = await pkResp.json();
  const der    = Buffer.from(pkJson.publicKey, "base64");
  const serverPubKey = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
  console.log("[client] Step 4 — pubkey fingerprint (SHA256 b64):", pkJson.fingerprint || sha256Base64(der));
  console.log("[client]       requestId from server:", pkResp.headers.get("X-Request-ID") || pkJson.requestId);

  /* ------------------ Step 3 — Generate AES-256 session key ------------------- */
  const symmKey = crypto.randomBytes(32); // 32 bytes = AES-256
  console.log("[client] Step 3 — generated symmetric key (len bytes):", symmKey.length);

  /* ------- Step 5 — RSA-OAEP(sha256) encrypt key and create a session -------- */
  // We encrypt the AES session key with the server's public RSA key and send it.
  const encKey = crypto.publicEncrypt({ key: serverPubKey, oaepHash: "sha256" }, symmKey);

  const sessRes = await fetch(`${SERVER}/session`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ encryptedKey: encKey.toString("base64") }),
  });
  if (!sessRes.ok) throw new Error(`session error: ${sessRes.status} ${await sessRes.text()}`);
  const sessJson = await sessRes.json();
  console.log("[client] Step 5 — sessionID:", sessJson.sessionID);
  console.log("[client]       requestId from server:", sessRes.headers.get("X-Request-ID") || sessJson.requestId);

  /* ---------------------- Step 6 — AES-GCM encrypt JSON ----------------------- */
  // Serialize the Student instance to JSON, then encrypt it.
  const studentJSON = Buffer.from(JSON.stringify(stu));  // UTF-8 JSON
  const { nonce, ciphertext } = encryptAESGCM(symmKey, studentJSON);
  console.log("[client] Step 6 — AES-GCM encrypted student JSON");
  console.log("          nonce (b64):",      nonce.toString("base64"));
  console.log("     ciphertext length:",     ciphertext.length);

  /* ------------------- Step 7 — HMAC-SHA256 over ciphertext ------------------ */
  // Integrity protection is over the ciphertext bytes (not plaintext).
  const mac = computeHMACSHA256(symmKey, ciphertext);
  console.log("[client] Step 7 — HMAC computed");
  console.log("          hmac (b64):", mac.toString("base64"));

  /* ---------------- Steps 8–10 — Send, verify, decrypt, deserialize ---------- */
  // We POST the (sessionID, nonce, ciphertext, hmac). Server verifies HMAC
  // (Step 8), decrypts AES-GCM (Step 9), and returns plaintext as Base64.
  const msgRes = await fetch(`${SERVER}/message`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      sessionID:  sessJson.sessionID,
      nonce:      nonce.toString("base64"),
      ciphertext: ciphertext.toString("base64"),
      hmac:       mac.toString("base64"),
    }),
  });
  if (!msgRes.ok) throw new Error(`message error: ${msgRes.status} ${await msgRes.text()}`);
  const msgJson = await msgRes.json();

  console.log("[client] Server response requestId:", msgRes.headers.get("X-Request-ID") || msgJson.requestId);
  console.log("[client] validHMAC:", msgJson.validHMAC);
  console.log("[client] message  :", msgJson.message);

  // Step 10 — Client deserializes plaintext JSON into a Student object.
  if (msgJson.validHMAC && msgJson.plaintextB64) {
    const plaintext = Buffer.from(msgJson.plaintextB64, "base64");
    const obj2 = JSON.parse(plaintext.toString("utf8"));
    const stu2 = new Student(obj2.id, obj2.name, obj2.gpa);
    console.log("[client] Step 10 — deserialized plaintext -> Student:", stu2);
  } else {
    console.log("[client] No plaintext returned (HMAC failed or decryption error).");
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
