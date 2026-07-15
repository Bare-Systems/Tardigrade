#!/usr/bin/env node
// Reproduce project-owned TLS/QUIC vector literals used by tests/crypto_vectors.zig.
//
// Runtime used when the fixture was added:
//   node v24.1.0
//
// The script depends only on Node's built-in crypto module. It is intentionally
// not wired into CI; the checked-in Zig tests use fixed bytes, while this file
// documents exactly how the project-owned bytes were generated.

const crypto = require("crypto");

function fromHex(hex) {
  return Buffer.from(hex, "hex");
}

function toHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function hmac(hash, key, data) {
  return crypto.createHmac(hash, key).update(data).digest();
}

function hkdfExtract(hash, salt, ikm) {
  return hmac(hash, salt, ikm);
}

function hkdfExpand(hash, prk, info, len) {
  let previous = Buffer.alloc(0);
  let output = Buffer.alloc(0);
  let counter = 1;
  while (output.length < len) {
    previous = hmac(hash, prk, Buffer.concat([previous, info, Buffer.from([counter])]));
    output = Buffer.concat([output, previous]);
    counter += 1;
  }
  return output.subarray(0, len);
}

function hkdfLabel(label, context, len) {
  const fullLabel = Buffer.from(`tls13 ${label}`, "ascii");
  const info = Buffer.alloc(2 + 1 + fullLabel.length + 1 + context.length);
  info.writeUInt16BE(len, 0);
  info[2] = fullLabel.length;
  fullLabel.copy(info, 3);
  info[3 + fullLabel.length] = context.length;
  context.copy(info, 4 + fullLabel.length);
  return info;
}

function hkdfExpandLabel(hash, secret, label, context, len) {
  return hkdfExpand(hash, secret, hkdfLabel(label, context, len), len);
}

function aeadSeal(cipher, key, nonce, aad, plaintext) {
  const seal = crypto.createCipheriv(cipher, key, nonce, { authTagLength: 16 });
  seal.setAAD(aad);
  const ciphertext = Buffer.concat([seal.update(plaintext), seal.final()]);
  return { ciphertext, tag: seal.getAuthTag() };
}

function aes128HeaderProtectionMask(key, sample) {
  const block = crypto.createCipheriv("aes-128-ecb", key, null);
  block.setAutoPadding(false);
  return Buffer.concat([block.update(sample), block.final()]).subarray(0, 5);
}

function print(name, value) {
  console.log(`${name}=${toHex(value)}`);
}

function generateHkdfVectors() {
  const ikm = fromHex("0b".repeat(22));
  const salt = fromHex("000102030405060708090a0b0c");
  const context = fromHex("f0f1f2f3f4f5f6f7f8f9");
  const prk = hkdfExtract("sha256", salt, ikm);
  print("hkdf.rfc5869.sha256.prk", prk);
  print("hkdf.expand_label.sha256.derived.len42", hkdfExpandLabel("sha256", prk, "derived", context, 42));

  const secret384 = Buffer.alloc(48, 0x42);
  print("hkdf.expand_label.sha384.c_hs_traffic.len48", hkdfExpandLabel("sha384", secret384, "c hs traffic", Buffer.alloc(0), 48));
}

function generateTranscriptVectors() {
  const clientHello1 = fromHex("01000003aabbcc");
  const helloRetryRequest = fromHex("02000002cf21");
  const clientHello2 = fromHex("01000002ddee");
  const ch1Hash = crypto.createHash("sha256").update(clientHello1).digest();
  const synthetic = Buffer.concat([fromHex("fe000020"), ch1Hash]);
  print("tls.transcript.client_hello_1_hash", ch1Hash);
  print("tls.transcript.synthetic_message_hash", crypto.createHash("sha256").update(synthetic).digest());
  print("tls.transcript.after_hrr", crypto.createHash("sha256").update(Buffer.concat([synthetic, helloRetryRequest])).digest());
  print("tls.transcript.after_client_hello_2", crypto.createHash("sha256").update(Buffer.concat([synthetic, helloRetryRequest, clientHello2])).digest());
}

function generateTlsRecordVector() {
  const secret = fromHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
  const key = hkdfExpandLabel("sha256", secret, "key", Buffer.alloc(0), 16);
  const iv = hkdfExpandLabel("sha256", secret, "iv", Buffer.alloc(0), 12);
  const plaintext = Buffer.concat([Buffer.from("server finished record", "ascii"), Buffer.from([0x16]), Buffer.alloc(4)]);
  const aad = fromHex("170303002b");
  const sealed = aeadSeal("aes-128-gcm", key, iv, aad, plaintext);
  print("tls.record.aes128.key", key);
  print("tls.record.aes128.iv", iv);
  print("tls.record.aes128.ciphertext", sealed.ciphertext);
  print("tls.record.aes128.tag", sealed.tag);
  print("tls.record.aes128.record", Buffer.concat([aad, sealed.ciphertext, sealed.tag]));
}

function generateQuicSmallPacketVector() {
  const dcid = fromHex("8394c8f03e515708");
  const initialSalt = fromHex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
  const initialSecret = hkdfExtract("sha256", initialSalt, dcid);
  const clientSecret = hkdfExpandLabel("sha256", initialSecret, "client in", Buffer.alloc(0), 32);
  const key = hkdfExpandLabel("sha256", clientSecret, "quic key", Buffer.alloc(0), 16);
  const iv = hkdfExpandLabel("sha256", clientSecret, "quic iv", Buffer.alloc(0), 12);
  const hp = hkdfExpandLabel("sha256", clientSecret, "quic hp", Buffer.alloc(0), 16);

  const packetNumber = Buffer.alloc(8);
  packetNumber.writeBigUInt64BE(2n);
  const nonce = Buffer.from(iv);
  for (let i = 0; i < packetNumber.length; i += 1) {
    nonce[nonce.length - packetNumber.length + i] ^= packetNumber[i];
  }

  // QUIC long header with pn_len=4, DCID 8394c8f03e515708, zero-length SCID
  // and token, Length = packet_number_len + 32-byte plaintext + 16-byte tag.
  const header = fromHex("c300000001088394c8f03e5157080000403400000002");
  const plaintext = Buffer.alloc(32);
  const sealed = aeadSeal("aes-128-gcm", key, nonce, header, plaintext);
  const payload = Buffer.concat([sealed.ciphertext, sealed.tag]);
  const sample = payload.subarray(0, 16);
  const mask = aes128HeaderProtectionMask(hp, sample);
  const protectedHeader = Buffer.from(header);
  protectedHeader[0] ^= mask[0] & 0x0f;
  for (let i = 0; i < 4; i += 1) {
    protectedHeader[protectedHeader.length - 4 + i] ^= mask[i + 1];
  }

  print("quic.small.header", header);
  print("quic.small.nonce", nonce);
  print("quic.small.ciphertext", sealed.ciphertext);
  print("quic.small.tag", sealed.tag);
  print("quic.small.hp_sample", sample);
  print("quic.small.hp_mask", mask);
  print("quic.small.protected_header", protectedHeader);
  print("quic.small.final_packet", Buffer.concat([protectedHeader, payload]));
}

generateHkdfVectors();
generateTranscriptVectors();
generateTlsRecordVector();
generateQuicSmallPacketVector();
