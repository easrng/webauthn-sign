/* global CBOR base64js identicon */
(() => {
  // CONSTANTS
  const flag_AT = 0x40;
  const flag_ED = 0x80;
  const cose_kty = 1;
  const cose_kty_ec2 = 2;
  const cose_alg = 3;
  const cose_alg_ECDSA_w_SHA256 = -7;
  const cose_crv = -1;
  const cose_crv_P256 = 1;
  const cose_crv_x = -2;
  const cose_crv_y = -3;

  // UTILS
  class UserFacingError extends Error {}
  function b64enc(buf) {
    if (!(buf instanceof Uint8Array)) {
      buf = new Uint8Array(buf);
    }
    return base64js
      .fromByteArray(buf)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }
  function b64dec(s) {
    s = s + "=".repeat(Math.ceil(s.length / 4) * 4 - s.length);
    return base64js.toByteArray(s);
  }
  function sum(array) {
    return array.reduce((a, b) => a + b, 0);
  }
  function sliceWithLengthChecks(data, segements, allowExtra) {
    let ret = [];
    if (!(data instanceof Uint8Array)) {
      data = new Uint8Array(data);
    }
    const totalSlicedLength = sum(segements);
    if (
      allowExtra
        ? totalSlicedLength > data.length
        : totalSlicedLength !== data.length
    ) {
      throw new Error("mismatched lengths");
    }
    let offset = 0;
    for (let segement of segements) {
      ret.push(data.slice(offset, offset + segement));
      offset += segement;
    }
    if (allowExtra) ret.push(data.slice(offset));
    return ret;
  }
  function concatWithLengthChecks(pairs) {
    const size = sum(pairs.map((e) => e.length));
    const data = new Uint8Array(size);
    let offset = 0;
    for (let pair of pairs) {
      let pairData = pair.data;
      if (!(pairData instanceof Uint8Array)) {
        pairData = new Uint8Array(pairData);
      }
      if (pairData.length !== pair.length)
        throw new Error("mismatched lengths");
      for (let i = 0; i < pair.length; i++) {
        data[offset + i] = pairData[i];
      }
      offset += pair.length;
    }
    return data;
  }

  // THE ACTUAL CODE
  function importPublicKey(keyBytes) {
    const [version, x, y] = sliceWithLengthChecks(keyBytes, [1, 32, 32]);
    if (version[0] != 0x04) {
      throw "bad public key";
    }
    let jwk = {
      kty: "EC",
      crv: "P-256",
      x: b64enc(x),
      y: b64enc(y),
    };
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"]
    );
  }
  async function webAuthnDecodeAuthDataArray(aAuthData) {
    const [rpIdHash, flags, counter, rest] = sliceWithLengthChecks(
      aAuthData,
      [32, 1, 4],
      true
    );
    const hasAttest = (flags[0] & flag_AT) !== 0;
    const hasExtensions = (flags[0] & flag_ED) !== 0;
    if (!hasAttest) {
      if (!hasExtensions && rest.length !== 0)
        throw new Error("there shouldn't be any extra data");
      return {
        rpIdHash: rpIdHash,
        flags: flags,
        counter: counter,
      };
    }

    const [aaguid, credIdLen, rest2] = sliceWithLengthChecks(
      rest,
      [16, 2],
      true
    );
    let attData = {};
    attData.aaguid = aaguid;
    attData.credIdLen = new DataView(credIdLen.buffer).getUint16(0, false);

    const [credId, rest3] = sliceWithLengthChecks(
      rest2,
      [attData.credIdLen],
      true
    );
    attData.credId = credId;
    let i = 0,
      pubkeyObj,
      extensions;
    if (hasExtensions) {
      // you have to do it this way if there are extensions
      // what the fuck were they thinking
      // see https://stackoverflow.com/a/54058421/11831068
      let lastError;
      for (; i < rest.length; i++) {
        try {
          pubkeyObj = CBOR.decode(rest3.slice(0, i).buffer);
          break;
        } catch (e) {
          lastError = e;
        }
      }
      if (!pubkeyObj) throw lastError;
      extensions = CBOR.decode(rest3.slice(i).buffer);
    } else {
      pubkeyObj = CBOR.decode(rest3.buffer);
    }
    if (
      !(
        cose_kty in pubkeyObj &&
        cose_alg in pubkeyObj &&
        cose_crv in pubkeyObj &&
        cose_crv_x in pubkeyObj &&
        cose_crv_y in pubkeyObj
      )
    ) {
      throw "Invalid CBOR Public Key Object";
    }
    if (pubkeyObj[cose_kty] != cose_kty_ec2) {
      throw "Unexpected key type";
    }
    if (pubkeyObj[cose_alg] != cose_alg_ECDSA_w_SHA256) {
      throw "Unexpected public key algorithm";
    }
    if (pubkeyObj[cose_crv] != cose_crv_P256) {
      throw "Unexpected curve";
    }

    let pubKeyBytes = concatWithLengthChecks([
      {
        length: 1,
        data: [0x04],
      },
      {
        length: 32,
        data: pubkeyObj[cose_crv_x],
      },
      {
        length: 32,
        data: pubkeyObj[cose_crv_y],
      },
    ]);

    const aKeyHandle = await importPublicKey(pubKeyBytes);
    return {
      rpIdHash: rpIdHash,
      flags: flags,
      counter: counter,
      attestationAuthData: attData,
      publicKeyBytes: pubKeyBytes,
      publicKeyHandle: aKeyHandle,
    };
  }
  async function webAuthnDecodeCBORAttestation(aCborAttBuf) {
    let attObj = CBOR.decode(aCborAttBuf);
    if (!("authData" in attObj && "fmt" in attObj && "attStmt" in attObj)) {
      throw "Invalid CBOR Attestation Object";
    }
    if (attObj.fmt == "none") {
      const aAttestationObj = await webAuthnDecodeAuthDataArray(
        attObj.authData
      );
      aAttestationObj.attestationObject = attObj;
      return aAttestationObj;
    }
    throw new Error("Unknown attestation format: " + attObj.fmt);
  }
  function padZeros(arr, length) {
    let padded = new Uint8Array(length);
    padded.set(arr, length - arr.length);
    return padded;
  }
  function verifySignature(key, data, derSig) {
    let sig = [];
    let [header, rest] = sliceWithLengthChecks(derSig, [2], true);
    if (header[0] !== 0x30) throw new Error("not a sequence");
    if (header[1] > 127) throw new Error("invalid length");
    for (let i = 0; i < 2; i++) {
      [header, rest] = sliceWithLengthChecks(rest, [2], true);
      let length = header[1];
      if (length > 127) throw new Error("invalid length");
      let part;
      [part, rest] = sliceWithLengthChecks(rest, [length], true);
      let i = 0;
      while (part[i] === 0) i++;
      part = part.slice(i);
      part = padZeros(part, 32);
      sig.push({ length: 32, data: part });
    }
    if (rest.length !== 0) throw new Error("too many entries");
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      concatWithLengthChecks(sig),
      data
    );
  }
  async function verifyPacked(sig) {
    if (
      !(await verifySignature(
        await importPublicKey(sig.pky),
        concatWithLengthChecks([
          {
            length: 32,
            data: sig.rph,
          },
          {
            length: 1,
            data: sig.flg,
          },
          {
            length: 4,
            data: sig.ctr,
          },
          {
            length: 32,
            data: await crypto.subtle.digest("SHA-256", sig.chl),
          },
        ]),
        sig.sig
      ))
    )
      return;
    const challenge = JSON.parse(new TextDecoder().decode(sig.chl));
    if (
      b64enc(
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(new URL(challenge.origin).hostname)
        )
      ) !== b64enc(sig.rph)
    )
      return;
    if (challenge.type !== "webauthn.get") return;
    return { challenge: b64dec(challenge.challenge), origin: challenge.origin };
  }
  let identity;
  function encodingVersionSupported(obj) {
    if (typeof obj !== "object") {
      return false;
    } else if (typeof obj.ver === "number" && obj.ver === 0) {
      return true;
    } else if (typeof obj.ver === "undefined") {
      return true;
    } else {
      return false;
    }
  }
  window.webauthn = {
    async decodeIdentity(file) {
      identity = CBOR.decode(file);
      if (!encodingVersionSupported(identity))
        throw new UserFacingError(
          "That Identity file uses version " +
            identity.ver +
            ", which isn't supported yet."
        );
      if (
        !(
          identity.wsk &&
          identity.kid instanceof Uint8Array &&
          identity.pky instanceof Uint8Array
        )
      )
        throw new UserFacingError("That Identity file is invalid");
      identity.identicon = await identicon(identity.pky);
      return identity;
    },
    async sign(signedFile) {
      if (!identity)
        throw new UserFacingError("Make sure you opened a valid Identity file");
      const keyId = identity.kid;
      const publicKey = identity.pky;
      const fileHash = await crypto.subtle.digest(
        "SHA-256",
        await new Response(signedFile).arrayBuffer()
      );
      let assertion;
      try {
        assertion = await navigator.credentials.get({
          publicKey: {
            timeout: 60000,
            challenge: fileHash,
            allowCredentials: [
              {
                id: keyId,
                type: "public-key",
              },
            ],
          },
        });
      } catch (e) {
        if (e instanceof DOMException) {
          console.error(e);
          throw new UserFacingError("Cancelled");
        }
        throw e;
      }
      const attestation = await webAuthnDecodeAuthDataArray(
        assertion.response.authenticatorData
      );
      const sig = {
        wsg: " webauthn-sign signature ",
        ver: 0,
        pky: publicKey,
        rph: new Uint8Array(attestation.rpIdHash),
        flg: new Uint8Array(attestation.flags),
        ctr: new Uint8Array(attestation.counter),
        sig: new Uint8Array(assertion.response.signature),
        chl: new Uint8Array(assertion.response.clientDataJSON),
      };
      if (!(await verifyPacked(sig)))
        throw new Error("couldn't verify signature");
      return {
        sigBlob: new Blob([CBOR.encode(sig)]),
        b64Pky: b64enc(sig.pky),
        identicon: identity.identicon,
        b64FileHash: b64enc(fileHash),
      };
    },
    async verify(fileHash, signatureFile) {
      let sig;
      try {
        sig = CBOR.decode(signatureFile);
        if (!encodingVersionSupported(signatureFile))
          throw new UserFacingError(
            "That signature file uses version " +
              sig.ver +
              ", which isn't supported yet"
          );
        if (!sig.wsg) throw new Error("not a wsg file");
        for (const key of ["pky", "rph", "flg", "ctr", "sig", "chl"])
          if (!(sig[key] instanceof Uint8Array))
            throw new Error("missing key " + key);
      } catch (e) {
        if (e instanceof UserFacingError) throw e;
        console.error(e);
        throw new UserFacingError(
          "The signature file you provided was invalid"
        );
      }
      const c = await verifyPacked(sig);
      if (!c) throw new Error("couldn't verify signature");
      const { challenge, origin } = c;
      const b64FileHash = b64enc(fileHash);
      if (b64enc(challenge) !== b64FileHash)
        throw new UserFacingError("That signature is for a different file");
      return {
        identicon: await identicon(sig.pky),
        b64Pky: b64enc(sig.pky),
        origin,
        b64FileHash,
      };
    },
    async newIdentity() {
      let cred;
      try {
        cred = await navigator.credentials.create({
          publicKey: {
            authenticatorSelection: {
              residentKey: "preferred",
              requireResidentKey: false,
              userVerification: "preferred",
            },
            rp: {
              name: "webauthn-sign",
            },
            user: {
              id: new ArrayBuffer(16),
              displayName: "webauthn-sign user",
              name: "webauthn-sign user",
            },
            pubKeyCredParams: [
              {
                type: "public-key",
                alg: -7,
              },
            ],
            attestation: "none",
            challenge: new ArrayBuffer(32),
          },
        });
      } catch (e) {
        if (e instanceof DOMException) {
          console.error(e);
          throw new UserFacingError("Cancelled");
        }
        throw e;
      }
      const keydata = await webAuthnDecodeCBORAttestation(
        cred.response.attestationObject
      );
      return new Blob([
        CBOR.encode({
          wsk: " webauthn-sign identity ",
          ver: 0,
          kid: new Uint8Array(cred.rawId),
          pky: keydata.publicKeyBytes,
        }),
      ]);
    },
    UserFacingError,
  };
})();
