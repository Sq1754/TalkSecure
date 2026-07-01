/**
 * Talk-Secure — TLS Certificate Generator
 * Generates self-signed RSA-2048 certificate for HTTPS/WSS
 * No third-party CA involved
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function generateSelfSignedCert(certsDir) {
    // Generate RSA 2048-bit key pair
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // Create self-signed certificate using Node.js crypto
    // We'll build a minimal X.509 v3 certificate manually
    const certInfo = {
        subject: '/CN=Talk-Secure/O=Personal/C=IN',
        validDays: 365
    };

    // Use openssl-like approach with Node.js built-in X509Certificate (Node 15+)
    // For broader compatibility, we'll use the forge-free approach with child_process
    // Actually, let's use Node's native crypto to create a proper self-signed cert

    const now = new Date();
    const notAfter = new Date(now.getTime() + certInfo.validDays * 24 * 60 * 60 * 1000);

    // Node.js 19+ has crypto.X509Certificate, but for signing we need createSign
    // The cleanest no-dependency approach: use createCertificate with DER encoding
    
    // Build the TBS (To Be Signed) certificate structure in ASN.1 DER
    const cert = buildSelfSignedCert(privateKey, publicKey, now, notAfter);

    if (!fs.existsSync(certsDir)) {
        fs.mkdirSync(certsDir, { recursive: true });
    }

    fs.writeFileSync(path.join(certsDir, 'server.key'), privateKey);
    fs.writeFileSync(path.join(certsDir, 'server.cert'), cert);

    console.log('   ✓ TLS certificate generated (RSA-2048, valid 365 days)');
    return { key: privateKey, cert };
}

function buildSelfSignedCert(privateKeyPem, publicKeyPem, notBefore, notAfter) {
    // ASN.1 DER encoding helpers
    function encodeLength(len) {
        if (len < 0x80) return Buffer.from([len]);
        if (len < 0x100) return Buffer.from([0x81, len]);
        return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
    }

    function encodeTLV(tag, value) {
        const len = encodeLength(value.length);
        return Buffer.concat([Buffer.from([tag]), len, value]);
    }

    function encodeSequence(...items) {
        const content = Buffer.concat(items);
        return encodeTLV(0x30, content);
    }

    function encodeSet(...items) {
        const content = Buffer.concat(items);
        return encodeTLV(0x31, content);
    }

    function encodeOID(oid) {
        const parts = oid.split('.').map(Number);
        const bytes = [40 * parts[0] + parts[1]];
        for (let i = 2; i < parts.length; i++) {
            let val = parts[i];
            if (val < 128) {
                bytes.push(val);
            } else {
                const encoded = [];
                encoded.push(val & 0x7f);
                val >>= 7;
                while (val > 0) {
                    encoded.push((val & 0x7f) | 0x80);
                    val >>= 7;
                }
                bytes.push(...encoded.reverse());
            }
        }
        return encodeTLV(0x06, Buffer.from(bytes));
    }

    function encodeUTF8String(str) {
        return encodeTLV(0x0c, Buffer.from(str, 'utf8'));
    }

    function encodePrintableString(str) {
        return encodeTLV(0x13, Buffer.from(str, 'ascii'));
    }

    function encodeInteger(buf) {
        // Ensure positive by prepending 0x00 if high bit set
        if (buf[0] & 0x80) {
            buf = Buffer.concat([Buffer.from([0x00]), buf]);
        }
        return encodeTLV(0x02, buf);
    }

    function encodeUTCTime(date) {
        const str = date.toISOString().replace(/[-:T]/g, '').substring(2, 14) + 'Z';
        return encodeTLV(0x17, Buffer.from(str, 'ascii'));
    }

    function encodeBitString(buf) {
        return encodeTLV(0x03, Buffer.concat([Buffer.from([0x00]), buf]));
    }

    // Parse the public key from PEM
    const pubKeyDer = Buffer.from(
        publicKeyPem
            .replace(/-----BEGIN PUBLIC KEY-----/, '')
            .replace(/-----END PUBLIC KEY-----/, '')
            .replace(/\s/g, ''),
        'base64'
    );

    // Serial number (random 16 bytes)
    const serial = crypto.randomBytes(16);
    serial[0] &= 0x7f; // Ensure positive

    // SHA256 with RSA OID
    const sha256WithRSA = encodeSequence(
        encodeOID('1.2.840.113549.1.1.11'), // sha256WithRSAEncryption
        encodeTLV(0x05, Buffer.alloc(0)) // NULL
    );

    // Subject/Issuer DN
    const cn = encodeSet(encodeSequence(encodeOID('2.5.4.3'), encodeUTF8String('Talk-Secure')));
    const org = encodeSet(encodeSequence(encodeOID('2.5.4.10'), encodeUTF8String('Personal')));
    const country = encodeSet(encodeSequence(encodeOID('2.5.4.6'), encodePrintableString('IN')));
    const issuerSubject = encodeSequence(country, org, cn);

    // Validity
    const validity = encodeSequence(
        encodeUTCTime(notBefore),
        encodeUTCTime(notAfter)
    );

    // Version (v3 = 2)
    const version = encodeTLV(0xa0, encodeInteger(Buffer.from([0x02])));

    // TBS Certificate
    const tbsCertificate = encodeSequence(
        version,
        encodeInteger(serial),
        sha256WithRSA,
        issuerSubject,
        validity,
        issuerSubject, // self-signed, so issuer = subject
        pubKeyDer // SubjectPublicKeyInfo (already DER encoded from PEM)
    );

    // Sign the TBS
    const signer = crypto.createSign('SHA256');
    signer.update(tbsCertificate);
    const signature = signer.sign(privateKeyPem);

    // Full certificate
    const certificate = encodeSequence(
        tbsCertificate,
        sha256WithRSA,
        encodeBitString(signature)
    );

    // Encode as PEM
    const certBase64 = certificate.toString('base64');
    const lines = certBase64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

module.exports = { generateSelfSignedCert };
