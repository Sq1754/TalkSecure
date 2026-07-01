/**
 * Talk-Secure — Client-Side End-to-End Encryption
 * Uses ONLY native Web Crypto API (window.crypto.subtle)
 * Zero third-party crypto dependencies
 *
 * Flow:
 * 1. Generate ECDH key pair (P-256)
 * 2. Exchange public keys with peer
 * 3. Derive shared secret via ECDH
 * 4. Encrypt/decrypt messages with AES-256-GCM
 */

const VaultCrypto = (() => {
    const ECDH_CURVE = { name: 'ECDH', namedCurve: 'P-256' };
    const AES_ALGO = { name: 'AES-GCM', length: 256 };
    const IV_LENGTH = 12; // 96 bits for GCM

    let _keyPair = null;
    let _sharedKey = null;
    let _sessionId = null;

    /**
     * Generate or load E2E identity key pair from IndexedDB
     */
    async function generateKeyPair(force = false) {
        try {
            if (!force) {
                const savedKeys = await VaultKeyStore.get('identity_keypair');
            if (savedKeys && savedKeys.privateKeyJwk && savedKeys.publicKeyJwk) {
                const privateKey = await window.crypto.subtle.importKey(
                    'jwk',
                    savedKeys.privateKeyJwk,
                    ECDH_CURVE,
                    true,
                    ['deriveKey']
                );
                const publicKey = await window.crypto.subtle.importKey(
                    'jwk',
                    savedKeys.publicKeyJwk,
                    ECDH_CURVE,
                    true,
                    []
                );
                _keyPair = { privateKey, publicKey };
                _sessionId = savedKeys.sessionId || generateSessionId();
                console.log('🔑 Loaded persistent E2E keys from VaultKeyStore (JWK mode)');
                return _keyPair;
            }
            }
        } catch (err) {
            console.warn('Failed to load persistent keys from store:', err);
        }

        _keyPair = await window.crypto.subtle.generateKey(
            ECDH_CURVE,
            true, // extractable (need to export public key)
            ['deriveKey']
        );

        _sessionId = generateSessionId();

        try {
            const privateKeyJwk = await window.crypto.subtle.exportKey('jwk', _keyPair.privateKey);
            const publicKeyJwk = await window.crypto.subtle.exportKey('jwk', _keyPair.publicKey);
            await VaultKeyStore.put('identity_keypair', {
                privateKeyJwk,
                publicKeyJwk,
                sessionId: _sessionId
            });
            console.log('🔑 Generated and saved persistent E2E keys to VaultKeyStore (JWK mode)');
        } catch (err) {
            console.error('Failed to save E2E keys to VaultKeyStore:', err);
        }

        return _keyPair;
    }

    /**
     * Export public key as JWK for transmission
     */
    async function exportPublicKey() {
        if (!_keyPair) throw new Error('Key pair not generated');
        return await window.crypto.subtle.exportKey('jwk', _keyPair.publicKey);
    }

    /**
     * Import a peer's public key from JWK
     */
    async function importPublicKey(jwk) {
        return await window.crypto.subtle.importKey(
            'jwk',
            jwk,
            ECDH_CURVE,
            true,
            []
        );
    }

    /**
     * Derive shared AES-256-GCM key from ECDH
     * This key is NEVER transmitted — computed independently by both parties
     */
    async function deriveSharedKey(peerPublicKey) {
        if (!_keyPair) throw new Error('Key pair not generated');

        const importedPeerKey = typeof peerPublicKey === 'object' && peerPublicKey.kty
            ? await importPublicKey(peerPublicKey)
            : peerPublicKey;

        _sharedKey = await window.crypto.subtle.deriveKey(
            { name: 'ECDH', public: importedPeerKey },
            _keyPair.privateKey,
            AES_ALGO,
            false, // non-extractable — key stays in crypto subsystem
            ['encrypt', 'decrypt']
        );

        return _sharedKey;
    }

    /**
     * Encrypt a message using AES-256-GCM
     * Returns: { ciphertext (base64), iv (base64), authTag (included in ciphertext) }
     */
    async function encrypt(plaintext) {
        if (!_sharedKey) throw new Error('Shared key not derived. Complete key exchange first.');

        const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
        const encodedText = new TextEncoder().encode(plaintext);

        const encrypted = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            _sharedKey,
            encodedText
        );

        return {
            ciphertext: arrayBufferToBase64(encrypted),
            iv: arrayBufferToBase64(iv)
        };
    }

    /**
     * Decrypt a message using AES-256-GCM
     * Verifies authenticity via GCM auth tag
     */
    async function decrypt(ciphertext, iv) {
        if (!_sharedKey) throw new Error('Shared key not derived');

        const ciphertextBuffer = base64ToArrayBuffer(ciphertext);
        const ivBuffer = base64ToArrayBuffer(iv);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ivBuffer, tagLength: 128 },
            _sharedKey,
            ciphertextBuffer
        );

        return new TextDecoder().decode(decrypted);
    }

    /**
     * Encrypt raw binary data (e.g. file ArrayBuffer)
     * Returns: { ciphertext (ArrayBuffer), iv (base64) }
     */
    async function encryptFileBuffer(arrayBuffer) {
        if (!_sharedKey) throw new Error('Shared key not derived.');

        const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
        const encrypted = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            _sharedKey,
            arrayBuffer
        );

        return {
            ciphertext: encrypted,
            iv: arrayBufferToBase64(iv)
        };
    }

    /**
     * Decrypt raw binary data (from server download)
     * Returns: ArrayBuffer of the original file
     */
    async function decryptFileBuffer(ciphertextBuffer, ivBase64) {
        if (!_sharedKey) throw new Error('Shared key not derived');

        const ivBuffer = base64ToArrayBuffer(ivBase64);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ivBuffer, tagLength: 128 },
            _sharedKey,
            ciphertextBuffer
        );

        return decrypted;
    }

    /**
     * Generate fingerprint of public key for verification
     * Users can compare fingerprints out-of-band to verify identity
     */
    async function getFingerprint(publicKeyJwk) {
        const jwk = publicKeyJwk || await exportPublicKey();
        const keyData = new TextEncoder().encode(JSON.stringify(jwk));
        const hash = await window.crypto.subtle.digest('SHA-256', keyData);
        const bytes = new Uint8Array(hash);

        // Format as groups of 4 hex chars for readability
        const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        return hex.match(/.{1,4}/g).join(' ').toUpperCase();
    }

    /**
     * Get current session ID
     */
    function getSessionId() {
        return _sessionId;
    }

    /**
     * Check if encryption is ready (key exchange completed)
     */
    function isReady() {
        return _sharedKey !== null;
    }

    function hasOwnKeyPair() {
        return _keyPair !== null;
    }

    /**
     * Decrypt a message from a specific peer on the fly using their public key,
     * without overwriting the active peer's shared key.
     */
    async function decryptWithPeerKey(ciphertext, iv, peerPublicKey) {
        if (!_keyPair) throw new Error('Key pair not generated');

        const importedPeerKey = typeof peerPublicKey === 'object' && peerPublicKey.kty
            ? await importPublicKey(peerPublicKey)
            : peerPublicKey;

        // Derive temporary shared key for this message
        const tempSharedKey = await window.crypto.subtle.deriveKey(
            { name: 'ECDH', public: importedPeerKey },
            _keyPair.privateKey,
            AES_ALGO,
            false,
            ['decrypt']
        );

        const ciphertextBuffer = base64ToArrayBuffer(ciphertext);
        const ivBuffer = base64ToArrayBuffer(iv);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ivBuffer, tagLength: 128 },
            tempSharedKey,
            ciphertextBuffer
        );

        return new TextDecoder().decode(decrypted);
    }

    /**
     * Encrypt a message on the fly using a peer's public key (temp shared key derivation)
     */
    async function encryptWithPeerKey(plaintext, peerPublicKey) {
        if (!_keyPair) throw new Error('Key pair not generated');

        const importedPeerKey = typeof peerPublicKey === 'object' && peerPublicKey.kty
            ? await importPublicKey(peerPublicKey)
            : peerPublicKey;

        // Derive temporary shared key for this message
        const tempSharedKey = await window.crypto.subtle.deriveKey(
            { name: 'ECDH', public: importedPeerKey },
            _keyPair.privateKey,
            AES_ALGO,
            false,
            ['encrypt']
        );

        const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
        const encodedText = new TextEncoder().encode(plaintext);

        const encrypted = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            tempSharedKey,
            encodedText
        );

        return {
            ciphertext: arrayBufferToBase64(encrypted),
            iv: arrayBufferToBase64(iv)
        };
    }

    /**
     * Clear all keys (logout / session end)
     */
    function clearKeys() {
        _keyPair = null;
        _sharedKey = null;
        _sessionId = null;
    }

    // ═══════════════════════════════════════
    // Utility Functions
    // ═══════════════════════════════════════

    function arrayBufferToBase64(buffer) {
        const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        let binary = '';
        const len = bytes.byteLength;
        const chunk_size = 0xffff;
        for (let i = 0; i < len; i += chunk_size) {
            binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk_size));
        }
        return btoa(binary);
    }

    function base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const len = binary.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function generateSessionId() {
        const bytes = window.crypto.getRandomValues(new Uint8Array(16));
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    return {
        generateKeyPair,
        exportPublicKey,
        importPublicKey,
        deriveSharedKey,
        encrypt,
        decrypt,
        encryptFileBuffer,
        decryptFileBuffer,
        getFingerprint,
        getSessionId,
        isReady,
        hasOwnKeyPair,
        decryptWithPeerKey,
        encryptWithPeerKey,
        clearKeys,
        arrayBufferToBase64,
        base64ToArrayBuffer
    };
})();
