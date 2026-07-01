/**
 * Talk-Secure — IndexedDB Key Storage
 * Securely stores encryption keys in the browser
 * Keys NEVER leave the device
 */

const VaultKeyStore = (() => {
    let _dbName = 'TalkSecureKeys';
    const DB_VERSION = 2;
    const STORE_NAME = 'keys';

    let _db = null;

    function setCurrentUser(userId) {
        const newDbName = userId ? `TalkSecureKeys_${userId}` : 'TalkSecureKeys';
        if (_dbName !== newDbName) {
            if (_db) {
                try {
                    _db.close();
                } catch (e) {
                    console.error('Error closing key database:', e);
                }
                _db = null;
            }
            _dbName = newDbName;
        }
    }

    async function openDb() {
        if (_db) return _db;

        return new Promise((resolve, reject) => {
            const request = indexedDB.open(_dbName, DB_VERSION);

            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                if (!db.objectStoreNames.contains(STORE_NAME)) {
                    db.createObjectStore(STORE_NAME, { keyPath: 'id' });
                }
            };

            request.onsuccess = (event) => {
                _db = event.target.result;
                resolve(_db);
            };

            request.onerror = (event) => {
                reject(new Error('Failed to open key store: ' + event.target.error));
            };
        });
    }

    async function put(id, data) {
        const db = await openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readwrite');
            const store = tx.objectStore(STORE_NAME);
            store.put({ id, ...data, updatedAt: Date.now() });
            tx.oncomplete = resolve;
            tx.onerror = () => reject(tx.error);
        });
    }

    async function get(id) {
        const db = await openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readonly');
            const store = tx.objectStore(STORE_NAME);
            const request = store.get(id);
            request.onsuccess = () => resolve(request.result || null);
            request.onerror = () => reject(request.error);
        });
    }

    async function remove(id) {
        const db = await openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readwrite');
            const store = tx.objectStore(STORE_NAME);
            store.delete(id);
            tx.oncomplete = resolve;
            tx.onerror = () => reject(tx.error);
        });
    }

    async function clearAll() {
        const db = await openDb();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readwrite');
            const store = tx.objectStore(STORE_NAME);
            store.clear();
            tx.oncomplete = resolve;
            tx.onerror = () => reject(tx.error);
        });
    }

    // High-level helpers

    async function saveSession(userId, token, username, isAdmin) {
        sessionStorage.setItem('talk_secure_session', JSON.stringify({ userId, token, username, isAdmin: !!isAdmin }));
    }

    async function getSession() {
        const data = sessionStorage.getItem('talk_secure_session');
        return data ? JSON.parse(data) : null;
    }

    async function savePeerFingerprint(peerId, fingerprint) {
        await put('peerFingerprint_' + peerId, { fingerprint });
    }

    async function getPeerFingerprint(peerId) {
        const data = await get('peerFingerprint_' + peerId);
        return data ? data.fingerprint : null;
    }

    async function saveChatTheme(peerId, themeName) {
        await put('chatTheme_' + peerId, { theme: themeName });
    }

    async function getChatTheme(peerId) {
        const data = await get('chatTheme_' + peerId);
        return data ? data.theme : null;
    }

    async function logout() {
        sessionStorage.removeItem('talk_secure_session');
    }

    return {
        setCurrentUser,
        saveSession,
        getSession,
        savePeerFingerprint,
        getPeerFingerprint,
        saveChatTheme,
        getChatTheme,
        logout,
        put,
        get
    };
})();
