/**
 * VaultLocalStorage — IndexedDB wrapper for device-only message storage
 * All chat data lives exclusively on the user's device (encrypted).
 * The server stores NOTHING — it is a pure relay.
 */
const VaultLocalStorage = (() => {
    let _dbName = 'VaultChatDB';
    const DB_VERSION = 1;
    const MSG_STORE = 'messages';

    let _db = null;
    let _openPromise = null;

    /**
     * Set the current logged in user ID to partition database storage
     * @param {string|number|null} userId 
     */
    function setCurrentUser(userId) {
        const newDbName = userId ? `VaultChatDB_${userId}` : 'VaultChatDB';
        if (_dbName !== newDbName) {
            if (_db) {
                try {
                    _db.close();
                } catch (e) {
                    console.error('Error closing database:', e);
                }
                _db = null;
            }
            _dbName = newDbName;
            _openPromise = null;
        }
    }

    /**
     * Open (or create) the IndexedDB database
     */
    function open() {
        if (_db) return Promise.resolve(_db);
        if (_openPromise) return _openPromise;

        _openPromise = new Promise((resolve, reject) => {
            const req = indexedDB.open(_dbName, DB_VERSION);

            req.onupgradeneeded = (e) => {
                const db = e.target.result;

                if (!db.objectStoreNames.contains(MSG_STORE)) {
                    const store = db.createObjectStore(MSG_STORE, { keyPath: 'id' });
                    store.createIndex('peerId', 'peerId', { unique: false });
                    store.createIndex('timestamp', 'timestamp', { unique: false });
                    store.createIndex('peerTimestamp', ['peerId', 'timestamp'], { unique: false });
                }
            };

            req.onsuccess = (e) => {
                _db = e.target.result;
                _openPromise = null;
                resolve(_db);
            };

            req.onerror = (e) => {
                console.error('IndexedDB open error:', e.target.error);
                _openPromise = null;
                reject(e.target.error);
            };
        });

        return _openPromise;
    }

    /**
     * Save a message to local storage
     * @param {Object} msg - { id, peerId, text, sent, timestamp, status, isFile, fileData }
     */
    async function saveMessage(msg) {
        const db = await open();
        if (msg && msg.peerId !== undefined && msg.peerId !== null) {
            msg.peerId = Number(msg.peerId);
        }
        return new Promise((resolve, reject) => {
            const tx = db.transaction(MSG_STORE, 'readwrite');
            tx.objectStore(MSG_STORE).put(msg);
            tx.oncomplete = () => resolve();
            tx.onerror = (e) => reject(e.target.error);
        });
    }

    /**
     * Get all messages for a specific peer, sorted by timestamp
     * @param {string|number} peerId
     * @param {number} limit
     * @returns {Promise<Array>}
     */
    async function getMessages(peerId, limit = 200) {
        const db = await open();
        const normalizedPeerId = Number(peerId);
        return new Promise((resolve, reject) => {
            const tx = db.transaction(MSG_STORE, 'readonly');
            const store = tx.objectStore(MSG_STORE);
            const index = store.index('peerId');
            const results = [];

            const req = index.openCursor(IDBKeyRange.only(normalizedPeerId));

            req.onsuccess = (e) => {
                const cursor = e.target.result;
                if (cursor) {
                    results.push(cursor.value);
                    cursor.continue();
                } else {
                    // Sort by timestamp ascending, return last `limit`
                    const parseDate = (dStr) => {
                        if (!dStr) return new Date(0);
                        let normalized = dStr;
                        if (!dStr.includes('T')) {
                            normalized = dStr.replace(' ', 'T') + 'Z';
                        } else if (!dStr.endsWith('Z') && !dStr.includes('+') && !dStr.includes('-')) {
                            normalized = dStr + 'Z';
                        }
                        return new Date(normalized);
                    };
                    results.sort((a, b) => parseDate(a.timestamp) - parseDate(b.timestamp));
                    resolve(results.slice(-limit));
                }
            };

            req.onerror = (e) => reject(e.target.error);
        });
    }

    /**
     * Update a message status (e.g. from 'sending' to 'delivered')
     */
    async function updateMessageStatus(messageId, status) {
        const db = await open();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(MSG_STORE, 'readwrite');
            const store = tx.objectStore(MSG_STORE);
            const req = store.get(messageId);

            req.onsuccess = (e) => {
                const msg = e.target.result;
                if (msg) {
                    msg.status = status;
                    store.put(msg);
                }
            };

            tx.oncomplete = () => resolve();
            tx.onerror = (e) => reject(e.target.error);
        });
    }

    /**
     * Clear all messages for a specific peer (e.g. on key rotation)
     */
    async function clearMessagesForPeer(peerId) {
        const db = await open();
        const normalizedPeerId = Number(peerId);
        return new Promise((resolve, reject) => {
            const tx = db.transaction(MSG_STORE, 'readwrite');
            const store = tx.objectStore(MSG_STORE);
            const index = store.index('peerId');
            const req = index.openCursor(IDBKeyRange.only(normalizedPeerId));

            req.onsuccess = (e) => {
                const cursor = e.target.result;
                if (cursor) {
                    cursor.delete();
                    cursor.continue();
                }
            };

            tx.oncomplete = () => resolve();
            tx.onerror = (e) => reject(e.target.error);
        });
    }

    /**
     * Clear ALL messages (e.g. on logout)
     */
    async function clearAll() {
        const db = await open();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(MSG_STORE, 'readwrite');
            tx.objectStore(MSG_STORE).clear();
            tx.oncomplete = () => resolve();
            tx.onerror = (e) => reject(e.target.error);
        });
    }

    /**
     * Completely delete the database
     */
    async function destroyDatabase() {
        if (_db) {
            _db.close();
            _db = null;
        }
        return new Promise((resolve, reject) => {
            const req = indexedDB.deleteDatabase(_dbName);
            req.onsuccess = () => resolve();
            req.onerror = (e) => reject(e.target.error);
        });
    }

    return {
        open,
        setCurrentUser,
        saveMessage,
        getMessages,
        updateMessageStatus,
        clearMessagesForPeer,
        clearAll,
        destroyDatabase
    };
})();
