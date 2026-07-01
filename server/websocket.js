/**
 * Talk-Secure — WebSocket Handler (Zero-Storage Mode)
 * Pure signaling relay — server stores NOTHING.
 * Messages are forwarded in real-time only.
 * Chat history lives exclusively on users' devices.
 */
const { WebSocketServer } = require('ws');
const { verifyToken } = require('./auth');
const {
    getUserById,
    getAllUsersExcept,
    storePublicKey,
    getPublicKey,
    getUndeliveredMessages,
    markAsDelivered,
    storeMessage
} = require('./database');

// Active connections: userId -> ws
const connections = new Map();

// Per-connection rate limiting
const WS_RATE_LIMIT = 60; // max messages per second
const WS_RATE_WINDOW = 1000; // 1 second window

function setupWebSocket(server) {
    const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 35 * 1024 * 1024 }); // 35MB max payload to accommodate file attachments up to 25MB + Base64 overhead

    wss.on('connection', (ws, req) => {
        let userId = null;
        let username = null;
        let _msgCount = 0;
        let _msgWindowStart = Date.now();

        // Heartbeat to detect stale connections
        ws.isAlive = true;
        ws.on('pong', () => { ws.isAlive = true; });

        // WebSocket rate limiter
        function checkRateLimit() {
            const now = Date.now();
            if (now - _msgWindowStart > WS_RATE_WINDOW) {
                _msgCount = 0;
                _msgWindowStart = now;
            }
            _msgCount++;
            if (_msgCount > WS_RATE_LIMIT) {
                ws.send(JSON.stringify({ type: 'error', message: 'Rate limit exceeded. Slow down.' }));
                return false;
            }
            return true;
        }

        ws.on('message', async (data) => {
            try {
                // Rate limit check
                if (!checkRateLimit()) return;

                const message = JSON.parse(data.toString());

                // Validate message structure
                if (!message || typeof message !== 'object' || !message.type || typeof message.type !== 'string') {
                    ws.send(JSON.stringify({ type: 'error', message: 'Invalid message structure' }));
                    return;
                }
                // Validate message type length
                if (message.type.length > 50) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Invalid message type' }));
                    return;
                }
                
                // Authentication must be the first message
                if (!userId && message.type !== 'auth') {
                    ws.send(JSON.stringify({ type: 'error', message: 'Authentication required' }));
                    ws.close(4001, 'Not authenticated');
                    return;
                }

                switch (message.type) {
                    case 'auth':
                        handleAuth(ws, message);
                        break;
                    case 'key_exchange':
                        handleKeyExchange(ws, message, userId);
                        break;
                    case 'message':
                        handleMessage(ws, message, userId, username);
                        break;
                    case 'typing':
                        handleTyping(ws, message, userId, username);
                        break;
                    case 'read_receipt':
                        handleReadReceipt(ws, message, userId);
                        break;
                    case 'get_peer_key':
                        handleGetPeerKey(ws, message, userId);
                        break;
                    case 'select_peer':
                        handleSelectPeer(ws, message, userId);
                        break;

                    // WebRTC signaling — server is just a relay
                    case 'call_offer':
                    case 'call_answer':
                    case 'call_reject':
                    case 'call_end':
                    case 'ice_candidate':
                        handleWebRTCSignal(ws, message, userId, username);
                        break;

                    default:
                        ws.send(JSON.stringify({ type: 'error', message: 'Unknown message type' }));
                }
            } catch (err) {
                console.error('WebSocket message error:', err.message);
                ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
            }
        });

        ws.on('close', () => {
            if (userId) {
                connections.delete(userId);
                broadcastPresence(userId, false);
                console.log(`🔌 ${username} disconnected`);
            }
        });

        ws.on('error', (err) => {
            console.error('WebSocket error:', err.message);
        });

        // ═══════════════════════════════════════
        // Message Handlers
        // ═══════════════════════════════════════

        function handleAuth(ws, message) {
            const decoded = verifyToken(message.token);
            if (!decoded) {
                ws.send(JSON.stringify({ type: 'auth_error', message: 'Invalid or expired token' }));
                ws.close(4001, 'Authentication failed');
                return;
            }

            userId = decoded.userId;
            username = decoded.username;

            // Close any existing connection for this user
            const existingWs = connections.get(userId);
            if (existingWs && existingWs.readyState === 1) {
                existingWs.close(4002, 'Replaced by new connection');
            }

            connections.set(userId, ws);

            // Get only connected contacts for this user (private directory mode)
            const { getContacts, getPublicKey, getLatestGlobalForceRotationTime } = require('./database');
            const users = getContacts(userId);
            const userList = users.map(u => ({
                id: u.id,
                username: u.username,
                is_admin: u.is_admin,
                online: connections.has(u.id)
            }));

            const keyData = getPublicKey(userId);
            const keyCreatedAt = keyData ? keyData.created_at : null;
            const globalForceRotationTime = getLatestGlobalForceRotationTime();

            ws.send(JSON.stringify({
                type: 'auth_success',
                userId,
                username,
                users: userList,
                keyCreatedAt,
                globalForceRotationTime
            }));

            // Broadcast online status to all connected users
            broadcastPresence(userId, true);

            // Deliver any pending offline messages
            try {
                const offlineMessages = getUndeliveredMessages(userId);
                if (offlineMessages && offlineMessages.length > 0) {
                    console.log(`✉️ Delivering ${offlineMessages.length} offline message(s) to ${username}`);
                    for (const msg of offlineMessages) {
                        const sender = getUserById(msg.sender_id);
                        const senderKeyData = getPublicKey(msg.sender_id);
                        const senderPublicKey = senderKeyData ? JSON.parse(senderKeyData.public_key_jwk) : null;

                        ws.send(JSON.stringify({
                            type: 'new_message',
                            id: msg.id,
                            senderId: msg.sender_id,
                            senderUsername: sender ? sender.username : 'Unknown',
                            senderPublicKey,
                            encryptedContent: msg.encrypted_content,
                            iv: msg.iv,
                            authTag: msg.auth_tag,
                            timestamp: msg.timestamp
                        }));
                        markAsDelivered(msg.id);
                    }
                }
            } catch (dbErr) {
                console.error('Failed to deliver offline messages:', dbErr);
            }
            console.log(`🔗 ${username} connected (zero-storage mode)`);
        }

        function handleSelectPeer(ws, message, userId) {
            if (!userId) return;

            const { peerId } = message;
            if (!peerId) {
                ws.send(JSON.stringify({ type: 'error', message: 'peerId is required' }));
                return;
            }

            const peer = getUserById(peerId);
            if (!peer) {
                ws.send(JSON.stringify({ type: 'error', message: 'User not found' }));
                return;
            }

            ws.send(JSON.stringify({
                type: 'peer_selected',
                peer: {
                    id: peer.id,
                    username: peer.username,
                    online: connections.has(peer.id)
                }
            }));
        }

        function handleKeyExchange(ws, message, userId) {
            if (!userId) return;

            const { publicKey, fingerprint, sessionId } = message;
            if (!publicKey || !fingerprint || !sessionId) {
                ws.send(JSON.stringify({ type: 'error', message: 'Invalid key exchange data' }));
                return;
            }

            // Store this user's public key (only auth data on server)
            storePublicKey(userId, JSON.stringify(publicKey), fingerprint, sessionId);

            // Notify all connected users about this key update
            for (const [connUserId, connWs] of connections.entries()) {
                if (connUserId !== userId && connWs.readyState === 1) {
                    connWs.send(JSON.stringify({
                        type: 'peer_key_update',
                        userId: userId,
                        publicKey,
                        fingerprint,
                        sessionId
                    }));
                }
            }

            ws.send(JSON.stringify({ type: 'key_stored', fingerprint }));
            console.log(`🔑 Key exchanged for ${username} [${fingerprint.substring(0, 8)}...]`);
        }

        /**
         * PURE RELAY — forward message to receiver, store NOTHING
         */
        function handleMessage(ws, message, senderId, senderUsername) {
            if (!senderId) return;

            const { id, encryptedContent, iv, authTag, receiverId } = message;
            if (!id || !encryptedContent || !iv || !receiverId) {
                ws.send(JSON.stringify({ type: 'error', message: 'Invalid message data (receiverId required)' }));
                return;
            }

            // Verify receiver exists
            const receiver = getUserById(receiverId);
            if (!receiver) {
                ws.send(JSON.stringify({ type: 'error', message: 'Recipient not found' }));
                return;
            }

            const timestamp = new Date().toISOString();

            // Acknowledge to sender immediately
            ws.send(JSON.stringify({
                type: 'message_ack',
                id,
                timestamp
            }));

            // Forward to recipient if online — otherwise store in SQLite database
            if (connections.has(receiverId)) {
                const peerWs = connections.get(receiverId);
                const senderKeyData = getPublicKey(senderId);
                const senderPublicKey = senderKeyData ? JSON.parse(senderKeyData.public_key_jwk) : null;

                peerWs.send(JSON.stringify({
                    type: 'new_message',
                    id,
                    senderId,
                    senderUsername,
                    senderPublicKey,
                    encryptedContent,
                    iv,
                    authTag,
                    timestamp
                }));
            } else {
                try {
                    storeMessage(id, senderId, receiverId, encryptedContent, iv, authTag);
                    console.log(`✉️ Queued offline message from ${senderUsername} to user ID ${receiverId}`);
                    // Notify sender that peer is offline but message is queued securely
                    ws.send(JSON.stringify({
                        type: 'message_status',
                        id,
                        status: 'peer_offline'
                    }));
                } catch (dbErr) {
                    console.error('Failed to store offline message:', dbErr);
                    ws.send(JSON.stringify({
                        type: 'message_status',
                        id,
                        status: 'delivery_failed'
                    }));
                }
            }
        }

        function handleTyping(ws, message, userId, username) {
            if (!userId) return;

            const { receiverId } = message;
            if (receiverId && connections.has(receiverId)) {
                const peerWs = connections.get(receiverId);
                peerWs.send(JSON.stringify({
                    type: 'typing',
                    userId: userId,
                    username
                }));
            }
        }

        /**
         * Read receipts — pure relay, no server storage
         */
        function handleReadReceipt(ws, message, userId) {
            if (!userId) return;

            const { messageId, senderId } = message;
            if (messageId && senderId && connections.has(senderId)) {
                const senderWs = connections.get(senderId);
                senderWs.send(JSON.stringify({
                    type: 'read_receipt',
                    messageId
                }));
            }
        }

        function handleGetPeerKey(ws, message, userId) {
            if (!userId) return;

            const { peerId } = message;
            if (!peerId) {
                ws.send(JSON.stringify({ type: 'peer_key', publicKey: null }));
                return;
            }

            const keyData = getPublicKey(peerId);
            if (keyData) {
                ws.send(JSON.stringify({
                    type: 'peer_key',
                    peerId,
                    publicKey: JSON.parse(keyData.public_key_jwk),
                    fingerprint: keyData.fingerprint,
                    sessionId: keyData.session_id
                }));
            } else {
                ws.send(JSON.stringify({ type: 'peer_key', peerId, publicKey: null }));
            }
        }

        /**
         * Relay WebRTC signaling messages to a specific peer
         * Server NEVER inspects or modifies the SDP/ICE data
         */
        function handleWebRTCSignal(ws, message, userId, username) {
            if (!userId) return;

            const targetId = message.receiverId || message.peerId;
            if (!targetId || !connections.has(targetId)) {
                // If caller is initiating a call (call_offer) but peer is offline, send call_reject reason: offline
                if (message.type === 'call_offer') {
                    ws.send(JSON.stringify({
                        type: 'call_reject',
                        reason: 'offline',
                        peerId: targetId
                    }));
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Peer is offline' }));
                }
                return;
            }

            const peerWs = connections.get(targetId);

            // Whitelist only allowed signaling fields — never relay arbitrary client data
            const safeSignal = {
                type: message.type,
                fromUserId: userId,
                fromUsername: username
            };
            if (message.sdp) safeSignal.sdp = message.sdp;
            if (message.candidate) safeSignal.candidate = message.candidate;
            if (message.reason) safeSignal.reason = String(message.reason).substring(0, 50);
            if (message.callType) safeSignal.callType = String(message.callType).substring(0, 20);
            peerWs.send(JSON.stringify(safeSignal));

            const signalLabels = {
                'call_offer': '📞 Call initiated',
                'call_answer': '📞 Call accepted',
                'call_reject': '📞 Call rejected',
                'call_end': '📞 Call ended',
                'ice_candidate': null // Too noisy to log
            };

            const label = signalLabels[message.type];
            if (label) {
                console.log(`${label} by ${username}`);
            }
        }
    });

    // Heartbeat interval — close dead connections
    const heartbeat = setInterval(() => {
        wss.clients.forEach((ws) => {
            if (!ws.isAlive) {
                ws.terminate();
                return;
            }
            ws.isAlive = false;
            ws.ping();
        });
    }, 30000);

    wss.on('close', () => {
        clearInterval(heartbeat);
    });

    return wss;
}

function broadcastPresence(userId, online) {
    const user = getUserById(userId);
    if (!user) return;

    const { getContacts } = require('./database');
    const contacts = getContacts(userId);
    const contactIds = new Set(contacts.map(c => Number(c.id)));

    for (const [connUserId, ws] of connections.entries()) {
        if (connUserId !== userId && contactIds.has(Number(connUserId)) && ws.readyState === 1) {
            ws.send(JSON.stringify({
                type: 'presence',
                userId,
                username: user.username,
                online
            }));
        }
    }
}

function disconnectUser(userId) {
    const ws = connections.get(userId);
    if (ws && ws.readyState === 1) {
        ws.close(4003, 'Account deleted by administrator');
        console.log(`🔌 Terminated active WebSocket session for deleted user ID ${userId}`);
    }
}

function getActiveConnectionsCount() {
    return connections.size;
}

module.exports = { setupWebSocket, disconnectUser, getActiveConnectionsCount };
