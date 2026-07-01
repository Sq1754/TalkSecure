/**
 * Talk-Secure — WebSocket Client
 * Auto-reconnect, message queuing, event system
 */

const VaultSocket = (() => {
    let _ws = null;
    let _token = null;
    let _handlers = {};
    let _reconnectAttempts = 0;
    let _maxReconnect = 10;
    let _messageQueue = [];
    let _connected = false;
    let _intentionalClose = false;

    function connect(token) {
        _token = token;
        _intentionalClose = false;

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}`;

        try {
            _ws = new WebSocket(wsUrl);
        } catch (err) {
            console.error('WebSocket connection error:', err);
            scheduleReconnect();
            return;
        }

        _ws.onopen = () => {
            _reconnectAttempts = 0;
            console.log('🔌 WebSocket connected');

            // Authenticate immediately
            send({ type: 'auth', token: _token });
        };

        _ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                handleMessage(data);
            } catch (err) {
                console.error('Failed to parse WebSocket message:', err);
            }
        };

        _ws.onclose = (event) => {
            _connected = false;
            console.log(`🔌 WebSocket closed: ${event.code} ${event.reason}`);

            if (!_intentionalClose && event.code !== 4001) {
                scheduleReconnect();
            }

            emit('disconnected');
        };

        _ws.onerror = (err) => {
            console.error('WebSocket error:', err);
        };
    }

    function handleMessage(data) {
        switch (data.type) {
            case 'auth_success':
                _connected = true;
                _reconnectAttempts = 0;
                emit('authenticated', data);
                flushQueue();
                break;

            case 'auth_error':
                emit('auth_error', data);
                break;

            case 'new_message':
                emit('message', data);
                break;

            case 'message_ack':
                emit('message_ack', data);
                break;

            case 'typing':
                emit('typing', data);
                break;

            case 'presence':
                emit('presence', data);
                break;

            case 'peer_key_update':
                emit('peer_key_update', data);
                break;

            case 'peer_key':
                emit('peer_key', data);
                break;

            case 'key_stored':
                emit('key_stored', data);
                break;

            case 'history':
                emit('history', data);
                break;

            case 'read_receipt':
                emit('read_receipt', data);
                break;

            case 'message_status':
                emit('message_status', data);
                break;

            case 'peer_selected':
                emit('peer_selected', data);
                break;

            // WebRTC signaling (relayed by server)
            case 'call_offer':
                emit('call_offer', data);
                break;

            case 'call_answer':
                emit('call_answer', data);
                break;

            case 'call_reject':
                emit('call_reject', data);
                break;

            case 'call_end':
                emit('call_end', data);
                break;

            case 'ice_candidate':
                emit('ice_candidate', data);
                break;

            case 'error':
                console.error('Server error:', data.message);
                emit('server_error', data);
                break;

            default:
                console.warn('Unknown message type:', data.type);
        }
    }

    function send(data) {
        if (_ws && _ws.readyState === WebSocket.OPEN) {
            _ws.send(JSON.stringify(data));
        } else {
            // Queue for when connection is restored
            if (data.type !== 'auth') {
                _messageQueue.push(data);
            }
        }
    }

    function flushQueue() {
        while (_messageQueue.length > 0) {
            const msg = _messageQueue.shift();
            send(msg);
        }
    }

    function scheduleReconnect() {
        if (_reconnectAttempts >= _maxReconnect) {
            console.log('Max reconnect attempts reached');
            emit('max_reconnect');
            return;
        }

        // Exponential backoff: 1s, 2s, 4s, 8s... max 30s
        const delay = Math.min(1000 * Math.pow(2, _reconnectAttempts), 30000);
        _reconnectAttempts++;

        console.log(`🔄 Reconnecting in ${delay / 1000}s (attempt ${_reconnectAttempts})`);
        emit('reconnecting', { attempt: _reconnectAttempts, delay });

        setTimeout(() => {
            if (!_intentionalClose && _token) {
                connect(_token);
            }
        }, delay);
    }

    function disconnect() {
        _intentionalClose = true;
        if (_ws) {
            _ws.close(1000, 'User logout');
            _ws = null;
        }
        _connected = false;
        _messageQueue = [];
    }

    function isConnected() {
        return _connected;
    }

    // ═══════════════════════════════════════
    // Event System
    // ═══════════════════════════════════════

    function on(event, handler) {
        if (!_handlers[event]) _handlers[event] = [];
        _handlers[event].push(handler);
    }

    function off(event, handler) {
        if (!_handlers[event]) return;
        _handlers[event] = _handlers[event].filter(h => h !== handler);
    }

    function emit(event, data) {
        if (_handlers[event]) {
            _handlers[event].forEach(h => {
                try { h(data); } catch (err) { console.error(`Handler error [${event}]:`, err); }
            });
        }
    }

    return {
        connect,
        disconnect,
        send,
        isConnected,
        on,
        off,
        clearHandlers: function() { _handlers = {}; }
    };
})();
