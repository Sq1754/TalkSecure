/**
 * Talk-Secure - Main Application Logic
 * Orchestrates auth, encryption, WebSocket, and UI
 * Multi-user support with contact list
 * ZERO-STORAGE: All chat data stored on device only (IndexedDB)
 */

const VaultApp = (() => {
    var _seenMessageIds = new Set();
    let _userId = null;
    let _username = null;
    let _token = null;
    let _isAdmin = false;
    let _peer = null;
    let _users = [];
    let _typingTimeout = null;
    let _lastTypingSent = 0;
    let _callTimerInterval = null;
    let _callStartTime = null;
    let _ringtoneInterval = null;
    let _messageProcessingQueue = [];
    let _isProcessingQueue = false;
    let _mediaRecorder = null;
    let _audioChunks = [];
    let _isRecording = false;
    let _pendingAdminKeyResolve = null;
    let _pendingAdminKeyUserId = null;
    let _sentMessagesTimes = {};
    let _webrtcCallStartTime = null;
    let _pendingId = null;

    async function init() {
        await checkRegistrationStatus();
        const session = await VaultKeyStore.getSession();
        if (session && session.token) {
            _token = session.token;
            _userId = session.userId;
            _username = session.username;
            _isAdmin = !!session.isAdmin;

            // Partition storage and keystore by user ID
            VaultLocalStorage.setCurrentUser(_userId);
            VaultKeyStore.setCurrentUser(_userId);

            try {
                await VaultLocalStorage.open();
            } catch (e) {
                console.error('Failed to open local storage:', e);
            }

            await connectAndSetup();
            var adminBtn = document.getElementById('menu-admin-dashboard');
            if (adminBtn) {
                adminBtn.style.display = isAdminUser() ? 'flex' : 'none';
            }
        } else {
            // Default/guest state
            VaultLocalStorage.setCurrentUser(null);
            VaultKeyStore.setCurrentUser(null);

            try {
                await VaultLocalStorage.open();
            } catch (e) {
                console.error('Failed to open local storage:', e);
            }
            showAuthView();
        }
        setupEventListeners();
    }

    async function checkRegistrationStatus() {
        try {
            const res = await fetch('/api/auth/status');
            const data = await res.json();
            const registerTab = document.getElementById('register-tab');
            if (!data.registrationOpen && registerTab) {
                registerTab.style.opacity = '0.5';
                registerTab.title = 'Registration closed - max users reached';
            }
        } catch (err) { console.error('Failed to check registration status:', err); }
    }

    async function handleRegister(e) {
        e.preventDefault();
        const username = document.getElementById('reg-username').value.trim();
        const email = document.getElementById('reg-email').value.trim();
        const phone = document.getElementById('reg-phone').value.trim();
        const inviteToken = document.getElementById('reg-invite').value.trim();
        const password = document.getElementById('reg-password').value;
        const confirmPassword = document.getElementById('reg-confirm-password').value;
        if (password !== confirmPassword) { showAuthError('Passwords do not match'); return; }
        setAuthLoading(true);
        try {
            const res = await fetch('/api/auth/register', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password, email, phone, inviteToken })
            });
            const data = await res.json();
            if (data.success) {
                if (data.pending) {
                    showOtpForm(data.pendingId, data.message);
                } else {
                    showAuthSuccess('Account created! Please login.');
                    switchToLogin();
                }
            }
            else { showAuthError(data.message); }
        } catch (err) { showAuthError('Connection error. Is the server running?'); }
        finally { setAuthLoading(false); }
    }

    function showOtpForm(pendingId, msg) {
        _pendingId = pendingId;
        document.getElementById('login-form').classList.remove('active');
        document.getElementById('register-form').classList.remove('active');
        const tabs = document.querySelector('.auth-tabs');
        if (tabs) tabs.style.display = 'none';
        
        const otpForm = document.getElementById('otp-form');
        if (otpForm) otpForm.classList.add('active');
        const otpCodeInput = document.getElementById('otp-code');
        if (otpCodeInput) {
            otpCodeInput.value = '';
            otpCodeInput.focus();
        }
        showAuthSuccess(msg);
    }

    function hideOtpForm() {
        _pendingId = null;
        const otpForm = document.getElementById('otp-form');
        if (otpForm) otpForm.classList.remove('active');
        const tabs = document.querySelector('.auth-tabs');
        if (tabs) tabs.style.display = 'flex';
        const registerForm = document.getElementById('register-form');
        if (registerForm) registerForm.classList.add('active');
    }

    function handleOtpCancel() {
        hideOtpForm();
    }

    async function handleOtpSubmit(e) {
        e.preventDefault();
        const otpCodeEl = document.getElementById('otp-code');
        const otp = otpCodeEl ? otpCodeEl.value.trim() : '';
        if (!otp || !_pendingId) return;
        setAuthLoading(true);
        try {
            const res = await fetch('/api/auth/verify-otp', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pendingId: _pendingId, otp })
            });
            const data = await res.json();
            if (data.success) {
                showAuthSuccess('Account created successfully! Please login.');
                hideOtpForm();
                switchToLogin();
            } else {
                showAuthError(data.message || 'Verification failed');
            }
        } catch (err) {
            showAuthError('Connection error. Is the server running?');
        } finally {
            setAuthLoading(false);
        }
    }

    async function handleLogin(e) {
        e.preventDefault();
        const username = document.getElementById('login-username').value.trim();
        const password = document.getElementById('login-password').value;
        setAuthLoading(true);
        try {
            const res = await fetch('/api/auth/login', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const data = await res.json();
            if (data.success) {
                _token = data.token; _userId = data.userId; _username = data.username; _isAdmin = !!data.isAdmin;
                
                // Partition storage and keystore by user ID
                VaultLocalStorage.setCurrentUser(_userId);
                VaultKeyStore.setCurrentUser(_userId);

                await VaultKeyStore.saveSession(_userId, _token, _username, _isAdmin);
                await connectAndSetup();
                var adminBtn = document.getElementById('menu-admin-dashboard');
                if (adminBtn) {
                    adminBtn.style.display = isAdminUser() ? 'flex' : 'none';
                }
            } else { showAuthError(data.message); }
        } catch (err) { showAuthError('Connection error. Is the server running?'); }
        finally { setAuthLoading(false); }
    }

    async function handleLogout() {
        if (VaultWebRTC.getCallState() !== 'idle') VaultWebRTC.endCall();
        else VaultWebRTC.reset();
        VaultSocket.disconnect(); VaultCrypto.clearKeys();
        await VaultKeyStore.logout();
        
        // Reset storage partition to default/guest state
        VaultLocalStorage.setCurrentUser(null);
        VaultKeyStore.setCurrentUser(null);

        _token = null; _userId = null; _username = null; _peer = null; _users = [];
        document.body.classList.remove('theme-cyberpunk', 'theme-emerald', 'theme-ocean', 'theme-crimson', 'theme-default');
        showAuthView();
    }

    async function connectAndSetup() {
        showChatView();
        updateConnectionStatus('connecting');
        VaultWebRTC.reset();
        clearChatMessages();
        await VaultCrypto.generateKeyPair();

        // Clear old handlers to prevent duplicates on reconnect
        VaultSocket.clearHandlers();
        VaultSocket.connect(_token);

        VaultSocket.on('authenticated', onAuthenticated);
        VaultSocket.on('auth_error', onAuthError);
        VaultSocket.on('message', function(data) {
            _messageProcessingQueue.push(data);
            processQueue();
        });
        VaultSocket.on('message_ack', onMessageAck);
        VaultSocket.on('message_status', onMessageStatus);
        VaultSocket.on('typing', onPeerTyping);
        VaultSocket.on('presence', onPresenceUpdate);
        VaultSocket.on('peer_key_update', onPeerKeyUpdate);
        VaultSocket.on('peer_key', onPeerKeyReceived);
        VaultSocket.on('key_stored', onKeyStored);
        VaultSocket.on('read_receipt', onReadReceipt);
        VaultSocket.on('disconnected', onDisconnected);
        VaultSocket.on('reconnecting', onReconnecting);

        VaultSocket.on('call_offer', function(data) { VaultWebRTC.handleOffer(data.sdp); });
        VaultSocket.on('call_answer', function(data) { VaultWebRTC.handleAnswer(data.sdp); });
        VaultSocket.on('call_reject', function(data) { VaultWebRTC.handleReject(data.reason); });
        VaultSocket.on('call_end', function() { VaultWebRTC.handleCallEnd(); });
        VaultSocket.on('ice_candidate', function(data) { VaultWebRTC.handleIceCandidate(data.candidate); });

        setupWebRTCHandlers();
    }

    function clearChatMessages() {
        var el = document.getElementById('chat-messages');
        if (el) el.innerHTML = '<div class="empty-chat"><div class="empty-icon"><svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" width="64" height="64"><rect x="8" y="28" width="48" height="32" rx="4" stroke="currentColor" stroke-width="2" opacity="0.3"/><path d="M20 28V20C20 13.373 25.373 8 32 8C38.627 8 44 13.373 44 20V28" stroke="currentColor" stroke-width="2" opacity="0.3" stroke-linecap="round"/></svg></div><p>Messages are end-to-end encrypted.</p><p class="muted">Your chat history is stored only on your device.</p></div>';
    }

    // ═══════════════════════════════════════
    // Authentication & Key Exchange
    // ═══════════════════════════════════════

    async function onAuthenticated(data) {
        _users = data.users || [];
        updateConnectionStatus('connected');
        updateUserDisplay();
        renderContactList();
        // Process pending receipts for all currently online users
        _users.forEach(function(u) {
            if (u.online) {
                processPendingReceiptsForUser(u.id);
            }
        });
        var publicKey = await VaultCrypto.exportPublicKey();
        var fingerprint = await VaultCrypto.getFingerprint(publicKey);
        VaultSocket.send({ type: 'key_exchange', publicKey: publicKey, fingerprint: fingerprint, sessionId: VaultCrypto.getSessionId(), peerId: _peer ? _peer.id : null });
        updateFingerprint('own', fingerprint);
        if (_peer) { selectPeer(_peer.id); }
        
        // Security check: identity key age and global force rotation
        checkIdentityKeyExpiration(data.keyCreatedAt, data.globalForceRotationTime);
    }

    function checkIdentityKeyExpiration(keyCreatedAt, globalForceRotationTime) {
        var banner = document.getElementById('key-rotation-alert-banner');
        var textEl = document.getElementById('key-rotation-alert-text');
        if (!banner) return;

        // Default hidden
        banner.style.display = 'none';

        if (!keyCreatedAt) return;

        var keyDate = new Date(keyCreatedAt);
        var forceRotationRequired = false;
        var alertMessage = '';

        // 1. Check global force rotation time
        if (globalForceRotationTime) {
            var forceDate = new Date(globalForceRotationTime);
            if (forceDate.getTime() > keyDate.getTime()) {
                forceRotationRequired = true;
                alertMessage = 'An administrator has forced a global security key compliance rotation. Please rotate your encryption keys now.';
            }
        }

        // 2. Check 30-day key age expiry
        if (!forceRotationRequired) {
            var ageInDays = (Date.now() - keyDate.getTime()) / (1000 * 60 * 60 * 24);
            if (ageInDays > 30) {
                forceRotationRequired = true;
                alertMessage = 'Your E2E identity key is older than 30 days (' + Math.round(ageInDays) + ' days old). We recommend rotating your keys now to maintain peak forward secrecy.';
            }
        }

        if (forceRotationRequired) {
            if (textEl) textEl.textContent = alertMessage;
            banner.style.display = 'flex';
        }
    }

    function onAuthError(data) { handleLogout(); showAuthError(data.message || 'Session expired.'); }

    function renderContactList() {
        var list = document.getElementById('contacts-list');
        var count = document.getElementById('contacts-count');
        if (!list) return;
        if (count) count.textContent = _users.length;
        if (_users.length === 0) { list.innerHTML = '<div class="contacts-empty">No other users yet. Share the link!</div>'; return; }
        list.innerHTML = _users.map(function(u) {
            return '<div class="contact-item ' + (_peer && _peer.id === u.id ? 'active' : '') + '" data-user-id="' + u.id + '"><div class="contact-avatar">' + u.username.charAt(0).toUpperCase() + '</div><div class="contact-info"><span class="contact-name">' + escapeHtml(u.username) + '</span><span class="contact-status ' + (u.online ? 'online' : 'offline') + '">' + (u.online ? '\u25cf Online' : '\u25cb Offline') + '</span></div></div>';
        }).join('');
        list.querySelectorAll('.contact-item').forEach(function(item) {
            item.addEventListener('click', function() {
                var uid = parseInt(item.dataset.userId, 10);
                if (uid) selectPeer(uid);
            });
        });
    }

    async function selectPeer(peerId) {
        var user = _users.find(function(u) { return Number(u.id) === Number(peerId); });
        if (!user) return;
        _peer = { id: user.id, username: user.username, online: user.online };
        updatePeerDisplay();
        renderContactList();
        clearChatMessages();
        await loadLocalHistory(_peer.id);
        
        // Load custom theme
        var activeTheme = await VaultKeyStore.getChatTheme(peerId) || 'theme-default';
        await applyChatTheme(activeTheme);
        
        updateEncryptionStatus('waiting');
        enableMessageInput(false);
        enableVideoCallButton(false);
        VaultSocket.send({ type: 'get_peer_key', peerId: _peer.id });
        var sidebar = document.getElementById('contacts-sidebar');
        var overlay = document.getElementById('sidebar-overlay');
        if (sidebar) sidebar.classList.remove('open');
        if (overlay) overlay.classList.remove('active');
    }

    async function onPeerKeyReceived(data) {
        if (_pendingAdminKeyResolve && Number(data.peerId) === Number(_pendingAdminKeyUserId)) {
            _pendingAdminKeyResolve(data.publicKey);
            _pendingAdminKeyResolve = null;
            return;
        }
        if (data.publicKey) { await completePeerKeyExchange(data.publicKey, data.fingerprint); }
        else { updateEncryptionStatus('waiting'); }
    }
    async function onPeerKeyUpdate(data) {
        if (_peer && Number(data.userId) === Number(_peer.id) && data.publicKey) {
            await completePeerKeyExchange(data.publicKey, data.fingerprint);
        }
    }
    async function completePeerKeyExchange(peerPublicKey, peerFingerprint) {
        try {
            await VaultCrypto.deriveSharedKey(peerPublicKey);
            updateEncryptionStatus('active');
            updateFingerprint('peer', peerFingerprint);
            if (_peer) await loadLocalHistory(_peer.id);
            enableMessageInput(true);
            enableVideoCallButton(true);
            console.log('\ud83d\udd10 E2E encryption established (device-only storage)');
        } catch (err) { console.error('Key exchange failed:', err); updateEncryptionStatus('error'); }
    }
    function onKeyStored() { console.log('\ud83d\udd11 Public key stored on server'); }

    // ═══════════════════════════════════════
    // Messaging (Device-Only Storage)
    // ═══════════════════════════════════════

    async function sendMessage(textOverride) {
        var input = document.getElementById('message-input');
        var text = textOverride || input.value.trim();
        if (!text || !VaultCrypto.isReady() || !_peer) return;
        try {
            var encrypted = await VaultCrypto.encrypt(text);
            var messageId = generateId();
            var timestamp = new Date().toISOString();
            VaultSocket.send({ type: 'message', id: messageId, encryptedContent: encrypted.ciphertext, iv: encrypted.iv, receiverId: _peer.id });
            addMessageToUI({ id: messageId, text: text, sent: true, timestamp: timestamp, status: 'sending' });
            await VaultLocalStorage.saveMessage({ id: messageId, peerId: _peer.id, text: text, sent: true, timestamp: timestamp, status: 'sending' });
            if (!textOverride) {
                input.value = '';
                input.style.height = 'auto';
                var voiceBtn = document.getElementById('voice-record-btn');
                var sBtn = document.getElementById('send-btn');
                if (sBtn) sBtn.style.display = 'none';
                if (voiceBtn) voiceBtn.style.display = 'flex';
            }
            scrollToBottom();
        } catch (err) { console.error('Failed to send:', err); showToast('Failed to encrypt message', 'error'); }
    }

    // ═══════════════════════════════════════
    // File Attachments (P2P via WebSocket relay)
    // ═══════════════════════════════════════

    async function handleFileAttachment(e) {
        var file = e.target.files[0];
        if (!file) return;
        if (file.size > 25 * 1024 * 1024) { showToast('File exceeds 25MB limit (P2P mode)', 'error'); e.target.value = ''; return; }
        if (!_peer || !_peer.online) { showToast('Peer must be online for file transfer', 'error'); e.target.value = ''; return; }
        var progressContainer = document.getElementById('upload-progress-container');
        var progressBar = document.getElementById('upload-progress-bar');
        var filenameSpan = document.getElementById('upload-filename');
        try {
            progressContainer.classList.add('active');
            filenameSpan.textContent = 'Encrypting ' + file.name + '...';
            progressBar.style.width = '10%';
            enableMessageInput(false);
            var buffer = await file.arrayBuffer();
            progressBar.style.width = '30%';
            filenameSpan.textContent = 'Sending ' + file.name + '...';
            var encrypted = await VaultCrypto.encryptFileBuffer(buffer);
            progressBar.style.width = '60%';
            var base64Data = VaultCrypto.arrayBufferToBase64(encrypted.ciphertext);
            progressBar.style.width = '90%';
            var fileMsg = { type: 'file_attachment', fileName: file.name, fileType: file.type, fileSize: file.size, fileIv: encrypted.iv, fileData: base64Data };
            await sendMessage(JSON.stringify(fileMsg));
            progressBar.style.width = '100%';
            setTimeout(function() { progressContainer.classList.remove('active'); progressBar.style.width = '0%'; enableMessageInput(true); }, 500);
        } catch (err) {
            console.error('File attachment error:', err);
            showToast('Failed to send file', 'error');
            progressContainer.classList.remove('active');
            enableMessageInput(true);
        }
        e.target.value = '';
    }

    // ═══════════════════════════════════════
    // Message Handlers
    // ═══════════════════════════════════════

    async function processQueue() {
        if (_isProcessingQueue || _messageProcessingQueue.length === 0) return;
        _isProcessingQueue = true;
        while (_messageProcessingQueue.length > 0) {
            const data = _messageProcessingQueue.shift();
            try {
                await onMessageReceived(data);
            } catch (err) {
                console.error('Queue processing error:', err);
            }
        }
        _isProcessingQueue = false;
    }

    async function onMessageReceived(data) {
        if (!VaultCrypto.hasOwnKeyPair()) return;
        try {
            var plaintext;
            if (data.senderPublicKey) {
                plaintext = await VaultCrypto.decryptWithPeerKey(data.encryptedContent, data.iv, data.senderPublicKey);
            } else {
                plaintext = await VaultCrypto.decrypt(data.encryptedContent, data.iv);
            }

            await VaultLocalStorage.saveMessage({ id: data.id, peerId: data.senderId, text: plaintext, sent: false, timestamp: data.timestamp, status: 'delivered' });
            
            var senderObj = _users.find(function(u) { return Number(u.id) === Number(data.senderId); });
            var isSenderOnline = senderObj && senderObj.online;
            if (isSenderOnline) {
                VaultSocket.send({ type: 'read_receipt', messageId: data.id, senderId: data.senderId });
            } else {
                queuePendingReceipt(data.senderId, data.id);
            }

            if (_peer && Number(data.senderId) === Number(_peer.id)) {
                if (_seenMessageIds.has(data.id)) { console.warn('Duplicate message rejected:', data.id); return; }
                _seenMessageIds.add(data.id);
                // Prevent unbounded growth — trim oldest entries if set gets too large
                if (_seenMessageIds.size > 5000) {
                    var iter = _seenMessageIds.values();
                    for (var i = 0; i < 1000; i++) { _seenMessageIds.delete(iter.next().value); }
                }
                addMessageToUI({ id: data.id, text: plaintext, sent: false, timestamp: data.timestamp, senderUsername: data.senderUsername });
                scrollToBottom();
            } else {
                // Background message notification
                showToast('New message from ' + data.senderUsername, 'info');
                playNotificationSound();
            }

            if (document.hidden) { playNotificationSound(); document.title = 'New Message - Talk-Secure'; }
        } catch (err) {
            console.error('Failed to decrypt incoming message:', err);
            showToast('Failed to decrypt message from ' + data.senderUsername, 'error');
            if (_peer && Number(data.senderId) === Number(_peer.id)) {
                addMessageToUI({ id: data.id, text: '🔒 Unable to decrypt', sent: false, timestamp: data.timestamp, error: true });
            }
        }
    }

    function onMessageAck(data) {
        var msgEl = document.querySelector('[data-msg-id="' + data.id + '"]');
        if (msgEl) { var s = msgEl.querySelector('.msg-status'); if (s) { s.textContent = '\u2713'; s.title = 'Delivered'; } }
        VaultLocalStorage.updateMessageStatus(data.id, 'delivered');
        
        if (_sentMessagesTimes[data.id]) {
            var rtt = Date.now() - _sentMessagesTimes[data.id];
            delete _sentMessagesTimes[data.id];
            reportDiagnosticMetric('ws_latency', rtt);
        }
    }

    function onMessageStatus(data) {
        if (data.status === 'peer_offline') { showToast('Peer is offline \u2014 message saved locally', 'info'); }
    }

    function queuePendingReceipt(senderId, messageId) {
        if (!_userId) return;
        var key = 'pending_receipts_' + _userId;
        var queue = {};
        try {
            queue = JSON.parse(localStorage.getItem(key)) || {};
        } catch (e) {}
        if (!queue[senderId]) queue[senderId] = [];
        if (!queue[senderId].includes(messageId)) {
            queue[senderId].push(messageId);
            localStorage.setItem(key, JSON.stringify(queue));
        }
    }

    function processPendingReceiptsForUser(peerId) {
        if (!_userId) return;
        var key = 'pending_receipts_' + _userId;
        var queue = {};
        try {
            queue = JSON.parse(localStorage.getItem(key)) || {};
        } catch (e) {}
        var list = queue[peerId];
        if (list && list.length > 0) {
            console.log('Sending ' + list.length + ' pending read receipts to online peer ' + peerId);
            list.forEach(function(msgId) {
                VaultSocket.send({ type: 'read_receipt', messageId: msgId, senderId: Number(peerId) });
            });
            delete queue[peerId];
            localStorage.setItem(key, JSON.stringify(queue));
        }
    }

    function onReadReceipt(data) {
        var msgEl = document.querySelector('[data-msg-id="' + data.messageId + '"]');
        if (msgEl) { var s = msgEl.querySelector('.msg-status'); if (s) { s.textContent = '\u2713\u2713'; s.title = 'Read'; s.classList.add('read'); } }
        VaultLocalStorage.updateMessageStatus(data.messageId, 'read');
    }

    async function loadLocalHistory(peerId) {
        var chatMessages = document.getElementById('chat-messages');
        chatMessages.innerHTML = '';
        try {
            var messages = await VaultLocalStorage.getMessages(peerId);
            for (var i = 0; i < messages.length; i++) {
                addMessageToUI({ id: messages[i].id, text: messages[i].text, sent: messages[i].sent, timestamp: messages[i].timestamp, status: messages[i].status || 'delivered' });
            }
            scrollToBottom();
        } catch (err) { console.error('Failed to load local history:', err); }
    }

    // ═══════════════════════════════════════
    // Typing & Presence
    // ═══════════════════════════════════════

    function handleTypingInput() {
        var now = Date.now();
        if (now - _lastTypingSent > 2000 && _peer) { VaultSocket.send({ type: 'typing', receiverId: _peer.id }); _lastTypingSent = now; }
    }
    function onPeerTyping(data) {
        if (!_peer || Number(data.userId) !== Number(_peer.id)) return;
        var indicator = document.getElementById('typing-indicator');
        if (indicator) { indicator.classList.add('visible'); clearTimeout(_typingTimeout); _typingTimeout = setTimeout(function() { indicator.classList.remove('visible'); }, 3000); }
    }
    function onPresenceUpdate(data) {
        var u = _users.find(function(x) { return Number(x.id) === Number(data.userId); });
        if (u) { 
            u.online = data.online; 
            renderContactList(); 
            if (data.online) {
                processPendingReceiptsForUser(data.userId);
            }
        }
        if (_peer && Number(data.userId) === Number(_peer.id)) {
            _peer.online = data.online;
            updatePeerDisplay();
            if (VaultCrypto.isReady()) enableVideoCallButton(true);
            if (!data.online && VaultWebRTC.getCallState() === 'connected') { VaultWebRTC.endCall(); showToast('Call ended - peer went offline', 'info'); }
        }
    }
    function onDisconnected() { updateConnectionStatus('disconnected'); enableMessageInput(false); enableVideoCallButton(false); if (VaultWebRTC.getCallState() !== 'idle') VaultWebRTC.endCall(); }
    function onReconnecting() { updateConnectionStatus('reconnecting'); }

    // ═══════════════════════════════════════
    // WebRTC (Video Calls) — Mobile-First UX
    // ═══════════════════════════════════════

    let _controlsHideTimer = null;
    let _qualityInterval = null;
    let _videosSwapped = false;

    function setupWebRTCHandlers() {
        VaultWebRTC.clearHandlers();
        VaultWebRTC.on('signal_send', function(data) { if (_peer) data.receiverId = _peer.id; VaultSocket.send(data); });
        VaultWebRTC.on('local_stream', function(data) { var v = document.getElementById('local-video'); if (v) v.srcObject = data.stream; });
        VaultWebRTC.on('remote_stream', function(data) { var v = document.getElementById('remote-video'); if (v) v.srcObject = data.stream; });
        VaultWebRTC.on('state_change', function(data) { handleCallStateChange(data.state, data); });
        VaultWebRTC.on('call_ended', function() { hideCallOverlay(); hideIncomingCallModal(); stopCallTimer(); stopRingtone(); stopQualityMonitor(); showToast('Call ended', 'info'); });
        VaultWebRTC.on('rejected', function(data) {
            hideCallOverlay();
            stopCallTimer();
            stopQualityMonitor();
            stopRingtone();
            if (data.reason === 'offline') {
                showToast('User is offline', 'info');
                sendMissedCallMessage();
            } else if (data.reason === 'busy') {
                showToast('User is busy', 'info');
            } else {
                showToast('Call declined', 'info');
            }
        });
        VaultWebRTC.on('mute_change', function(data) { var b = document.getElementById('toggle-mute-btn'); if (b) b.classList.toggle('active', data.muted); });
        VaultWebRTC.on('video_change', function(data) { var b = document.getElementById('toggle-video-btn'); if (b) b.classList.toggle('active', data.videoOff); });
        VaultWebRTC.on('error', function(data) { showToast(data.message, 'error'); });
    }

    function handleCallStateChange(state, data) {
        var st = document.getElementById('call-status-text');
        switch (state) {
            case 'calling':
                showCallOverlay();
                if (st) st.textContent = 'Calling...';
                playRingtone();
                break;
            case 'ringing':
                showIncomingCallModal(data);
                playRingtone();
                break;
            case 'connecting':
                hideIncomingCallModal();
                showCallOverlay();
                stopRingtone();
                _webrtcCallStartTime = Date.now();
                if (st) st.textContent = 'Connecting...';
                break;
            case 'connected':
                stopRingtone();
                if (st) st.textContent = 'Encrypted Call';
                startCallTimer();
                startQualityMonitor();
                showSwapHint();
                startControlsAutoHide();
                
                if (_webrtcCallStartTime) {
                    var callLatency = Date.now() - _webrtcCallStartTime;
                    _webrtcCallStartTime = null;
                    reportDiagnosticMetric('webrtc_latency', callLatency);
                }
                break;
            case 'idle':
                hideCallOverlay();
                hideIncomingCallModal();
                stopCallTimer();
                stopRingtone();
                stopQualityMonitor();
                stopControlsAutoHide();
                break;
        }
    }

    function showCallOverlay() {
        var o = document.getElementById('call-overlay');
        if (o) { o.classList.add('active'); o.classList.remove('controls-hidden'); }
        _videosSwapped = false;
        var vids = document.getElementById('call-videos');
        if (vids) vids.classList.remove('swapped');
    }

    function hideCallOverlay() {
        var o = document.getElementById('call-overlay');
        if (o) { o.classList.remove('active'); o.classList.remove('controls-hidden'); }
        var lv = document.getElementById('local-video');
        var rv = document.getElementById('remote-video');
        if (lv) lv.srcObject = null;
        if (rv) rv.srcObject = null;
        _videosSwapped = false;
        var vids = document.getElementById('call-videos');
        if (vids) vids.classList.remove('swapped');
        stopControlsAutoHide();
    }

    function showIncomingCallModal() {
        var m = document.getElementById('incoming-call-modal');
        var cn = document.getElementById('caller-name');
        if (m) m.classList.add('active');
        if (cn && _peer) cn.textContent = _peer.username + ' is calling...';
    }
    function hideIncomingCallModal() { var m = document.getElementById('incoming-call-modal'); if (m) m.classList.remove('active'); }
    function enableVideoCallButton(enabled) { var b = document.getElementById('video-call-btn'); if (b) b.disabled = !enabled || !_peer || !VaultCrypto.isReady(); }

    function startCallTimer() {
        _callStartTime = Date.now();
        var t = document.getElementById('call-timer');
        _callTimerInterval = setInterval(function() {
            if (!_callStartTime || !t) return;
            var e = Math.floor((Date.now() - _callStartTime) / 1000);
            t.textContent = Math.floor(e/60).toString().padStart(2,'0') + ':' + (e%60).toString().padStart(2,'0');
        }, 1000);
    }
    function stopCallTimer() { if (_callTimerInterval) { clearInterval(_callTimerInterval); _callTimerInterval = null; } _callStartTime = null; var t = document.getElementById('call-timer'); if (t) t.textContent = ''; }

    // ── Flip Camera (front/back & multi-device webcam cycling) ──
    async function flipCamera() {
        var stream = VaultWebRTC.getLocalStream();
        if (!stream) return;
        var videoTracks = stream.getVideoTracks();
        if (videoTracks.length === 0) { showToast('No camera available', 'error'); return; }

        try {
            var devices = await navigator.mediaDevices.enumerateDevices();
            var videoDevices = devices.filter(function(d) { return d.kind === 'videoinput'; });
            
            if (videoDevices.length <= 1) {
                // If only 1 camera, try toggling facingMode as fallback without exact constraint
                var currentTrack = videoTracks[0];
                var settings = currentTrack.getSettings();
                var currentFacing = settings.facingMode || 'user';
                var newFacing = (currentFacing === 'user') ? 'environment' : 'user';
                
                var constraints = {
                    video: { facingMode: newFacing },
                    audio: false
                };
                
                var newStream = await navigator.mediaDevices.getUserMedia(constraints);
                var newTrack = newStream.getVideoTracks()[0];
                if (newTrack) {
                    await replaceLocalVideoTrack(newTrack);
                    showToast(newFacing === 'user' ? 'Front camera' : 'Rear camera', 'info');
                }
                resetControlsAutoHide();
                return;
            }
            
            // If multiple cameras, find the current one and switch to the next one!
            var currentTrack = videoTracks[0];
            var currentLabel = currentTrack.label;
            var currentIndex = videoDevices.findIndex(function(d) { return d.label === currentLabel; });
            var nextIndex = (currentIndex + 1) % videoDevices.length;
            var nextDevice = videoDevices[nextIndex];
            
            var constraints = {
                video: { deviceId: { exact: nextDevice.deviceId } },
                audio: false
            };
            
            var newStream = await navigator.mediaDevices.getUserMedia(constraints);
            var newTrack = newStream.getVideoTracks()[0];
            if (newTrack) {
                await replaceLocalVideoTrack(newTrack);
                showToast('Camera: ' + (nextDevice.label || ('Camera ' + (nextIndex + 1))), 'info');
            }
        } catch (err) {
            console.warn('Camera switch failed, trying facingMode fallback:', err);
            // Fallback to simple facingMode toggle without exact constraints
            try {
                var currentTrack = videoTracks[0];
                var settings = currentTrack.getSettings();
                var currentFacing = settings.facingMode || 'user';
                var newFacing = (currentFacing === 'user') ? 'environment' : 'user';
                var newStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: newFacing }, audio: false });
                var newTrack = newStream.getVideoTracks()[0];
                if (newTrack) {
                    await replaceLocalVideoTrack(newTrack);
                    showToast(newFacing === 'user' ? 'Front camera' : 'Rear camera', 'info');
                }
            } catch (fallbackErr) {
                console.error('All camera flip methods failed:', fallbackErr);
                showToast('Could not switch camera', 'error');
            }
        }
        resetControlsAutoHide();
    }

    async function replaceLocalVideoTrack(newTrack) {
        var stream = VaultWebRTC.getLocalStream();
        if (!stream) return;
        var videoTracks = stream.getVideoTracks();
        
        // Stop old track
        if (videoTracks[0]) {
            videoTracks[0].stop();
            stream.removeTrack(videoTracks[0]);
        }
        
        // Add new track to local stream
        stream.addTrack(newTrack);
        
        // Replace in WebRTC peer connection
        var pc = VaultWebRTC.getPeerConnection && VaultWebRTC.getPeerConnection();
        if (pc) {
            var sender = pc.getSenders().find(function(s) { return s.track && s.track.kind === 'video'; });
            if (sender) {
                await sender.replaceTrack(newTrack);
            }
        }
        
        // Re-bind to local video element and play
        var lv = document.getElementById('local-video');
        if (lv) {
            lv.srcObject = null;
            lv.srcObject = stream;
            try { await lv.play(); } catch(e) {}
        }
    }

    async function sendMissedCallMessage() {
        if (!VaultCrypto.isReady() || !_peer) return;
        try {
            var text = '🎬 Missed video call';
            var encrypted = await VaultCrypto.encrypt(text);
            var messageId = generateId();
            var timestamp = new Date().toISOString();
            VaultSocket.send({ type: 'message', id: messageId, encryptedContent: encrypted.ciphertext, iv: encrypted.iv, receiverId: _peer.id });
            addMessageToUI({ id: messageId, text: text, sent: true, timestamp: timestamp, status: 'sending' });
            await VaultLocalStorage.saveMessage({ id: messageId, peerId: _peer.id, text: text, sent: true, timestamp: timestamp, status: 'sending' });
        } catch (err) {
            console.error('Failed to send missed call message:', err);
        }
    }

    async function clearChatHistory() {
        if (!_peer) return;
        if (!confirm('Are you sure you want to clear your chat history with ' + _peer.username + '? This action only deletes messages locally on this device and cannot be undone.')) return;

        try {
            await VaultLocalStorage.clearMessagesForPeer(_peer.id);
            clearChatMessages();
            showToast('Chat history cleared', 'info');
        } catch (err) {
            console.error('Failed to clear chat history:', err);
            showToast('Failed to clear history', 'error');
        }
    }

    async function rotateEncryptionKeys(confirmRequired = true) {
        if (confirmRequired && !confirm('Are you sure you want to rotate your E2E encryption keys? This will generate a new cryptographic identity keypair and re-establish a secure E2E channel.')) return;

        try {
            updateEncryptionStatus('waiting');
            if (_peer) {
                enableMessageInput(false);
                enableVideoCallButton(false);
            }
            
            // 1. Force generate new key pair
            await VaultCrypto.generateKeyPair(true);
            
            // 2. Export and send key exchange message to server
            var publicKey = await VaultCrypto.exportPublicKey();
            var fingerprint = await VaultCrypto.getFingerprint(publicKey);
            
            // Inform server / peers about the key rotation session ID
            VaultSocket.send({
                type: 'key_exchange',
                publicKey: publicKey,
                fingerprint: fingerprint,
                sessionId: VaultCrypto.getSessionId(),
                peerId: _peer ? _peer.id : null
            });
            
            updateFingerprint('own', fingerprint);
            showToast('E2E identity keys rotated successfully', 'success');
            
            // Hide the warning banner if visible
            var banner = document.getElementById('key-rotation-alert-banner');
            if (banner) banner.style.display = 'none';
            
            // 3. If there is a peer selected, request peer's key to re-derive the shared key
            if (_peer) {
                VaultSocket.send({ type: 'get_peer_key', peerId: _peer.id });
            }
        } catch (err) {
            console.error('Key rotation failed:', err);
            showToast('Failed to rotate keys', 'error');
            updateEncryptionStatus('error');
        }
    }

    // ── Swap Videos (PiP ↔ Fullscreen) ──
    function swapVideos() {
        _videosSwapped = !_videosSwapped;
        var vids = document.getElementById('call-videos');
        if (vids) vids.classList.toggle('swapped', _videosSwapped);
        resetControlsAutoHide();
    }

    // ── Swap Hint (shown briefly when call connects) ──
    function showSwapHint() {
        var hint = document.getElementById('swap-hint');
        if (!hint) return;
        hint.classList.add('visible');
        setTimeout(function() { hint.classList.remove('visible'); }, 3000);
    }

    // ── Auto-hide Controls ──
    function startControlsAutoHide() {
        var overlay = document.getElementById('call-overlay');
        if (!overlay) return;
        // Show controls on touch/mouse move
        overlay.addEventListener('touchstart', resetControlsAutoHide, { passive: true });
        overlay.addEventListener('mousemove', resetControlsAutoHide);
        overlay.addEventListener('click', toggleControlsVisibility);
        resetControlsAutoHide();
    }
    function stopControlsAutoHide() {
        if (_controlsHideTimer) { clearTimeout(_controlsHideTimer); _controlsHideTimer = null; }
        var overlay = document.getElementById('call-overlay');
        if (overlay) {
            overlay.removeEventListener('touchstart', resetControlsAutoHide);
            overlay.removeEventListener('mousemove', resetControlsAutoHide);
            overlay.removeEventListener('click', toggleControlsVisibility);
            overlay.classList.remove('controls-hidden');
        }
    }
    function resetControlsAutoHide() {
        var overlay = document.getElementById('call-overlay');
        if (!overlay) return;
        overlay.classList.remove('controls-hidden');
        if (_controlsHideTimer) clearTimeout(_controlsHideTimer);
        _controlsHideTimer = setTimeout(function() {
            if (VaultWebRTC.getCallState() === 'connected') {
                overlay.classList.add('controls-hidden');
            }
        }, 5000);
    }
    function toggleControlsVisibility(e) {
        // Don't toggle if clicking on a button
        if (e.target.closest('.call-control-btn') || e.target.closest('.call-controls')) return;
        var overlay = document.getElementById('call-overlay');
        if (!overlay) return;
        if (overlay.classList.contains('controls-hidden')) {
            resetControlsAutoHide();
        }
    }

    // ── Connection Quality Monitor ──
    function startQualityMonitor() {
        stopQualityMonitor();
        _qualityInterval = setInterval(function() {
            var pc = VaultWebRTC.getPeerConnection && VaultWebRTC.getPeerConnection();
            if (!pc) return;
            pc.getStats(null).then(function(stats) {
                var quality = 'good';
                stats.forEach(function(report) {
                    if (report.type === 'candidate-pair' && report.state === 'succeeded') {
                        var rtt = report.currentRoundTripTime;
                        if (rtt !== undefined) {
                            if (rtt > 0.4) quality = 'poor';
                            else if (rtt > 0.15) quality = 'medium';
                        }
                    }
                    if (report.type === 'inbound-rtp' && report.kind === 'video') {
                        if (report.packetsLost > 50 && report.packetsReceived > 0) {
                            var lossRate = report.packetsLost / (report.packetsReceived + report.packetsLost);
                            if (lossRate > 0.1) quality = 'poor';
                            else if (lossRate > 0.03) quality = 'medium';
                        }
                    }
                });
                updateQualityIndicator(quality);
            }).catch(function() {});
        }, 3000);
    }
    function stopQualityMonitor() { if (_qualityInterval) { clearInterval(_qualityInterval); _qualityInterval = null; } }
    function updateQualityIndicator(quality) {
        var el = document.getElementById('call-quality');
        if (!el) return;
        el.className = 'call-quality ' + quality;
    }

    function playRingtone() { stopRingtone(); var c = 0; function ring() { try { var ctx = new (window.AudioContext || window.webkitAudioContext)(); [440, 523].forEach(function(f, i) { var o = ctx.createOscillator(); var g = ctx.createGain(); o.connect(g); g.connect(ctx.destination); o.frequency.value = f; o.type = 'sine'; g.gain.value = 0.08; o.start(ctx.currentTime + i * 0.15); g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + i * 0.15 + 0.4); o.stop(ctx.currentTime + i * 0.15 + 0.4); }); } catch(e){} c++; if (c > 30) stopRingtone(); } ring(); _ringtoneInterval = setInterval(ring, 1000); }
    function stopRingtone() { if (_ringtoneInterval) { clearInterval(_ringtoneInterval); _ringtoneInterval = null; } }

    // ═══════════════════════════════════════
    // UI Helpers
    // ═══════════════════════════════════════

    function showAuthView() { 
        document.getElementById('auth-view').classList.add('active'); 
        document.getElementById('chat-view').classList.remove('active'); 
        var adminView = document.getElementById('admin-view');
        if (adminView) adminView.classList.remove('active');
        document.title = 'Talk-Secure - Login'; 
    }
    function showChatView() { 
        document.getElementById('auth-view').classList.remove('active'); 
        document.getElementById('chat-view').classList.add('active'); 
        var adminView = document.getElementById('admin-view');
        if (adminView) adminView.classList.remove('active');
        document.title = 'Talk-Secure - Encrypted'; 
    }
    function showAuthError(msg) { var e = document.getElementById('auth-error'); if (e) { e.textContent = msg; e.classList.add('visible'); setTimeout(function() { e.classList.remove('visible'); }, 5000); } }
    function showAuthSuccess(msg) { var e = document.getElementById('auth-success'); if (e) { e.textContent = msg; e.classList.add('visible'); setTimeout(function() { e.classList.remove('visible'); }, 5000); } }
    function setAuthLoading(loading) { document.querySelectorAll('.auth-form button[type="submit"]').forEach(function(btn) { btn.disabled = loading; if (loading) { btn.dataset.originalText = btn.textContent; btn.textContent = 'Please wait...'; } else { btn.textContent = btn.dataset.originalText || btn.textContent; } }); }
    function switchToLogin() { document.getElementById('login-tab').click(); }
    function updateUserDisplay() { var e = document.getElementById('current-user'); if (e) e.textContent = _username; }
    function updatePeerDisplay() { var n = document.getElementById('peer-name'); var s = document.getElementById('peer-status'); if (_peer) { if (n) n.textContent = _peer.username; if (s) { s.textContent = _peer.online ? 'Online' : 'Offline'; s.className = 'peer-status ' + (_peer.online ? 'online' : 'offline'); } } }
    function updateConnectionStatus(status) { var el = document.getElementById('connection-status'); if (!el) return; var states = { connecting: { text: 'Connecting...', class: 'connecting' }, connected: { text: 'Connected', class: 'connected' }, disconnected: { text: 'Disconnected', class: 'disconnected' }, reconnecting: { text: 'Reconnecting...', class: 'reconnecting' } }; var st = states[status] || states.disconnected; el.textContent = st.text; el.className = 'connection-status ' + st.class; }
    function updateEncryptionStatus(status) {
        var el = document.getElementById('encryption-status');
        if (!el) return;
        var states = {
            active: { text: '\ud83d\udd12 E2E Encrypted (Device-Only)', class: 'active' },
            waiting: { text: '\u231b Waiting for peer key...', class: 'waiting' },
            error: { text: '\u26a0 Encryption Error', class: 'error' }
        };
        var st = states[status] || states.waiting;
        el.textContent = st.text;
        el.className = 'encryption-status ' + st.class;
    }
    function updateFingerprint(type, fp) { var el = document.getElementById(type + '-fingerprint'); if (el) el.textContent = fp || 'Not available'; }
    function enableMessageInput(enabled) {
        var inp = document.getElementById('message-input');
        var btn = document.getElementById('send-btn');
        var att = document.getElementById('attachment-btn');
        var menuBtn = document.getElementById('chat-menu-btn');
        var searchBtn = document.getElementById('chat-search-btn');
        var voiceBtn = document.getElementById('voice-record-btn');
        
        if (inp) {
            inp.disabled = !enabled;
            inp.placeholder = enabled ? 'Type a message...' : (_peer ? 'Waiting for encryption...' : 'Select a contact...');
            if (!enabled) {
                inp.value = '';
                inp.style.height = 'auto';
            }
        }
        if (btn) {
            btn.disabled = !enabled;
            btn.style.display = (enabled && inp && inp.value.trim().length > 0) ? 'flex' : 'none';
        }
        if (voiceBtn) {
            voiceBtn.disabled = !enabled;
            voiceBtn.style.display = (enabled && inp && inp.value.trim().length > 0) ? 'none' : 'flex';
        }
        if (att) att.disabled = !enabled;
        if (menuBtn) menuBtn.disabled = !_peer;
        if (searchBtn) searchBtn.disabled = !_peer;
    }

    function addMessageToUI(opts) {
        var id = opts.id, text = opts.text, sent = opts.sent, timestamp = opts.timestamp, status = opts.status, error = opts.error;
        var chatMessages = document.getElementById('chat-messages');
        if (!chatMessages) return;
        var msgDiv = document.createElement('div');
        msgDiv.className = 'message ' + (sent ? 'sent' : 'received') + (error ? ' error' : '');
        msgDiv.dataset.msgId = id;

        // Parse UTC timestamp robustly (handling SQLite space format)
        var parsedTimestamp = timestamp;
        if (typeof timestamp === 'string') {
            if (!timestamp.includes('T')) {
                parsedTimestamp = timestamp.replace(' ', 'T') + 'Z';
            } else if (!timestamp.endsWith('Z') && !timestamp.includes('+') && !timestamp.includes('-')) {
                parsedTimestamp = timestamp + 'Z';
            }
        }
        var time = new Date(parsedTimestamp);
        var timeStr = time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        var statusIcon = '';
        if (sent) {
            if (status === 'read') statusIcon = '<span class="msg-status read" title="Read">\u2713\u2713</span>';
            else if (status === 'delivered') statusIcon = '<span class="msg-status" title="Delivered">\u2713</span>';
            else statusIcon = '<span class="msg-status" title="Sending">\u25cb</span>';
        }

        // Check for file attachment or voice note JSON
        var isFile = false, isVoice = false, fileData = null, htmlContent = '';
        try {
            var parsed = JSON.parse(text);
            if (parsed) {
                if (parsed.type === 'file_attachment') {
                    isFile = true;
                    fileData = parsed;
                } else if (parsed.type === 'voice_note') {
                    isVoice = true;
                    fileData = parsed;
                }
            }
        } catch(e) {}

        if (isFile) {
            var sizeStr = (fileData.fileSize / (1024 * 1024)).toFixed(2) + ' MB';
            var isImage = fileData.fileType.startsWith('image/');
            var isVideo = fileData.fileType.startsWith('video/');
            var previewHtml = '';

            if (isImage) {
                previewHtml = '<img class="msg-image" style="display:none"><button class="btn btn-primary btn-sm fetch-file-btn">Loading (' + sizeStr + ')</button>';
            } else if (isVideo) {
                previewHtml = '<video class="msg-video" style="display:none" controls></video><button class="btn btn-primary btn-sm fetch-file-btn">Loading (' + sizeStr + ')</button>';
            } else {
                previewHtml = '<div class="msg-document"><div class="doc-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="24" height="24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg></div><div class="doc-info"><div class="doc-name">' + escapeHtml(fileData.fileName) + '</div><div class="doc-size">' + sizeStr + '</div></div><button class="doc-download-btn fetch-file-btn">Loading...</button></div>';
            }
            htmlContent = '<div class="msg-file-container">' + previewHtml + '</div>';
        } else if (isVoice) {
            htmlContent = '<div class="msg-voice-container">' +
                '<button class="voice-play-btn" disabled>' +
                    '<svg viewBox="0 0 24 24" fill="currentColor" width="14" height="14" class="play-icon"><path d="M8 5v14l11-7z"/></svg>' +
                    '<svg viewBox="0 0 24 24" fill="currentColor" width="14" height="14" class="pause-icon" style="display: none;"><path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/></svg>' +
                '</button>' +
                '<div class="voice-progress-container">' +
                    '<div class="voice-progress-bar"></div>' +
                '</div>' +
                '<span class="voice-duration">...</span>' +
            '</div>';
        } else {
            if (opts.highlightQuery) {
                var escaped = escapeHtml(text);
                var safeQuery = opts.highlightQuery.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
                var regex = new RegExp('(' + safeQuery + ')', 'gi');
                var highlighted = escaped.replace(regex, '<mark class="search-highlight">$1</mark>');
                htmlContent = '<div class="msg-text">' + highlighted + '</div>';
            } else {
                htmlContent = '<div class="msg-text">' + escapeHtml(text) + '</div>';
            }
        }

        msgDiv.innerHTML = '<div class="msg-bubble">' + htmlContent + '<div class="msg-meta"><span class="msg-time">' + timeStr + '</span>' + statusIcon + '</div></div>';
        chatMessages.appendChild(msgDiv);

        // If file has inline data, auto-decrypt and render
        if (isFile && fileData.fileData) {
            (function(div, fd, img, vid) {
                try {
                    var decryptedBuffer = VaultCrypto.base64ToArrayBuffer(fd.fileData);
                    VaultCrypto.decryptFileBuffer(decryptedBuffer, fd.fileIv).then(function(plainBuf) {
                        var blob = new Blob([plainBuf], { type: fd.fileType });
                        var url = URL.createObjectURL(blob);
                        var mediaEl = div.querySelector('img, video');
                        var btnEl = div.querySelector('.fetch-file-btn');
                        if (img && mediaEl) { mediaEl.src = url; mediaEl.style.display = 'block'; if (btnEl) btnEl.style.display = 'none'; }
                        else if (vid && mediaEl) { mediaEl.src = url; mediaEl.style.display = 'block'; if (btnEl) btnEl.style.display = 'none'; }
                        else {
                            if (btnEl) {
                                btnEl.textContent = '\u2b07 Download';
                                btnEl.addEventListener('click', function() { var a = document.createElement('a'); a.href = url; a.download = fd.fileName; a.click(); });
                            }
                        }
                    }).catch(function(err) {
                        console.error('Auto-decrypt failed:', err);
                        var btn = div.querySelector('.fetch-file-btn');
                        if (btn) btn.textContent = 'Decrypt failed';
                    });
                } catch(decErr) { console.error('Base64 decode error:', decErr); }
            })(msgDiv, fileData, isImage, isVideo);
        } else if (isVoice && fileData.fileData) {
            (function(div, fd) {
                try {
                    var decryptedBuffer = VaultCrypto.base64ToArrayBuffer(fd.fileData);
                    VaultCrypto.decryptFileBuffer(decryptedBuffer, fd.fileIv).then(function(plainBuf) {
                        var blob = new Blob([plainBuf], { type: 'audio/webm' });
                        var url = URL.createObjectURL(blob);
                        
                        var audio = new Audio(url);
                        var playBtn = div.querySelector('.voice-play-btn');
                        var playIcon = playBtn.querySelector('.play-icon');
                        var pauseIcon = playBtn.querySelector('.pause-icon');
                        var progressBar = div.querySelector('.voice-progress-bar');
                        var progressContainer = div.querySelector('.voice-progress-container');
                        var durationSpan = div.querySelector('.voice-duration');
                        
                        playBtn.removeAttribute('disabled');
                        
                        audio.addEventListener('loadedmetadata', function() {
                            durationSpan.textContent = formatDuration(audio.duration);
                        });
                        
                        if (audio.duration && !isNaN(audio.duration)) {
                            durationSpan.textContent = formatDuration(audio.duration);
                        } else {
                            durationSpan.textContent = '0:00';
                        }
                        
                        playBtn.addEventListener('click', function() {
                            if (audio.paused) {
                                document.querySelectorAll('audio').forEach(function(a) {
                                    if (a !== audio) a.pause();
                                });
                                audio.play();
                            } else {
                                audio.pause();
                            }
                        });
                        
                        audio.addEventListener('play', function() {
                            playIcon.style.display = 'none';
                            pauseIcon.style.display = 'block';
                        });
                        
                        audio.addEventListener('pause', function() {
                            playIcon.style.display = 'block';
                            pauseIcon.style.display = 'none';
                        });
                        
                        audio.addEventListener('timeupdate', function() {
                            var pct = (audio.currentTime / audio.duration) * 100;
                            progressBar.style.width = pct + '%';
                            durationSpan.textContent = formatDuration(audio.currentTime);
                        });
                        
                        audio.addEventListener('ended', function() {
                            playIcon.style.display = 'block';
                            pauseIcon.style.display = 'none';
                            progressBar.style.width = '0%';
                            durationSpan.textContent = formatDuration(audio.duration);
                        });
                        
                        progressContainer.addEventListener('click', function(e) {
                            var rect = progressContainer.getBoundingClientRect();
                            var clickX = e.clientX - rect.left;
                            var width = rect.width;
                            var pct = clickX / width;
                            if (audio.duration && !isNaN(audio.duration)) {
                                audio.currentTime = pct * audio.duration;
                            }
                        });
                    }).catch(function(err) {
                        console.error('Voice note decrypt failed:', err);
                        var durationSpan = div.querySelector('.voice-duration');
                        if (durationSpan) durationSpan.textContent = 'Decrypt failed';
                    });
                } catch(decErr) { console.error('Voice note base64 decode error:', decErr); }
            })(msgDiv, fileData);
        }
    }

    function scrollToBottom() { var c = document.getElementById('chat-messages'); if (c) requestAnimationFrame(function() { c.scrollTop = c.scrollHeight; }); }
    function showToast(message, type) { type = type || 'info'; var c = document.getElementById('toast-container'); if (!c) return; var t = document.createElement('div'); t.className = 'toast ' + type; t.textContent = message; c.appendChild(t); setTimeout(function() { t.classList.add('visible'); }, 10); setTimeout(function() { t.classList.remove('visible'); setTimeout(function() { t.remove(); }, 300); }, 4000); }
    function playNotificationSound() { try { var ctx = new (window.AudioContext || window.webkitAudioContext)(); var o = ctx.createOscillator(); var g = ctx.createGain(); o.connect(g); g.connect(ctx.destination); o.frequency.value = 800; o.type = 'sine'; g.gain.value = 0.1; o.start(); g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3); o.stop(ctx.currentTime + 0.3); } catch(e) {} }

    // ═══════════════════════════════════════
    // Event Listeners
    // ═══════════════════════════════════════

    function setupEventListeners() {
        var loginForm = document.getElementById('login-form');
        var registerForm = document.getElementById('register-form');
        if (loginForm) loginForm.addEventListener('submit', handleLogin);
        if (registerForm) registerForm.addEventListener('submit', handleRegister);
        var otpForm = document.getElementById('otp-form');
        if (otpForm) otpForm.addEventListener('submit', handleOtpSubmit);
        var otpCancelBtn = document.getElementById('otp-cancel-btn');
        if (otpCancelBtn) otpCancelBtn.addEventListener('click', handleOtpCancel);
        var loginTab = document.getElementById('login-tab');
        var registerTab = document.getElementById('register-tab');
        if (loginTab) loginTab.addEventListener('click', function() { loginTab.classList.add('active'); registerTab.classList.remove('active'); document.getElementById('login-form').classList.add('active'); document.getElementById('register-form').classList.remove('active'); });
        if (registerTab) registerTab.addEventListener('click', function() { registerTab.classList.add('active'); loginTab.classList.remove('active'); document.getElementById('register-form').classList.add('active'); document.getElementById('login-form').classList.remove('active'); });
        var msgInput = document.getElementById('message-input');
        var sendBtn = document.getElementById('send-btn');
        if (msgInput) {
            msgInput.addEventListener('keydown', function(e) { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } });
            msgInput.addEventListener('input', function() {
                handleTypingInput();
                msgInput.style.height = 'auto';
                msgInput.style.height = Math.min(msgInput.scrollHeight, 120) + 'px';
                
                var val = msgInput.value.trim();
                var voiceBtn = document.getElementById('voice-record-btn');
                var sBtn = document.getElementById('send-btn');
                if (val.length > 0) {
                    if (sBtn) sBtn.style.display = 'flex';
                    if (voiceBtn) voiceBtn.style.display = 'none';
                } else {
                    if (sBtn) sBtn.style.display = 'none';
                    if (voiceBtn) voiceBtn.style.display = 'flex';
                }
            });
        }
        if (sendBtn) sendBtn.addEventListener('click', function() { sendMessage(); });
        
        // Voice recording button
        var voiceRecordBtn = document.getElementById('voice-record-btn');
        if (voiceRecordBtn) {
            voiceRecordBtn.addEventListener('click', toggleVoiceRecording);
        }



        // Search engine toggle and filtering triggers
        var searchBtn = document.getElementById('chat-search-btn');
        var searchBar = document.getElementById('chat-search-bar');
        var searchInput = document.getElementById('chat-search-input');
        if (searchBtn && searchBar) {
            searchBtn.addEventListener('click', function() {
                searchBar.classList.add('active');
                if (searchInput) {
                    searchInput.focus();
                }
            });
        }
        var searchClose = document.getElementById('chat-search-close');
        if (searchClose && searchBar && searchInput) {
            searchClose.addEventListener('click', function() {
                searchBar.classList.remove('active');
                searchInput.value = '';
                if (_peer) {
                    loadLocalHistory(_peer.id);
                }
            });
        }
        if (searchInput) {
            searchInput.addEventListener('input', function() {
                filterChatMessages(searchInput.value);
            });
        }

        var attachmentBtn = document.getElementById('attachment-btn');
        var fileInput = document.getElementById('file-attachment-input');
        if (attachmentBtn && fileInput) { attachmentBtn.addEventListener('click', function() { fileInput.click(); }); fileInput.addEventListener('change', handleFileAttachment); }
        var logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);
        
        // Chat Options Dropdown Menu
        var chatMenuBtn = document.getElementById('chat-menu-btn');
        var chatMenuContent = document.getElementById('chat-menu-content');
        if (chatMenuBtn && chatMenuContent) {
            chatMenuBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                chatMenuContent.classList.toggle('show');
            });
            document.addEventListener('click', function() {
                chatMenuContent.classList.remove('show');
            });
        }
        var menuClearHistory = document.getElementById('menu-clear-history');
        if (menuClearHistory) menuClearHistory.addEventListener('click', clearChatHistory);
        var menuRotateKeys = document.getElementById('menu-rotate-keys');
        if (menuRotateKeys) menuRotateKeys.addEventListener('click', rotateEncryptionKeys);

        // Key rotation warning banner events
        var bannerRotateBtn = document.getElementById('banner-rotate-keys-btn');
        if (bannerRotateBtn) {
            bannerRotateBtn.addEventListener('click', function() {
                rotateEncryptionKeys(true);
            });
        }
        var bannerCloseBtn = document.getElementById('banner-close-btn');
        if (bannerCloseBtn) {
            bannerCloseBtn.addEventListener('click', function() {
                var banner = document.getElementById('key-rotation-alert-banner');
                if (banner) banner.style.display = 'none';
            });
        }
        var menuToggleSecurity = document.getElementById('menu-toggle-security');
        var secPanel = document.getElementById('security-panel');
        if (menuToggleSecurity && secPanel) {
            menuToggleSecurity.addEventListener('click', function() {
                secPanel.classList.toggle('visible');
            });
        }

        var sidebarToggle = document.getElementById('sidebar-toggle');
        var sidebar = document.getElementById('contacts-sidebar');
        var sidebarOverlay = document.getElementById('sidebar-overlay');
        if (sidebarToggle && sidebar) sidebarToggle.addEventListener('click', function() { sidebar.classList.toggle('open'); if (sidebarOverlay) sidebarOverlay.classList.toggle('active'); });
        if (sidebarOverlay) sidebarOverlay.addEventListener('click', function() { if (sidebar) sidebar.classList.remove('open'); sidebarOverlay.classList.remove('active'); });
        var closeSidebarBtn = document.getElementById('close-sidebar-btn');
        if (closeSidebarBtn) closeSidebarBtn.addEventListener('click', function() { if (sidebar) sidebar.classList.remove('open'); if (sidebarOverlay) sidebarOverlay.classList.remove('active'); });
        var videoCallBtn = document.getElementById('video-call-btn');
        if (videoCallBtn) videoCallBtn.addEventListener('click', function() { console.log('📞 Start video call clicked'); if (VaultWebRTC.getCallState() === 'idle') VaultWebRTC.startCall(); });
        var endCallBtn = document.getElementById('end-call-btn');
        if (endCallBtn) endCallBtn.addEventListener('click', function() { console.log('☎️ End call clicked'); VaultWebRTC.endCall(); if (_peer) VaultSocket.send({ type: 'call_end', receiverId: _peer.id }); });
        var toggleMuteBtn = document.getElementById('toggle-mute-btn');
        if (toggleMuteBtn) toggleMuteBtn.addEventListener('click', function() { console.log('🎤 Toggle mute clicked'); VaultWebRTC.toggleMute(); });
        var toggleVideoBtn = document.getElementById('toggle-video-btn');
        if (toggleVideoBtn) toggleVideoBtn.addEventListener('click', function() { console.log('📹 Toggle video clicked'); VaultWebRTC.toggleVideo(); });
        var acceptCallBtn = document.getElementById('accept-call-btn');
        if (acceptCallBtn) acceptCallBtn.addEventListener('click', function() { console.log('✅ Accept call clicked'); VaultWebRTC.acceptCall(); });
        var rejectCallBtn = document.getElementById('reject-call-btn');
        if (rejectCallBtn) rejectCallBtn.addEventListener('click', function() { console.log('❌ Reject call clicked'); VaultWebRTC.rejectCall(); });
        var flipCameraBtn = document.getElementById('flip-camera-btn');
        if (flipCameraBtn) flipCameraBtn.addEventListener('click', function() { console.log('📸 Flip camera clicked'); flipCamera(); });
        var swapVideoBtn = document.getElementById('swap-video-btn');
        if (swapVideoBtn) swapVideoBtn.addEventListener('click', function() { console.log('🔄 Swap video clicked'); swapVideos(); });
        document.addEventListener('visibilitychange', function() { if (!document.hidden) document.title = 'Talk-Secure - Encrypted'; });

        // Star ratings click handler in feedback modal
        document.querySelectorAll('.feedback-rating .star').forEach(function(star) {
            star.addEventListener('click', function() {
                var rating = parseInt(star.dataset.rating, 10);
                document.getElementById('feedback-rating-val').value = rating;
                
                // Update active state of star elements visually
                document.querySelectorAll('.feedback-rating .star').forEach(function(s) {
                    var r = parseInt(s.dataset.rating, 10);
                    s.classList.toggle('active', r <= rating);
                });
            });
        });

        // Feedback modal triggers
        var menuSubmitFeedback = document.getElementById('menu-submit-feedback');
        if (menuSubmitFeedback) {
            menuSubmitFeedback.addEventListener('click', function() {
                var modal = document.getElementById('feedback-modal');
                if (modal) {
                    modal.classList.add('active');
                    document.getElementById('feedback-message').value = '';
                    document.getElementById('feedback-rating-val').value = '5';
                    document.querySelectorAll('.feedback-rating .star').forEach(function(s) {
                        s.classList.add('active');
                    });
                }
            });
        }
        var feedbackModalClose = document.getElementById('feedback-modal-close');
        if (feedbackModalClose) {
            feedbackModalClose.addEventListener('click', function() {
                var modal = document.getElementById('feedback-modal');
                if (modal) modal.classList.remove('active');
            });
        }

        // Feedback form submit handler
        var feedbackForm = document.getElementById('feedback-form');
        if (feedbackForm) {
            feedbackForm.addEventListener('submit', async function(e) {
                e.preventDefault();
                var message = document.getElementById('feedback-message').value.trim();
                var rating = parseInt(document.getElementById('feedback-rating-val').value, 10);
                
                try {
                    const res = await fetch('/api/feedback', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + _token
                        },
                        body: JSON.stringify({ message, rating })
                    });
                    const data = await res.json();
                    if (data.success) {
                        showToast('Feedback submitted! Thank you.', 'success');
                        var modal = document.getElementById('feedback-modal');
                        if (modal) modal.classList.remove('active');
                    } else {
                        showToast(data.message || 'Failed to submit feedback', 'error');
                    }
                } catch (err) {
                    console.error('Feedback failed:', err);
                    showToast('Connection error. Failed to submit feedback.', 'error');
                }
            });
        }

        // Add contact modal triggers
        var addContactBtn = document.getElementById('add-contact-btn');
        if (addContactBtn) {
            addContactBtn.addEventListener('click', function() {
                var modal = document.getElementById('add-contact-modal');
                if (modal) {
                    modal.classList.add('active');
                    var input = document.getElementById('contact-search-input');
                    if (input) {
                        input.value = '';
                        input.focus();
                    }
                    var results = document.getElementById('contact-search-results');
                    if (results) {
                        results.innerHTML = '<div class="results-empty">Type to start searching...</div>';
                    }
                }
            });
        }
        var addContactModalClose = document.getElementById('add-contact-modal-close');
        if (addContactModalClose) {
            addContactModalClose.addEventListener('click', function() {
                var modal = document.getElementById('add-contact-modal');
                if (modal) modal.classList.remove('active');
            });
        }

        // Contact search input handler
        var contactSearchInput = document.getElementById('contact-search-input');
        if (contactSearchInput) {
            contactSearchInput.addEventListener('input', function() {
                var query = contactSearchInput.value.trim();
                searchContacts(query);
            });
        }

        // Admin Dashboard dropdown menu trigger
        var menuAdminDashboard = document.getElementById('menu-admin-dashboard');
        if (menuAdminDashboard) {
            menuAdminDashboard.addEventListener('click', function() {
                showAdminView();
            });
        }

        // Admin back and refresh button triggers
        var adminBackBtn = document.getElementById('admin-back-btn');
        if (adminBackBtn) {
            adminBackBtn.addEventListener('click', function() {
                showChatView();
            });
        }
        var adminRefreshBtn = document.getElementById('admin-refresh-btn');
        if (adminRefreshBtn) {
            adminRefreshBtn.addEventListener('click', function() {
                loadAdminData();
            });
        }

        // Admin tab switches
        document.querySelectorAll('.admin-tab').forEach(function(tab) {
            tab.addEventListener('click', function() {
                document.querySelectorAll('.admin-tab').forEach(function(t) { t.classList.remove('active'); });
                document.querySelectorAll('.admin-tab-content').forEach(function(c) { c.classList.remove('active'); });
                
                tab.classList.add('active');
                var targetId = tab.dataset.target;
                var content = document.getElementById(targetId);
                 if (content) content.classList.add('active');
            });
        });

        // Invite actions triggers
        var generateInviteBtn = document.getElementById('admin-generate-invite-btn');
        if (generateInviteBtn) {
            generateInviteBtn.addEventListener('click', generateInviteToken);
        }
        var copyInviteBtn = document.getElementById('admin-copy-invite-btn');
        if (copyInviteBtn) {
            copyInviteBtn.addEventListener('click', copyInviteLink);
        }
        var sendBroadcastBtn = document.getElementById('admin-send-broadcast-btn');
        if (sendBroadcastBtn) {
            sendBroadcastBtn.addEventListener('click', handleSendBroadcast);
        }
        
        var forceRotationAlertBtn = document.getElementById('btn-force-rotation-alert');
        if (forceRotationAlertBtn) {
            forceRotationAlertBtn.addEventListener('click', triggerForceGlobalKeyRotation);
        }

        // Support ticket modal triggers
        var contactSupportBtn = document.getElementById('menu-contact-support');
        if (contactSupportBtn) {
            contactSupportBtn.addEventListener('click', function() {
                var dropdown = document.getElementById('chat-menu-content');
                if (dropdown) dropdown.classList.remove('show');
                
                var modal = document.getElementById('support-ticket-modal');
                if (modal) modal.classList.add('active');
            });
        }
        var closeSupportModalBtn = document.getElementById('support-ticket-modal-close');
        if (closeSupportModalBtn) {
            closeSupportModalBtn.addEventListener('click', function() {
                var modal = document.getElementById('support-ticket-modal');
                if (modal) modal.classList.remove('active');
            });
        }
        var supportForm = document.getElementById('support-ticket-form');
        if (supportForm) {
            supportForm.addEventListener('submit', handleCreateSupportTicket);
        }
    }

    async function applyChatTheme(themeName) {
        document.body.classList.remove('theme-cyberpunk', 'theme-emerald', 'theme-ocean', 'theme-crimson', 'theme-default');
        if (themeName && themeName !== 'theme-default') {
            document.body.classList.add(themeName);
        }
        
        document.querySelectorAll('.theme-option').forEach(function(opt) {
            opt.classList.toggle('selected', opt.dataset.theme === themeName);
        });
        
        if (_peer) {
            await VaultKeyStore.saveChatTheme(_peer.id, themeName);
        }
    }

    async function filterChatMessages(query) {
        if (!_peer) return;
        query = query.trim().toLowerCase();
        
        var chatMessages = document.getElementById('chat-messages');
        if (!chatMessages) return;
        
        if (!query) {
            await loadLocalHistory(_peer.id);
            return;
        }
        
        chatMessages.innerHTML = '';
        try {
            var messages = await VaultLocalStorage.getMessages(_peer.id);
            var filtered = messages.filter(function(msg) {
                return msg.text && msg.text.toLowerCase().includes(query);
            });
            
            if (filtered.length === 0) {
                chatMessages.innerHTML = '<div class="empty-chat"><p class="muted">No matching messages found.</p></div>';
                return;
            }
            
            for (var i = 0; i < filtered.length; i++) {
                var isJson = false;
                try { JSON.parse(filtered[i].text); isJson = true; } catch(e) {}
                
                var opts = {
                    id: filtered[i].id,
                    text: filtered[i].text,
                    sent: filtered[i].sent,
                    timestamp: filtered[i].timestamp,
                    status: filtered[i].status || 'delivered',
                    highlightQuery: isJson ? null : query
                };
                addMessageToUI(opts);
            }
        } catch (err) {
            console.error('Failed to filter chat history:', err);
        }
    }

    async function toggleVoiceRecording() {
        var voiceRecordBtn = document.getElementById('voice-record-btn');
        var msgInput = document.getElementById('message-input');
        if (!voiceRecordBtn || !msgInput || !_peer || !VaultCrypto.isReady()) return;

        if (!_isRecording) {
            try {
                var stream = await navigator.mediaDevices.getUserMedia({ audio: true });
                _audioChunks = [];
                _mediaRecorder = new MediaRecorder(stream);
                _mediaRecorder.ondataavailable = function(e) {
                    if (e.data.size > 0) {
                        _audioChunks.push(e.data);
                    }
                };
                _mediaRecorder.onstop = async function() {
                    var audioBlob = new Blob(_audioChunks, { type: 'audio/webm' });
                    stream.getTracks().forEach(function(track) { track.stop(); });
                    await sendVoiceNote(audioBlob);
                };
                _mediaRecorder.start();
                _isRecording = true;
                voiceRecordBtn.classList.add('recording');
                msgInput.placeholder = 'Recording... Click mic to stop and send';
                msgInput.disabled = true;
                showToast('Voice recording started', 'success');
            } catch (err) {
                console.error('Microphone access error:', err);
                showToast('Could not access microphone', 'error');
            }
        } else {
            if (_mediaRecorder && _mediaRecorder.state !== 'inactive') {
                _mediaRecorder.stop();
            }
            _isRecording = false;
            voiceRecordBtn.classList.remove('recording');
            msgInput.disabled = false;
            msgInput.placeholder = 'Type a message...';
            msgInput.focus();
        }
    }

    async function sendVoiceNote(audioBlob) {
        if (!_peer || !VaultCrypto.isReady()) return;
        try {
            var buffer = await audioBlob.arrayBuffer();
            var encrypted = await VaultCrypto.encryptFileBuffer(buffer);
            
            var bytes = new Uint8Array(encrypted.ciphertext);
            var binary = '';
            for (var i = 0; i < bytes.length; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            var base64Data = btoa(binary);
            
            var voiceMsg = {
                type: 'voice_note',
                fileIv: encrypted.iv,
                fileData: base64Data
            };
            
            await sendMessage(JSON.stringify(voiceMsg));
        } catch (err) {
            console.error('Failed to encrypt/send voice note:', err);
            showToast('Failed to send voice note', 'error');
        }
    }

    function formatDuration(secs) {
        if (isNaN(secs) || secs === Infinity) return '0:00';
        var m = Math.floor(secs / 60);
        var s = Math.floor(secs % 60);
        return m + ':' + s.toString().padStart(2, '0');
    }

    function escapeHtml(text) {
        if (typeof text !== 'string') text = String(text);
        var d = document.createElement('div');
        d.textContent = text;
        return d.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    function generateId() { var b = new Uint8Array(16); window.crypto.getRandomValues(b); return Array.from(b).map(function(x) { return x.toString(16).padStart(2, '0'); }).join(''); }

    function isAdminUser() {
        return _isAdmin === true;
    }

    let _searchTimeout = null;
    async function searchContacts(query) {
        if (_searchTimeout) clearTimeout(_searchTimeout);
        var resultsContainer = document.getElementById('contact-search-results');
        if (!resultsContainer) return;

        if (!query || query.length < 2) {
            resultsContainer.innerHTML = '<div class="results-empty">Type at least 2 characters to search...</div>';
            return;
        }

        _searchTimeout = setTimeout(async function() {
            try {
                resultsContainer.innerHTML = '<div class="results-loading">Searching...</div>';
                const res = await fetch('/api/contacts/search', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + _token
                    },
                    body: JSON.stringify({ query: query })
                });
                const data = await res.json();
                if (data.success && data.results) {
                    if (data.results.length === 0) {
                        resultsContainer.innerHTML = '<div class="results-empty">No users found matching "' + escapeHtml(query) + '"</div>';
                        return;
                    }
                    var filtered = data.results.filter(function(r) {
                        return !_users.some(function(u) { return Number(u.id) === Number(r.id); });
                    });
                    
                    if (filtered.length === 0) {
                        resultsContainer.innerHTML = '<div class="results-empty">All matched users are already in your contacts.</div>';
                        return;
                    }

                    resultsContainer.innerHTML = filtered.map(function(u) {
                        return '<div class="search-result-item">' +
                            '<div class="search-result-info">' +
                                '<div class="search-result-name">' + escapeHtml(u.username) + '</div>' +
                                '<div class="search-result-meta">' + escapeHtml(u.phone || 'No phone') + ' | ' + escapeHtml(u.email || 'No email') + '</div>' +
                            '</div>' +
                            '<button class="btn btn-primary btn-sm add-user-btn" data-user-id="' + u.id + '">+ Add</button>' +
                        '</div>';
                    }).join('');

                    resultsContainer.querySelectorAll('.add-user-btn').forEach(function(btn) {
                        btn.addEventListener('click', async function() {
                            var uid = parseInt(btn.dataset.userId, 10);
                            await addContactUser(uid);
                        });
                    });
                } else {
                    resultsContainer.innerHTML = '<div class="results-error">Error: ' + escapeHtml(data.message) + '</div>';
                }
            } catch (err) {
                console.error('Search failed:', err);
                resultsContainer.innerHTML = '<div class="results-error">Failed to connect to search server.</div>';
            }
        }, 300);
    }

    async function addContactUser(contactId) {
        try {
            const res = await fetch('/api/contacts/add', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + _token
                },
                body: JSON.stringify({ contactId })
            });
            const data = await res.json();
            if (data.success) {
                showToast('Contact added successfully!', 'success');
                var modal = document.getElementById('add-contact-modal');
                if (modal) modal.classList.remove('active');
                
                await connectAndSetup();
            } else {
                showToast(data.message || 'Failed to add contact', 'error');
            }
        } catch (err) {
            console.error('Failed to add contact:', err);
            showToast('Connection error. Failed to add contact.', 'error');
        }
    }

    function showAdminView() {
        document.getElementById('auth-view').classList.remove('active');
        document.getElementById('chat-view').classList.remove('active');
        document.getElementById('admin-view').classList.add('active');
        document.title = 'Talk-Secure - Admin Cockpit';
        loadAdminData();
    }

    async function loadAdminData() {
        if (!_token) return;
        
        try {
            const metricsRes = await fetch('/api/admin/metrics', {
                headers: { 'Authorization': 'Bearer ' + _token }
            });
            const metricsData = await metricsRes.json();
            if (metricsData.success) {
                document.getElementById('metric-total-users').textContent = metricsData.totalUsers;
                document.getElementById('metric-active-users').textContent = metricsData.activeUsers24h;
                document.getElementById('metric-total-messages').textContent = metricsData.totalMessages;
                document.getElementById('metric-avg-rating').textContent = metricsData.avgRating;
                
                renderAdminUsersTable(metricsData.usersList);
            }
            
            const feedbackRes = await fetch('/api/admin/feedback', {
                headers: { 'Authorization': 'Bearer ' + _token }
            });
            const feedbackData = await feedbackRes.json();
            if (feedbackData.success) {
                renderAdminFeedbackHub(feedbackData.feedbacks);
            }
            
            const logsRes = await fetch('/api/admin/logs', {
                headers: { 'Authorization': 'Bearer ' + _token }
            });
            const logsData = await logsRes.json();
            if (logsData.success) {
                renderAdminLogs(logsData.logs);
            }

            const invitesRes = await fetch('/api/admin/invites', {
                headers: { 'Authorization': 'Bearer ' + _token }
            });
            const invitesData = await invitesRes.json();
            if (invitesData.success) {
                renderAdminInvitesTable(invitesData.invites);
            }

            const ticketsRes = await fetch('/api/admin/support/tickets', {
                headers: { 'Authorization': 'Bearer ' + _token }
            });
            const ticketsData = await ticketsRes.json();
            if (ticketsData.success) {
                var totalTickets = ticketsData.tickets.length;
                var openTickets = ticketsData.tickets.filter(function(t) { return t.status === 'open'; }).length;
                var resolvedTickets = ticketsData.tickets.filter(function(t) { return t.status === 'resolved'; }).length;
                
                var totalTicketsEl = document.getElementById('metric-total-tickets');
                var openTicketsEl = document.getElementById('metric-open-tickets');
                var resolvedTicketsEl = document.getElementById('metric-resolved-tickets');
                
                if (totalTicketsEl) totalTicketsEl.textContent = totalTickets;
                if (openTicketsEl) openTicketsEl.textContent = openTickets;
                if (resolvedTicketsEl) resolvedTicketsEl.textContent = resolvedTickets;
                
                renderAdminTicketsTable(ticketsData.tickets);
            }
            
            const diagRes = await fetch('/api/admin/diagnostics', {
                headers: { 'Authorization': 'Bearer ' + _token }
            });
            const diagData = await diagRes.json();
            if (diagData.success) {
                var memUsageEl = document.getElementById('metric-memory-usage');
                var activeSocketsEl = document.getElementById('metric-active-sockets');
                var avgRttEl = document.getElementById('metric-avg-rtt');
                var avgWebrtcEl = document.getElementById('metric-avg-webrtc');
                
                if (memUsageEl) memUsageEl.textContent = diagData.memoryUsageMB + ' MB';
                if (activeSocketsEl) activeSocketsEl.textContent = diagData.activeSockets;
                if (avgRttEl) avgRttEl.textContent = diagData.avgWsLatency + ' ms';
                if (avgWebrtcEl) avgWebrtcEl.textContent = diagData.avgWebRtcLatency + ' ms';
                
                renderDiagnosticsChart(diagData.sparklinePoints);
                renderAdminDiagnosticsTable(diagData.rawLogs);
            }

            const securityRes = await fetch('/api/admin/security/audit', {
                headers: { 'Authorization': 'Bearer ' + _token }
            });
            const securityData = await securityRes.json();
            if (securityData.success) {
                renderAdminSecurityTab(securityData);
            }
        } catch (err) {
            console.error('Failed to load admin cockpit data:', err);
            showToast('Failed to load admin cockpit data.', 'error');
        }
    }

    function renderAdminUsersTable(usersList) {
        var tbody = document.getElementById('admin-users-list');
        if (!tbody) return;
        
        if (!usersList || usersList.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center">No registered users</td></tr>';
            return;
        }
        
        tbody.innerHTML = usersList.map(function(u) {
            var lockStatus = u.locked_until && new Date(u.locked_until) > new Date() ? 'Locked' : 'Active';
            var lockClass = lockStatus === 'Locked' ? 'status-locked' : 'status-active';
            var hasKeyText = u.has_key > 0 ? '✔️ Yes' : '❌ No';
            var hasKeyClass = u.has_key > 0 ? 'key-yes' : 'key-no';
            var roleText = u.is_admin === 1 ? 'Admin' : 'User';
            var roleClass = u.is_admin === 1 ? 'role-admin' : 'role-user';
            
            var isSelf = Number(u.id) === Number(_userId);
            var lockBtnText = lockStatus === 'Locked' ? 'Unlock' : 'Lock';
            var lockBtnClass = lockStatus === 'Locked' ? 'btn-success' : 'btn-danger';
            var roleBtnText = u.is_admin === 1 ? 'Demote' : 'Promote';
            var roleBtnClass = 'btn-secondary';
            
            var actions = '';
            if (isSelf) {
                actions = '<span class="muted">Logged In (Self)</span>';
            } else {
                actions = '<button class="btn btn-sm ' + lockBtnClass + ' toggle-lock-btn" data-user-id="' + u.id + '">' + lockBtnText + '</button> ' +
                          '<button class="btn btn-sm ' + roleBtnClass + ' toggle-role-btn" data-user-id="' + u.id + '" data-is-admin="' + u.is_admin + '">' + roleBtnText + '</button> ' +
                          '<button class="btn btn-sm btn-danger delete-user-btn" data-user-id="' + u.id + '" data-username="' + escapeHtml(u.username) + '">Delete</button>';
            }
            
            var joinedDate = new Date(u.created_at).toLocaleDateString();
            
            return '<tr>' +
                '<td><strong class="user-table-name">' + escapeHtml(u.username) + '</strong></td>' +
                '<td>' + escapeHtml(u.email || 'N/A') + '</td>' +
                '<td>' + escapeHtml(u.phone || 'N/A') + '</td>' +
                '<td><span class="status-badge ' + lockClass + '">' + lockStatus + '</span></td>' +
                '<td><span class="key-badge ' + hasKeyClass + '">' + hasKeyText + '</span></td>' +
                '<td><span class="role-badge ' + roleClass + '">' + roleText + '</span></td>' +
                '<td>' + joinedDate + '</td>' +
                '<td>' + actions + '</td>' +
            '</tr>';
        }).join('');
        
        tbody.querySelectorAll('.toggle-lock-btn').forEach(function(btn) {
            btn.addEventListener('click', async function() {
                var uid = parseInt(btn.dataset.userId, 10);
                await toggleUserLock(uid);
            });
        });
        
        tbody.querySelectorAll('.toggle-role-btn').forEach(function(btn) {
            btn.addEventListener('click', async function() {
                var uid = parseInt(btn.dataset.userId, 10);
                var currentIsAdmin = parseInt(btn.dataset.isAdmin, 10) === 1;
                await changeUserRole(uid, !currentIsAdmin);
            });
        });
        
        tbody.querySelectorAll('.delete-user-btn').forEach(function(btn) {
            btn.addEventListener('click', async function() {
                var uid = parseInt(btn.dataset.userId, 10);
                var uname = btn.dataset.username;
                await deleteUser(uid, uname);
            });
        });
    }

    async function toggleUserLock(targetUserId) {
        try {
            const res = await fetch('/api/admin/users/lock', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + _token
                },
                body: JSON.stringify({ targetUserId })
            });
            const data = await res.json();
            if (data.success) {
                showToast('User lock status successfully toggled!', 'success');
                await loadAdminData();
            } else {
                showToast(data.message || 'Failed to toggle user lock', 'error');
            }
        } catch (err) {
            console.error('Lock toggle failed:', err);
            showToast('Connection error. Failed to lock/unlock user.', 'error');
        }
    }

    async function changeUserRole(targetUserId, isAdmin) {
        try {
            const res = await fetch('/api/admin/users/role', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + _token
                },
                body: JSON.stringify({ targetUserId, isAdmin })
            });
            const data = await res.json();
            if (data.success) {
                showToast('User role successfully updated!', 'success');
                await loadAdminData();
            } else {
                showToast(data.message || 'Failed to update user role', 'error');
            }
        } catch (err) {
            console.error('Role update failed:', err);
            showToast('Connection error. Failed to update user role.', 'error');
        }
    }

    async function deleteUser(targetUserId, username) {
        if (!confirm('⚠️ WARNING: Are you sure you want to permanently delete user "' + username + '"? This will delete their credentials, keys, contacts, encrypted messages, and cannot be undone.')) return;
        
        try {
            const res = await fetch('/api/admin/users/delete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + _token
                },
                body: JSON.stringify({ targetUserId })
            });
            const data = await res.json();
            if (data.success) {
                showToast('User "' + username + '" successfully deleted!', 'success');
                await loadAdminData();
            } else {
                showToast(data.message || 'Failed to delete user', 'error');
            }
        } catch (err) {
            console.error('Delete user failed:', err);
            showToast('Connection error. Failed to delete user.', 'error');
        }
    }

    function renderAdminFeedbackHub(feedbacks) {
        var list = document.getElementById('admin-feedback-list');
        if (!list) return;
        
        if (!feedbacks || feedbacks.length === 0) {
            list.innerHTML = '<div class="feedback-empty">No feedback submitted yet.</div>';
            return;
        }
        
        list.innerHTML = feedbacks.map(function(f) {
            var stars = '';
            for (var i = 1; i <= 5; i++) {
                stars += '<span class="hub-star ' + (i <= f.rating ? 'active' : '') + '">★</span>';
            }
            var dateStr = new Date(f.timestamp).toLocaleString();
            
            return '<div class="feedback-card">' +
                '<div class="feedback-card-header">' +
                    '<span class="feedback-user">' + escapeHtml(f.username) + '</span>' +
                    '<span class="feedback-date">' + dateStr + '</span>' +
                '</div>' +
                '<div class="feedback-rating-display">' + stars + '</div>' +
                '<p class="feedback-card-text">' + escapeHtml(f.message) + '</p>' +
            '</div>';
        }).join('');
    }

    function renderAdminLogs(logs) {
        var tbody = document.getElementById('admin-logs-list');
        if (!tbody) return;
        
        if (!logs || logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center">No system logs available</td></tr>';
            return;
        }
        
        tbody.innerHTML = logs.map(function(l) {
            var dateStr = new Date(l.timestamp).toLocaleString();
            var detailsText = l.details ? escapeHtml(l.details) : '<span class="muted">None</span>';
            
            return '<tr>' +
                '<td>' + dateStr + '</td>' +
                '<td><strong>' + escapeHtml(l.username || 'System') + '</strong></td>' +
                '<td><code class="action-code">' + escapeHtml(l.action) + '</code></td>' +
                '<td><span class="log-details-block" title="' + detailsText + '">' + detailsText + '</span></td>' +
            '</tr>';
        }).join('');
    }

    async function generateInviteToken() {
        try {
            const res = await fetch('/api/admin/invites/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + _token
                }
            });
            const data = await res.json();
            if (data.success) {
                showToast('Invite token generated successfully!', 'success');
                
                var container = document.getElementById('admin-generated-invite-container');
                var val = document.getElementById('admin-generated-invite-val');
                if (container && val) {
                    val.textContent = data.token;
                    container.style.display = 'block';
                }
                
                await loadAdminData();
            } else {
                showToast(data.message || 'Failed to generate invite token', 'error');
            }
        } catch (err) {
            console.error('Invite generation failed:', err);
            showToast('Connection error. Failed to generate invite.', 'error');
        }
    }

    function copyInviteLink() {
        var val = document.getElementById('admin-generated-invite-val');
        if (!val) return;
        
        var text = val.textContent;
        navigator.clipboard.writeText(text).then(function() {
            showToast('Invite token copied to clipboard!', 'success');
            var btn = document.getElementById('admin-copy-invite-btn');
            if (btn) {
                btn.textContent = 'Copied!';
                setTimeout(function() { btn.textContent = 'Copy'; }, 2000);
            }
        }).catch(function() {
            showToast('Failed to copy. Copy manually: ' + text, 'error');
        });
    }

    function renderAdminInvitesTable(invites) {
        var tbody = document.getElementById('admin-invites-list');
        if (!tbody) return;
        
        if (!invites || invites.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center">No invites generated yet</td></tr>';
            return;
        }
        
        tbody.innerHTML = invites.map(function(i) {
            var statusText = i.status === 'used' ? 'Redeemed' : 'Pending';
            var statusClass = i.status === 'used' ? 'status-active' : 'status-locked';
            
            var createdDate = new Date(i.created_at).toLocaleString();
            var redeemedDate = i.used_at ? new Date(i.used_at).toLocaleString() : '<span class="muted">—</span>';
            var redeemerText = i.redeemer_username ? '<strong>' + escapeHtml(i.redeemer_username) + '</strong>' : '<span class="muted">—</span>';
            
            return '<tr>' +
                '<td><code class="action-code">' + escapeHtml(i.token) + '</code></td>' +
                '<td><strong>' + escapeHtml(i.creator_username) + '</strong></td>' +
                '<td><span class="status-badge ' + statusClass + '">' + statusText + '</span></td>' +
                '<td>' + redeemerText + '</td>' +
                '<td>' + createdDate + '</td>' +
                '<td>' + redeemedDate + '</td>' +
            '</tr>';
        }).join('');
    }

    async function handleSendBroadcast() {
        var messageInput = document.getElementById('admin-broadcast-message');
        if (!messageInput) return;
        var text = messageInput.value.trim();
        if (!text) {
            showToast('Broadcast message cannot be empty', 'error');
            return;
        }

        var sendBtn = document.getElementById('admin-send-broadcast-btn');
        var statusLabel = document.getElementById('broadcast-status-label');
        var progressContainer = document.getElementById('broadcast-progress-container');
        var progressBar = document.getElementById('broadcast-progress-bar');
        var progressText = document.getElementById('broadcast-progress-text');
        var progressPercent = document.getElementById('broadcast-progress-percent');

        if (!confirm('Are you sure you want to send this E2E encrypted broadcast announcement to all users?')) {
            return;
        }

        try {
            sendBtn.disabled = true;
            statusLabel.style.display = 'inline';
            statusLabel.textContent = 'Fetching user keys...';
            
            var response = await fetch('/api/admin/broadcast/keys', {
                headers: { 'Authorization': 'Bearer ' + _token }
            });
            var data = await response.json();
            if (!data.success) {
                throw new Error(data.message || 'Failed to fetch user keys');
            }

            var users = data.keys || [];
            // Filter out own admin key
            users = users.filter(function(u) { return Number(u.id) !== Number(_userId); });

            if (users.length === 0) {
                showToast('No other registered users with keys found', 'info');
                sendBtn.disabled = false;
                statusLabel.style.display = 'none';
                return;
            }

            progressContainer.style.display = 'block';
            progressBar.style.width = '0%';
            progressText.textContent = 'Encrypted: 0/' + users.length + ' users';
            progressPercent.textContent = '0%';

            statusLabel.textContent = 'Encrypting & broadcasting...';

            var completedCount = 0;
            
            for (var i = 0; i < users.length; i++) {
                var user = users[i];
                try {
                    var publicKeyJwk = JSON.parse(user.public_key_jwk);
                    
                    // Client-side encrypt announcement using recipient's public key
                    var encrypted = await VaultCrypto.encryptWithPeerKey(text, publicKeyJwk);
                    var msgId = 'MSG-' + generateUUID();

                    // Send E2E packet over WebSocket
                    VaultSocket.send({
                        type: 'message',
                        id: msgId,
                        encryptedContent: encrypted.ciphertext,
                        iv: encrypted.iv,
                        receiverId: user.id
                    });

                    // Save a copy of the outgoing message in local IndexedDB under this recipient's thread
                    await VaultLocalStorage.saveMessage({
                        id: msgId,
                        peerId: user.id,
                        text: text,
                        sent: true,
                        timestamp: new Date().toISOString(),
                        status: 'delivered'
                    });
                } catch (userErr) {
                    console.error('Failed to encrypt broadcast for user ' + user.username + ':', userErr);
                }

                completedCount++;
                var percent = Math.round((completedCount / users.length) * 100);
                progressBar.style.width = percent + '%';
                progressText.textContent = 'Encrypted: ' + completedCount + '/' + users.length + ' users';
                progressPercent.textContent = percent + '%';
            }

            showToast('Broadcast successfully transmitted to ' + completedCount + ' users!', 'success');
            messageInput.value = '';
            statusLabel.textContent = 'Broadcast sent successfully!';
            
            setTimeout(function() {
                progressContainer.style.display = 'none';
                statusLabel.style.display = 'none';
                sendBtn.disabled = false;
            }, 3000);

        } catch (err) {
            console.error('Broadcast failed:', err);
            showToast(err.message || 'Failed to send broadcast', 'error');
            sendBtn.disabled = false;
            statusLabel.style.display = 'none';
            progressContainer.style.display = 'none';
        }
    }

    function generateUUID() {
        if (typeof crypto !== 'undefined' && crypto.randomUUID) {
            return crypto.randomUUID();
        }
        // Secure fallback using crypto.getRandomValues()
        var bytes = new Uint8Array(16);
        crypto.getRandomValues(bytes);
        bytes[6] = (bytes[6] & 0x0f) | 0x40; // Version 4
        bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant 1
        var hex = Array.from(bytes).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
        return hex.slice(0,8) + '-' + hex.slice(8,12) + '-' + hex.slice(12,16) + '-' + hex.slice(16,20) + '-' + hex.slice(20);
    }

    async function handleCreateSupportTicket(e) {
        e.preventDefault();
        
        var categorySelect = document.getElementById('support-ticket-category');
        var descriptionInput = document.getElementById('support-ticket-description');
        if (!categorySelect || !descriptionInput) return;
        
        var category = categorySelect.value;
        var description = descriptionInput.value.trim();
        if (!description) {
            showToast('Please provide an issue description', 'error');
            return;
        }
        
        var submitBtn = e.target.querySelector('button[type="submit"]');
        if (submitBtn) submitBtn.disabled = true;
        
        try {
            // 1. Generate local ticket ID
            var ticketId = 'TKT-' + generateUUID().split('-')[0].toUpperCase();
            
            // 2. Locate administrator
            var admin = _users.find(function(u) { return u.is_admin === 1; });
            if (!admin) {
                showToast('No administrator contact found. Support is temporarily unavailable.', 'error');
                if (submitBtn) submitBtn.disabled = false;
                return;
            }
            
            // 3. Fetch administrator public key
            var adminPubKey = await getPeerPublicKey(admin.id);
            if (!adminPubKey) {
                showToast('Could not fetch administrator E2E keys. Please try again.', 'error');
                if (submitBtn) submitBtn.disabled = false;
                return;
            }
            
            // 4. Client-side encrypt announcement payload using administrator's key
            var ticketText = '🎟️ [Support Ticket #' + ticketId + '] Category: ' + category + '\nIssue Details:\n' + description;
            var encrypted = await VaultCrypto.encryptWithPeerKey(ticketText, adminPubKey);
            
            // 5. Post metadata to server
            var response = await fetch('/api/support/tickets', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + _token
                },
                body: JSON.stringify({ ticketId: ticketId, category: category })
            });
            var data = await response.json();
            if (!data.success) {
                throw new Error(data.message || 'Server rejected ticket creation');
            }
            
            // 6. Send E2E packet over socket
            var msgId = 'MSG-' + generateUUID();
            VaultSocket.send({
                type: 'message',
                id: msgId,
                encryptedContent: encrypted.ciphertext,
                iv: encrypted.iv,
                receiverId: admin.id
            });
            
            // 7. Store E2E ticket announcement locally under admin contact thread
            await VaultLocalStorage.saveMessage({
                id: msgId,
                peerId: admin.id,
                text: ticketText,
                sent: true,
                timestamp: new Date().toISOString(),
                status: 'delivered'
            });
            
            showToast('Support ticket ' + ticketId + ' successfully created!', 'success');
            descriptionInput.value = '';
            
            // Hide modal
            var modal = document.getElementById('support-ticket-modal');
            if (modal) modal.classList.remove('active');
            
        } catch (err) {
            console.error('Support ticket creation failed:', err);
            showToast(err.message || 'Failed to submit support ticket', 'error');
        } finally {
            if (submitBtn) submitBtn.disabled = false;
        }
    }
    
    function getPeerPublicKey(peerId) {
        return new Promise(function(resolve) {
            _pendingAdminKeyResolve = resolve;
            _pendingAdminKeyUserId = peerId;
            VaultSocket.send({ type: 'get_peer_key', peerId: peerId });
            
            setTimeout(function() {
                if (_pendingAdminKeyResolve) {
                    _pendingAdminKeyResolve(null);
                    _pendingAdminKeyResolve = null;
                }
            }, 5000);
        });
    }
    
    function renderAdminTicketsTable(tickets) {
        var tbody = document.getElementById('admin-tickets-list');
        if (!tbody) return;
        
        if (!tickets || tickets.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center">No support tickets generated yet</td></tr>';
            return;
        }
        
        tbody.innerHTML = tickets.map(function(t) {
            var statusText = t.status === 'resolved' ? 'Resolved' : 'Open';
            var statusClass = t.status === 'resolved' ? 'status-active' : 'status-locked';
            
            var createdDate = new Date(t.created_at).toLocaleString();
            var resolvedDate = t.resolved_at ? new Date(t.resolved_at).toLocaleString() : '<span class="muted">—</span>';
            
            var actionBtns = '';
            if (t.status === 'open') {
                actionBtns = '<button class="btn btn-secondary btn-sm admin-ticket-chat-btn" data-username="' + escapeHtml(t.username) + '" style="margin-right: 8px;">Chat</button>' +
                             '<button class="btn btn-primary btn-sm admin-ticket-resolve-btn" data-ticket-id="' + escapeHtml(t.id) + '">Resolve</button>';
            } else {
                actionBtns = '<button class="btn btn-secondary btn-sm admin-ticket-chat-btn" data-username="' + escapeHtml(t.username) + '">Chat</button>';
            }
            
            return '<tr>' +
                '<td><code class="action-code">' + escapeHtml(t.id) + '</code></td>' +
                '<td><strong>' + escapeHtml(t.username) + '</strong></td>' +
                '<td><span class="category-badge">' + escapeHtml(t.category) + '</span></td>' +
                '<td><span class="status-badge ' + statusClass + '">' + statusText + '</span></td>' +
                '<td>' + createdDate + '</td>' +
                '<td>' + resolvedDate + '</td>' +
                '<td>' + actionBtns + '</td>' +
            '</tr>';
        }).join('');
        
        tbody.querySelectorAll('.admin-ticket-chat-btn').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var username = btn.dataset.username;
                chatWithUser(username);
            });
        });
        
        tbody.querySelectorAll('.admin-ticket-resolve-btn').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var ticketId = btn.dataset.ticketId;
                resolveSupportTicket(ticketId);
            });
        });
    }
    
    function chatWithUser(username) {
        var user = _users.find(function(u) { return u.username === username; });
        if (!user) {
            showToast('User not found in contacts list', 'error');
            return;
        }
        
        document.getElementById('admin-view').classList.remove('active');
        document.getElementById('chat-view').classList.add('active');
        document.title = 'Talk-Secure';
        
        selectPeer(user.id);
    }
    
    async function resolveSupportTicket(ticketId) {
        if (!confirm('Are you sure you want to mark ticket ' + ticketId + ' as resolved?')) {
            return;
        }
        
        try {
            var response = await fetch('/api/admin/support/tickets/resolve', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + _token
                },
                body: JSON.stringify({ ticketId: ticketId })
            });
            var data = await response.json();
            if (data.success) {
                showToast('Ticket marked as resolved!', 'success');
                await loadAdminData();
            } else {
                showToast(data.message || 'Failed to resolve ticket', 'error');
            }
        } catch (err) {
            console.error('Resolve ticket failed:', err);
            showToast('Connection error. Failed to resolve ticket.', 'error');
        }
    }
    
    async function reportDiagnosticMetric(type, value) {
        if (!_token) return;
        try {
            await fetch('/api/diagnostics/report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + _token
                },
                body: JSON.stringify({ type: type, value: value })
            });
        } catch (err) {
            console.warn('Failed to submit diagnostic metric:', err);
        }
    }
    
    function renderDiagnosticsChart(points) {
        var svg = document.getElementById('diagnostics-chart');
        if (!svg) return;
        
        var linePath = document.getElementById('chart-line-path');
        var fillPath = document.getElementById('chart-fill-path');
        var nodesContainer = document.getElementById('chart-data-nodes');
        
        if (!linePath || !fillPath || !nodesContainer) return;
        
        nodesContainer.innerHTML = '';
        
        if (!points || points.length === 0) {
            linePath.setAttribute('d', '');
            fillPath.setAttribute('d', '');
            return;
        }

        var data = points.map(function(p) { return parseFloat(p.metric_value); });
        
        var width = 600;
        var height = 180;
        var padding = 20;
        
        var minVal = Math.min.apply(null, data);
        var maxVal = Math.max.apply(null, data);
        if (minVal === maxVal) {
            minVal = 0;
            maxVal = maxVal || 100;
        }
        
        maxVal = maxVal * 1.15;
        
        var pointsCount = data.length;
        var stepX = pointsCount > 1 ? (width - padding * 2) / (pointsCount - 1) : width - padding * 2;
        
        var coords = [];
        for (var i = 0; i < pointsCount; i++) {
            var x = padding + i * stepX;
            var y = height - padding - ((data[i] - minVal) / (maxVal - minVal)) * (height - padding * 2);
            coords.push({ x: x, y: y, val: data[i], type: points[i].metric_type });
        }
        
        var dLine = '';
        if (coords.length > 0) {
            dLine = 'M ' + coords[0].x + ' ' + coords[0].y;
            
            for (var i = 0; i < coords.length - 1; i++) {
                var p0 = coords[i];
                var p1 = coords[i + 1];
                
                var cpX1 = p0.x + (p1.x - p0.x) / 3;
                var cpY1 = p0.y;
                var cpX2 = p0.x + 2 * (p1.x - p0.x) / 3;
                var cpY2 = p1.y;
                
                dLine += ' C ' + cpX1 + ' ' + cpY1 + ', ' + cpX2 + ' ' + cpY2 + ', ' + p1.x + ' ' + p1.y;
            }
        }
        
        linePath.setAttribute('d', dLine);
        
        var dFill = '';
        if (coords.length > 0) {
            dFill = dLine + 
                    ' L ' + coords[coords.length - 1].x + ' ' + (height - padding) + 
                    ' L ' + coords[0].x + ' ' + (height - padding) + 
                    ' Z';
        }
        fillPath.setAttribute('d', dFill);
        
        var nodesHtml = coords.map(function(c, idx) {
            var color = c.type === 'ws_latency' ? '#d4af37' : '#ec4899';
            return '<circle cx="' + c.x + '" cy="' + c.y + '" r="5" fill="' + color + '" stroke="#141414" stroke-width="2" style="cursor: pointer;">' +
                   '<title>' + c.type + ': ' + c.val.toFixed(1) + ' ms (' + new Date(points[idx].timestamp).toLocaleTimeString() + ')</title>' +
                   '</circle>';
        }).join('');
        nodesContainer.innerHTML = nodesHtml;
    }
    
    function renderAdminDiagnosticsTable(logs) {
        var tbody = document.getElementById('admin-diagnostics-list');
        if (!tbody) return;
        
        if (!logs || logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">No telemetry logs captured yet</td></tr>';
            return;
        }
        
        tbody.innerHTML = logs.map(function(l) {
            var dateStr = new Date(l.timestamp).toLocaleString();
            var usernameText = l.username ? '<strong>' + escapeHtml(l.username) + '</strong>' : '<span class="muted">System</span>';
            var typeText = l.metric_type === 'ws_latency' ? 'Signaling RTT' : 'WebRTC Call Setup';
            var valueText = l.metric_value.toFixed(1) + ' ms';
            var typeClass = l.metric_type === 'ws_latency' ? 'role-admin' : 'status-active';
            
            return '<tr>' +
                '<td><code class="action-code">LOG-' + l.id + '</code></td>' +
                '<td>' + dateStr + '</td>' +
                '<td>' + usernameText + '</td>' +
                '<td><span class="status-badge ' + typeClass + '">' + typeText + '</span></td>' +
                '<td><strong>' + valueText + '</strong></td>' +
            '</tr>';
        }).join('');
    }

    async function triggerForceGlobalKeyRotation() {
        if (!confirm('Are you sure you want to force a global cryptographic identity key rotation? This will notify all logged-in and future active sessions to rotate their keypairs.')) return;
        
        try {
            var response = await fetch('/api/admin/security/force-rotation-alert', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + _token
                }
            });
            var data = await response.json();
            if (data.success) {
                showToast('Global rotation alert forced successfully!', 'success');
                await loadAdminData();
            } else {
                showToast(data.message || 'Failed to force global rotation', 'error');
            }
        } catch (err) {
            console.error('Failed to force global rotation:', err);
            showToast('Connection error. Failed to force global rotation.', 'error');
        }
    }

    function renderAdminSecurityTab(data) {
        var avgKeyAgeEl = document.getElementById('metric-security-avg-key-age');
        var expiredKeysEl = document.getElementById('metric-security-expired-keys');
        var lockoutsEl = document.getElementById('metric-security-lockouts');
        var failedLoginsEl = document.getElementById('metric-security-failed-logins');
        
        if (avgKeyAgeEl) avgKeyAgeEl.textContent = parseFloat(data.avgKeyAge).toFixed(1) + ' days';
        if (expiredKeysEl) expiredKeysEl.textContent = data.expiredKeys + ' / ' + data.totalKeys;
        if (lockoutsEl) lockoutsEl.textContent = data.activeLockouts;
        if (failedLoginsEl) failedLoginsEl.textContent = data.failedLoginsWeek;
        
        var complianceStatusEl = document.getElementById('security-compliance-status');
        if (complianceStatusEl) {
            if (data.expiredKeys > 0 || data.activeLockouts > 0) {
                complianceStatusEl.textContent = 'WARNING';
                complianceStatusEl.style.color = '#ef4444';
            } else {
                complianceStatusEl.textContent = 'EXCELLENT';
                complianceStatusEl.style.color = '#10b981';
            }
        }

        var healthGradeEl = document.getElementById('security-health-grade');
        var healthScoreEl = document.getElementById('security-health-score');
        if (healthGradeEl) healthGradeEl.textContent = data.grade;
        if (healthScoreEl) healthScoreEl.textContent = 'Score: ' + data.score + '/100';

        var score = parseInt(data.score, 10) || 0;
        var needleAngle = -90 + (score / 100) * 180;
        
        var needleGroup = document.getElementById('gauge-needle-group');
        if (needleGroup) {
            needleGroup.style.transform = 'rotate(' + needleAngle + 'deg)';
        }

        var healthArc = document.getElementById('gauge-health-arc');
        if (healthArc) {
            var offset = 283 - (score / 100) * 283;
            healthArc.style.strokeDashoffset = offset;
        }

        renderSecurityLogsTable(data.securityLogs);
    }

    function renderSecurityLogsTable(logs) {
        var tbody = document.getElementById('admin-security-logs-list');
        if (!tbody) return;

        if (!logs || logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">No security logs recorded yet</td></tr>';
            return;
        }

        tbody.innerHTML = logs.map(function(l) {
            var dateStr = new Date(l.timestamp).toLocaleString();
            var userText = l.username ? '<strong>' + escapeHtml(l.username) + '</strong>' : '<span class="muted">System</span>';
            
            var categoryText = '';
            var categoryClass = '';
            var descText = '';

            switch (l.action) {
                case 'login_failed':
                    categoryText = 'Access Blocked';
                    categoryClass = 'btn-danger';
                    descText = 'Failed login attempt. Reason: ' + (l.details ? JSON.parse(l.details).reason : 'Unknown');
                    break;
                case 'account_locked':
                    categoryText = 'Account Locked';
                    categoryClass = 'btn-danger';
                    descText = 'Brute force protection triggered. Account temporarily locked.';
                    break;
                case 'admin_change_role':
                    categoryText = 'Privilege Change';
                    categoryClass = 'role-admin';
                    var details = l.details ? JSON.parse(l.details) : {};
                    descText = 'Role modified for target user ID: ' + details.targetUserId + '. Admin: ' + (details.isAdmin === 1 ? 'Yes' : 'No');
                    break;
                case 'admin_delete_user':
                    categoryText = 'User Purge';
                    categoryClass = 'btn-danger';
                    var details = l.details ? JSON.parse(l.details) : {};
                    descText = 'Deleted user account target ID: ' + details.targetUserId;
                    break;
                case 'admin_toggle_lock':
                    categoryText = 'Manual Override';
                    categoryClass = 'role-admin';
                    var details = l.details ? JSON.parse(l.details) : {};
                    descText = 'Manual account toggle lockout for target user ID: ' + details.targetUserId;
                    break;
                case 'register':
                    categoryText = 'Account Created';
                    categoryClass = 'status-active';
                    descText = 'New identity registered in sqlite database directory.';
                    break;
                case 'login_success':
                    categoryText = 'Access Granted';
                    categoryClass = 'status-active';
                    descText = 'User successfully logged in with safe credentials.';
                    break;
                case 'global_key_rotation_forced':
                    categoryText = 'Security Override';
                    categoryClass = 'role-admin';
                    descText = 'Global E2E identity key compliance rotation forced by system administrator.';
                    break;
                default:
                    categoryText = 'System Audit';
                    categoryClass = 'role-user';
                    descText = l.action;
            }

            return '<tr>' +
                '<td><code class="action-code">SEC-' + l.id + '</code></td>' +
                '<td>' + dateStr + '</td>' +
                '<td>' + userText + '</td>' +
                '<td><span class="status-badge ' + categoryClass + '" style="font-size: 11px; padding: 4px 8px; border-radius: var(--radius-sm); font-weight: 600;">' + categoryText + '</span></td>' +
                '<td>' + escapeHtml(descText) + '</td>' +
            '</tr>';
        }).join('');
    }

    return { init: init };
})();

document.addEventListener('DOMContentLoaded', VaultApp.init);
