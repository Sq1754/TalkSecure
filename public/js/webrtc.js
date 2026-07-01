/**
 * Talk-Secure — WebRTC Video Call Module
 * Peer-to-peer encrypted video/audio using native WebRTC
 * Server acts only as signaling relay — media goes P2P
 * DTLS-SRTP encryption is built into WebRTC
 */

const VaultWebRTC = (() => {
    let _peerConnection = null;
    let _localStream = null;
    let _remoteStream = null;
    let _callState = 'idle'; // idle, calling, ringing, connected, ended
    let _handlers = {};
    let _pendingCandidates = [];
    let _isInitiator = false;

    // WebRTC configuration
    // STUN servers help with NAT traversal (they only discover your public IP,
    // they never see any media data). For same-network usage, these aren't even needed.
    const RTC_CONFIG = {
        iceServers: [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:stun1.l.google.com:19302' }
        ],
        iceCandidatePoolSize: 2
    };

    // Media constraints
    const MEDIA_CONSTRAINTS = {
        video: {
            width: { ideal: 1280, max: 1920 },
            height: { ideal: 720, max: 1080 },
            frameRate: { ideal: 30, max: 60 },
            facingMode: 'user'
        },
        audio: {
            echoCancellation: true,
            noiseSuppression: true,
            autoGainControl: true
        }
    };

    // ═══════════════════════════════════════
    // Call Initiation
    // ═══════════════════════════════════════

    /**
     * Start a video call (caller side)
     */
    async function startCall() {
        if (_callState !== 'idle') {
            console.warn('Call already in progress');
            return;
        }

        try {
            _isInitiator = true;
            _callState = 'calling';
            emit('state_change', { state: 'calling' });

            // Get local media
            await acquireLocalMedia();

            // Create peer connection
            createPeerConnection();

            // Add local tracks to connection
            _localStream.getTracks().forEach(track => {
                _peerConnection.addTrack(track, _localStream);
            });

            // Create offer
            const offer = await _peerConnection.createOffer({
                offerToReceiveAudio: true,
                offerToReceiveVideo: true
            });

            await _peerConnection.setLocalDescription(offer);

            // Send offer via signaling (WebSocket)
            emit('signal_send', {
                type: 'call_offer',
                sdp: offer.sdp
            });

            console.log('📞 Call offer sent');
        } catch (err) {
            console.error('Failed to start call:', err);
            endCall();
            emit('error', { message: 'Failed to start camera/microphone. Check permissions.' });
        }
    }

    /**
     * Handle incoming call offer (callee side)
     */
    async function handleOffer(sdp) {
        if (_callState !== 'idle') {
            // Already in a call, reject
            emit('signal_send', { type: 'call_reject', reason: 'busy' });
            return;
        }

        _isInitiator = false;
        _callState = 'ringing';
        emit('state_change', { state: 'ringing', sdp });

        // Store the offer SDP for when user accepts
        _pendingOffer = sdp;
    }

    let _pendingOffer = null;

    /**
     * Accept incoming call
     */
    async function acceptCall() {
        if (_callState !== 'ringing' || !_pendingOffer) return;

        try {
            _callState = 'connecting';
            emit('state_change', { state: 'connecting' });

            // Get local media
            await acquireLocalMedia();

            // Create peer connection
            createPeerConnection();

            // Add local tracks
            _localStream.getTracks().forEach(track => {
                _peerConnection.addTrack(track, _localStream);
            });

            // Set remote description (the offer)
            await _peerConnection.setRemoteDescription(
                new RTCSessionDescription({ type: 'offer', sdp: _pendingOffer })
            );

            // Process any pending ICE candidates
            await processPendingCandidates();

            // Create answer
            const answer = await _peerConnection.createAnswer();
            await _peerConnection.setLocalDescription(answer);

            // Send answer
            emit('signal_send', {
                type: 'call_answer',
                sdp: answer.sdp
            });

            _pendingOffer = null;
            console.log('📞 Call answered');
        } catch (err) {
            console.error('Failed to accept call:', err);
            endCall();
            emit('error', { message: 'Failed to start camera/microphone. Check permissions.' });
        }
    }

    /**
     * Reject incoming call
     */
    function rejectCall() {
        _pendingOffer = null;
        _callState = 'idle';
        emit('signal_send', { type: 'call_reject', reason: 'declined' });
        emit('state_change', { state: 'idle' });
    }

    /**
     * Handle call answer (caller receives this)
     */
    async function handleAnswer(sdp) {
        if (!_peerConnection) return;

        try {
            await _peerConnection.setRemoteDescription(
                new RTCSessionDescription({ type: 'answer', sdp })
            );
            await processPendingCandidates();
            console.log('📞 Call answer received');
        } catch (err) {
            console.error('Failed to handle answer:', err);
        }
    }

    /**
     * Handle ICE candidate from peer
     */
    async function handleIceCandidate(candidate) {
        if (_peerConnection && _peerConnection.remoteDescription) {
            try {
                await _peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
            } catch (err) {
                console.error('Failed to add ICE candidate:', err);
            }
        } else {
            // Queue the candidate for later
            _pendingCandidates.push(candidate);
        }
    }

    /**
     * Handle call rejection
     */
    function handleReject(reason) {
        console.log('📞 Call rejected:', reason);
        endCall();
        emit('rejected', { reason });
    }

    /**
     * End the call
     */
    function endCall() {
        // Check state BEFORE resetting (for signaling decision)
        const prevState = _callState;

        // Stop local media tracks
        if (_localStream) {
            _localStream.getTracks().forEach(track => track.stop());
            _localStream = null;
        }

        // Close peer connection
        if (_peerConnection) {
            _peerConnection.close();
            _peerConnection = null;
        }

        _remoteStream = null;
        _pendingCandidates = [];
        _pendingOffer = null;
        _isInitiator = false;
        _callState = 'idle';

        // Notify peer if we were in an active call state
        if (prevState === 'connected' || prevState === 'calling' || prevState === 'ringing' || prevState === 'connecting') {
            emit('signal_send', { type: 'call_end' });
        }

        emit('state_change', { state: 'idle' });
        emit('call_ended', {});
    }

    /**
     * Handle peer ending the call
     */
    function handleCallEnd() {
        if (_callState === 'idle') return;
        endCall();
    }

    /**
     * Full reset — call on logout/disconnect to clean up all state
     */
    function reset() {
        // Stop any active media
        if (_localStream) {
            _localStream.getTracks().forEach(track => track.stop());
            _localStream = null;
        }

        if (_peerConnection) {
            _peerConnection.close();
            _peerConnection = null;
        }

        _remoteStream = null;
        _pendingCandidates = [];
        _pendingOffer = null;
        _isInitiator = false;
        _callState = 'idle';

        console.log('📞 WebRTC state reset');
    }

    // ═══════════════════════════════════════
    // Media Controls
    // ═══════════════════════════════════════

    function toggleMute() {
        if (!_localStream) return false;
        const audioTrack = _localStream.getAudioTracks()[0];
        if (audioTrack) {
            audioTrack.enabled = !audioTrack.enabled;
            emit('mute_change', { muted: !audioTrack.enabled });
            return !audioTrack.enabled;
        }
        return false;
    }

    function toggleVideo() {
        if (!_localStream) return false;
        const videoTrack = _localStream.getVideoTracks()[0];
        if (videoTrack) {
            videoTrack.enabled = !videoTrack.enabled;
            emit('video_change', { videoOff: !videoTrack.enabled });
            return !videoTrack.enabled;
        }
        return false;
    }

    function isMuted() {
        if (!_localStream) return true;
        const audioTrack = _localStream.getAudioTracks()[0];
        return audioTrack ? !audioTrack.enabled : true;
    }

    function isVideoOff() {
        if (!_localStream) return true;
        const videoTrack = _localStream.getVideoTracks()[0];
        return videoTrack ? !videoTrack.enabled : true;
    }

    function getCallState() {
        return _callState;
    }

    function getLocalStream() {
        return _localStream;
    }

    function getRemoteStream() {
        return _remoteStream;
    }

    // ═══════════════════════════════════════
    // Internal
    // ═══════════════════════════════════════

    async function acquireLocalMedia() {
        try {
            _localStream = await navigator.mediaDevices.getUserMedia(MEDIA_CONSTRAINTS);
            emit('local_stream', { stream: _localStream });
        } catch (err) {
            // Try audio-only if video fails
            console.warn('Video failed, trying audio-only:', err.message);
            try {
                _localStream = await navigator.mediaDevices.getUserMedia({ audio: MEDIA_CONSTRAINTS.audio, video: false });
                emit('local_stream', { stream: _localStream });
                emit('error', { message: 'Camera unavailable. Audio-only call.' });
            } catch (audioErr) {
                throw new Error('No camera or microphone available');
            }
        }
    }

    function createPeerConnection() {
        _peerConnection = new RTCPeerConnection(RTC_CONFIG);

        // ICE candidate events
        _peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                emit('signal_send', {
                    type: 'ice_candidate',
                    candidate: event.candidate.toJSON()
                });
            }
        };

        // Connection state changes
        _peerConnection.onconnectionstatechange = () => {
            const state = _peerConnection.connectionState;
            console.log('📞 Connection state:', state);

            if (state === 'connected') {
                _callState = 'connected';
                emit('state_change', { state: 'connected' });
            } else if (state === 'disconnected' || state === 'failed') {
                endCall();
            }
        };

        _peerConnection.oniceconnectionstatechange = () => {
            const state = _peerConnection.iceConnectionState;
            console.log('📞 ICE state:', state);

            if (state === 'connected' || state === 'completed') {
                _callState = 'connected';
                emit('state_change', { state: 'connected' });
            }
        };

        // Remote stream
        _peerConnection.ontrack = (event) => {
            console.log('📞 Remote track received:', event.track.kind);
            if (event.streams && event.streams[0]) {
                _remoteStream = event.streams[0];
                emit('remote_stream', { stream: _remoteStream });
            }
        };
    }

    async function processPendingCandidates() {
        for (const candidate of _pendingCandidates) {
            try {
                await _peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
            } catch (err) {
                console.error('Failed to add queued ICE candidate:', err);
            }
        }
        _pendingCandidates = [];
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
                try { h(data); } catch (err) { console.error(`WebRTC handler error [${event}]:`, err); }
            });
        }
    }

    function clearHandlers() {
        _handlers = {};
    }

    return {
        startCall,
        handleOffer,
        acceptCall,
        rejectCall,
        handleAnswer,
        handleIceCandidate,
        handleReject,
        handleCallEnd,
        endCall,
        reset,
        toggleMute,
        toggleVideo,
        isMuted,
        isVideoOff,
        getCallState,
        getLocalStream,
        getRemoteStream,
        getPeerConnection: function() { return _peerConnection; },
        on,
        off,
        clearHandlers
    };
})();
