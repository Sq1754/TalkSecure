const WebSocket = require('ws');
const crypto = require('crypto');

// Ignore self-signed cert errors for testing
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const BASE_URL = 'https://localhost:3000';
const WS_URL = 'wss://localhost:3000';
const NUM_USERS = 48; // Leaves room for the 2 existing users

async function runLoadTest() {
    console.log(`🚀 Starting load test for ${NUM_USERS} concurrent users...`);
    
    const users = [];
    const sockets = [];

    // 1. Registration Phase
    console.log('\n--- 1. Registration Phase ---');
    for (let i = 0; i < NUM_USERS; i++) {
        const username = `loaduser_${i}`;
        const password = 'LoadTestPassword123!';
        
        try {
            const res = await fetch(`${BASE_URL}/api/auth/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const data = await res.json();
            
            if (res.ok && data.success) {
                users.push({ username, password });
            } else if (data.message.includes('maximum number of users')) {
                console.log(`Registration capped: ${data.message}`);
                break;
            } else if (data.message.includes('already exists')) {
                users.push({ username, password }); // Use existing
            } else {
                console.warn(`Failed to register ${username}:`, data);
            }
        } catch (err) {
            console.error(`Error registering ${username}:`, err.message);
        }
    }
    console.log(`Registered/found ${users.length} users.`);

    // 2. Login Phase
    console.log('\n--- 2. Login Phase ---');
    for (const user of users) {
        try {
            const res = await fetch(`${BASE_URL}/api/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: user.username, password: user.password })
            });
            const data = await res.json();
            if (res.ok && data.success) {
                user.token = data.token;
                user.id = data.userId;
            }
        } catch (err) {
            console.error(`Error logging in ${user.username}:`, err.message);
        }
    }
    
    const loggedInUsers = users.filter(u => u.token);
    console.log(`Logged in ${loggedInUsers.length} users.`);

    // 3. WebSocket Connection Phase
    console.log('\n--- 3. WebSocket Connection Phase ---');
    let connectedCount = 0;
    
    for (const user of loggedInUsers) {
        const ws = new WebSocket(WS_URL);
        
        ws.on('open', () => {
            ws.send(JSON.stringify({ type: 'auth', token: user.token }));
        });
        
        ws.on('message', (data) => {
            const msg = JSON.parse(data);
            if (msg.type === 'auth_success') {
                connectedCount++;
                if (connectedCount % 10 === 0) {
                    console.log(`Connected ${connectedCount}/${loggedInUsers.length} websockets...`);
                }
                
                // Simulate periodic activity
                setInterval(() => {
                    if (ws.readyState === WebSocket.OPEN) {
                        // Send presence update to keep connection alive
                        ws.send(JSON.stringify({ type: 'typing', receiverId: 1 }));
                    }
                }, Math.random() * 5000 + 5000);
            }
        });
        
        ws.on('error', (err) => console.error(`WS Error for ${user.username}:`, err.message));
        
        sockets.push(ws);
        
        // Stagger connections slightly
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    
    // Wait for connections to stabilize
    await new Promise(resolve => setTimeout(resolve, 3000));
    console.log(`\n✅ Load test running with ${connectedCount} active connections.`);
    
    const memoryUsage = process.memoryUsage();
    console.log(`Client Memory: ${Math.round(memoryUsage.rss / 1024 / 1024)} MB RSS`);
    
    console.log('\nTest will run for 10 seconds, then clean up...');
    
    setTimeout(() => {
        console.log('\n--- 4. Cleanup Phase ---');
        sockets.forEach(ws => ws.close());
        console.log('Load test complete.');
        process.exit(0);
    }, 10000);
}

runLoadTest().catch(console.error);
