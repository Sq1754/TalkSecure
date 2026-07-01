/**
 * Talk-Secure — First-Run Setup
 * Generates all secrets, certificates, and database
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { generateSelfSignedCert } = require('./generate-cert');

const ROOT = path.join(__dirname, '..');

console.log('\n🔒 Talk-Secure Setup\n');
console.log('═══════════════════════════════════════');

// 1. Generate .env file with cryptographic secrets
const envPath = path.join(ROOT, '.env');
if (!fs.existsSync(envPath)) {
    const jwtSecret = crypto.randomBytes(64).toString('hex');
    const dbEncryptionKey = crypto.randomBytes(32).toString('hex');
    const port = 3000;
    const messageRetentionDays = 14;

    const envContent = `# Talk-Secure Configuration — AUTO-GENERATED
# DO NOT share this file or commit it to version control

# Server
PORT=${port}
HOST=0.0.0.0

# Authentication
JWT_SECRET=${jwtSecret}
JWT_EXPIRY=24h

# Database encryption (at-rest)
DB_ENCRYPTION_KEY=${dbEncryptionKey}

# Message retention (days) — messages auto-delete after this period
MESSAGE_RETENTION_DAYS=${messageRetentionDays}

# Max users (public testing)
MAX_USERS=50

# Rate limiting
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX_REQUESTS=100
`;

    fs.writeFileSync(envPath, envContent);
    console.log('   ✓ .env created with cryptographic secrets');
} else {
    console.log('   • .env already exists, skipping');
}

// 2. Generate TLS certificates
const certsDir = path.join(ROOT, 'certs');
if (!fs.existsSync(path.join(certsDir, 'server.cert'))) {
    generateSelfSignedCert(certsDir);
} else {
    console.log('   • TLS certificates already exist, skipping');
}

// 3. Create data directory
const dataDir = path.join(ROOT, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
    console.log('   ✓ Data directory created');
} else {
    console.log('   • Data directory already exists');
}

// 4. Create fonts directory
const fontsDir = path.join(ROOT, 'public', 'fonts');
if (!fs.existsSync(fontsDir)) {
    fs.mkdirSync(fontsDir, { recursive: true });
    console.log('   ✓ Fonts directory created');
}

console.log('\n═══════════════════════════════════════');
console.log('✅ Setup complete!\n');
console.log('Next steps:');
console.log('   1. npm start        (start the server)');
console.log('   2. Open https://localhost:3000 in your browser');
console.log('   3. Accept the self-signed certificate warning');
console.log('   4. Register your user accounts\n');
