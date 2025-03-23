const crypto = require('crypto');
const argon2 = require('argon2');
const os = require('os');
const fs = require('fs');
const dns = require('dns');

const { runOSCommand } = require('./ca');

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 16;

const ARGON2_OPTIONS = {
    type: argon2.argon2id,
    memoryCost: 2 ** 16,
    timeCost: 4,
    parallelism: 2,
}

module.exports = {
    sleep: (ms) => {
        return new Promise(resolve => setTimeout(resolve, ms));
    },

    generateKeyPair: () => {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });

        return { publicKey, privateKey };
    },

    encryptPrivateKey: async (privateKey, password, salt) => {
        const derivedKey = await argon2.hash(password+salt, ARGON2_OPTIONS);
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, derivedKey.substring(0, KEY_LENGTH), iv);
        let encrypted = cipher.update(privateKey, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();

        return { encryptedPrivateKey: encrypted, iv: iv.toString('hex'), authTag: authTag.toString('hex') };
    },

    decryptPrivateKey: async (encryptedPrivateKey, password, salt, iv, authTag) => {
        const derivedKey = await argon2.hash(password+salt, ARGON2_OPTIONS);
        const decipher = crypto.createDecipheriv(ALGORITHM, derivedKey.substring(0, KEY_LENGTH), Buffer.from(iv, 'hex'));
        decipher.setAuthTag(Buffer.from(authTag, 'hex'));
        let decrypted = decipher.update(encryptedPrivateKey, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    },

    generateSalt: () => {
        return crypto.randomBytes(32).toString('hex');
    },

    createRootCACert: () => {
        runOSCommand(`openssl genpkey -algorithm Ed25519 -out ca.key`);
        runOSCommand(`openssl req -x509 -new -key ca.key -out ca.crt -days 3650 -subj "/CN=Root CA" -extensions v3_ca`);
    },

    createServerCert: (ip) => {
        const hostname = os.hostname();
        runOSCommand(`openssl genpkey -algorithm Ed25519 -out server.key`);
        runOSCommand(`openssl req -new -key server.key -out server.csr -subj "/CN=${ip}"`);
        runOSCommand(`bash -c "openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extfile <(printf 'subjectAltName=IP:${ip},IP:127.0.0.1,DNS:${hostname}')"`);
    },

    createClientCert: () => {
        runOSCommand(`openssl genpkey -algorithm Ed25519 -out client.key`);
        runOSCommand(`openssl req -new -key client.key -out client.csr -subj "/CN=P2PAgentClient"`);
        runOSCommand(`openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365`)
    },

    getLocalIPv4Address: () => {
        const interfaces = os.networkInterfaces();
        for (const name of Object.keys(interfaces)) {
            for (const iface of interfaces[name]) {
                if (iface.family === 'IPv4' && !iface.internal) {
                    return iface.address;
                }
            }
        }
        return '127.0.0.1'; // Fallback to localhost if no external IPv4 address is found
    },

    getConfigDirectory: () => {
        const homedir = os.homedir();
        const configDir = `${homedir}/.p2p-agent`;

        if (!fs.existsSync(configDir)) {
            fs.mkdirSync(configDir);
            fs.mkdirSync(`${configDir}/certs`);
        }

        return configDir;
    },

    getCertDirectory: () => {
        const configDir = module.exports.getConfigDirectory();
        const certDir = `${configDir}/certs`;

        if (!fs.existsSync(certDir)) {
            fs.mkdirSync(certDir);
        }

        return certDir;
    },

    resolveHostnameToIP: (hostname) => {
        return new Promise((resolve, reject) => {
            dns.lookup(hostname, (err, address) => {
                if (err)
                    reject(err);
                else
                {
                    resolve(address);
                }
            });
        });
    }
}
