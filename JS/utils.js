const crypto = require('crypto');
const argon2 = require('argon2');
const os = require('os');
const fs = require('fs');
const dns = require('dns');
const path = require('path');

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

        const lines = publicKey.split('\n');
        const keyLines = lines.filter(line => !line.startsWith('-----'));
        const publicKeyStripped = keyLines.join('');

        const configDir = module.exports.getConfigDirectory();
        fs.writeFileSync(path.join(configDir, 'client_public.pem'), publicKeyStripped);

        return { publicKey, privateKey };
    },

    encryptPrivateKey: async (privateKey, derivedKey) => {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, derivedKey.substring(0, KEY_LENGTH), iv);
        let encrypted = cipher.update(privateKey, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();

        return { encryptedPrivateKey: encrypted, iv: iv.toString('hex'), authTag: authTag.toString('hex') };
    },

    decryptPrivateKey: async (encryptedPrivateKey, derivedKey, iv, authTag) => {
        const decipher = crypto.createDecipheriv(ALGORITHM, derivedKey.substring(0, KEY_LENGTH), Buffer.from(iv, 'hex'));
        decipher.setAuthTag(Buffer.from(authTag, 'hex'));
        let decrypted = decipher.update(encryptedPrivateKey, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    },

    generateSalt: () => {
        return crypto.randomBytes(32).toString('hex');
    },

    /**
     * For our application, TLS required the creation of a root CA to
     * sign the server and client certificates. Since it is not feasible to force the
     * `openssl` library to remove randomness from the CA certificate generation process
     * (in version 3.0.2), we are using a pre-generated CA key and certificate.
     * 
     * In a real world scenario, the CA certificate would be securely derived/provided with
     * the application.
     */
    placeRootCACert: () => {
        const certDir = module.exports.getCertDirectory();

        const caKeyPath = path.join(__dirname, 'ca.key');
        if (!fs.existsSync(caKeyPath))
        {
            console.error(`CA key not found at ${caKeyPath}`);
            return;
        }
        fs.copyFileSync(caKeyPath, path.join(certDir, 'ca.key'));

        const caCrtPath = path.join(__dirname, 'ca.crt');
        if (!fs.existsSync(caCrtPath))
        {
            console.error(`CA certificate not found at ${caCrtPath}`);
            return;
        }
        fs.copyFileSync(caCrtPath, path.join(certDir, 'ca.crt'));
    },

    createServerCert: (ip, options = {}) => {
        const { ciphers } = options;

        if (ciphers) {
            console.log(`Using ciphers: ${ciphers}`);
        }

        const certDir = module.exports.getCertDirectory();
        const hostname = os.hostname();
        runOSCommand(`openssl genpkey -algorithm Ed25519 -out ${path.join(certDir, 'server.key')}`);
        runOSCommand(`openssl req -new -key ${path.join(certDir, 'server.key')} -out ${path.join(certDir, 'server.csr')} -subj "/CN=${ip}"`);
        
        // Create a configuration file for server certificate with ciphers if specified
        const serverCnfPath = path.join(certDir, 'server.cnf');
        let serverExtConfig = `
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${ip}

[v3_req]
subjectAltName = IP:${ip},IP:127.0.0.1,DNS:${hostname}
`;

        // Add SSL options with ciphers if specified
        if (ciphers)
        {
            serverExtConfig += `
[ssl_sect]
CipherString = ${ciphers}
`;
        }

        fs.writeFileSync(serverCnfPath, serverExtConfig);
        
        // Use the configuration file for certificate generation
        runOSCommand(`openssl x509 -req -in ${path.join(certDir, 'server.csr')} -CA ${path.join(certDir, 'ca.crt')} -CAkey ${path.join(certDir, 'ca.key')} -CAcreateserial -out ${path.join(certDir, 'server.crt')} -days 365 -extfile ${serverCnfPath} -extensions v3_req`);
    },

    createClientCert: (options = {}) => {
        const { ciphers } = options;

        if (ciphers) {
            console.log(`Using ciphers: ${ciphers}`);
        }

        const certDir = module.exports.getCertDirectory();
        
        runOSCommand(`openssl genpkey -algorithm Ed25519 -out ${path.join(certDir, 'client.key')}`);
        
        // Create a configuration file for client certificate with ciphers if specified
        const clientCnfPath = path.join(certDir, 'client.cnf');
        let clientExtConfig = `
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = P2PAgentClient

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
`;

        // Add SSL options with ciphers if specified
        if (ciphers)
        {
            clientExtConfig += `
[ssl_sect]
CipherString = ${ciphers}
`;
        }

        fs.writeFileSync(clientCnfPath, clientExtConfig);
        
        // Use the config file for CSR and certificate generation
        runOSCommand(`openssl req -new -key ${path.join(certDir, 'client.key')} -out ${path.join(certDir, 'client.csr')} -config ${clientCnfPath}`);
        runOSCommand(`openssl x509 -req -in ${path.join(certDir, 'client.csr')} -CA ${path.join(certDir, 'ca.crt')} -CAkey ${path.join(certDir, 'ca.key')} -CAcreateserial -out ${path.join(certDir, 'client.crt')} -days 365 -extfile ${clientCnfPath} -extensions v3_req`);
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

    getFileVaultDirectory: () => {
        const configDir = module.exports.getConfigDirectory();
        const fileVaultDir = `${configDir}/file_vault`;

        if (!fs.existsSync(fileVaultDir)) {
            fs.mkdirSync(fileVaultDir);
        }

        return fileVaultDir;
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
    },

    createSha256Hash: (data) => {
        const hash = crypto.createHash('sha256');
        hash.update(data);
        return hash.digest('hex');   
    },

    signData: (data, privateKey) => {
        const signature = crypto.sign(null, 
            Buffer.isBuffer(data) ? data : Buffer.from(data), 
            privateKey);
        return signature.toString('hex');
    },

    verifySignature: (data, signature, publicKey) => {
        return crypto.verify(
            null, 
            Buffer.isBuffer(data) ? data : Buffer.from(data),
            publicKey, 
            Buffer.from(signature, 'hex')
        );
    },

    deriveKeyFromPassword: async (password, salt) => {
        const derivedKey = await argon2.hash(password, { ...ARGON2_OPTIONS, salt: Buffer.from(salt, 'hex') });
        return derivedKey;
    }
}
