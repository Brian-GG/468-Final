const crypto = require('crypto');
const argon2 = require('argon2');

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
    }
}