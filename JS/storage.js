const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const argon2 = require('argon2');
const { password } = require('@inquirer/prompts');
const { getFileVaultDirectory } = require("./utils");
const { readConfig } = require('./state');

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
    scanFileVault: () => {
        const fileVaultDir = getFileVaultDirectory();
        const files = fs.readdirSync(fileVaultDir);
        const fileList = [];
        const config = readConfig();

        files.forEach(file => {
            const filePath = path.join(fileVaultDir, file);
            const stats = fs.statSync(filePath);

            if (!file.endsWith('.enc'))
            {
                const fileContent = fs.readFileSync(filePath, 'utf8');
                try
                {
                    const { encryptedFile, iv, authTag } = encryptFile(fileContent, config.derivedKey);
                    const encryptedFilePath = `${filePath}.enc`;

                    const metadata = JSON.stringify({ iv, authTag });
                    fs.writeFileSync(encryptedFilePath, `${metadata}\n\n\n${encryptedFile}`, 'utf8');
                    fs.unlinkSync(filePath);

                    fileList.push({
                        name: file,
                        size: stats.size,
                        iv,
                        authTag
                    });
                }
                catch (error)
                {
                    console.error(`Error encrypting file ${file}:`, error);
                }
            }
            else
            {
                const metadata = fs.readFileSync(filePath, 'utf8').split('\n\n\n')[0];
                const { iv, authTag } = JSON.parse(metadata);
                fileList.push({
                    name: file,
                    size: stats.size,
                    iv,
                    authTag
                });
            }
        });

        return fileList;
    }
}

async function encryptFile(file, derivedKey)
{
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, derivedKey.substring(0, KEY_LENGTH), iv);
    let encrypted = cipher.update(file, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return { encryptedFile: encrypted, iv: iv.toString('hex'), authTag: authTag.toString('hex') };
}