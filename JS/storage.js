const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { getFileVaultDirectory } = require("./utils");
const { readConfig, saveConfig } = require('./state');
const secureContext = require('./secureContext');
const mdns = require('./mdns-discovery');

const ALGORITHM = 'aes-128-cbc';
const KEY_LENGTH = 32;
const IV_LENGTH = 16;

module.exports = {
    scanFileVault: async () => {
        const fileVaultDir = getFileVaultDirectory();
        const fileList = [];
        const config = readConfig();

        if (!config.fileMetadata)
            config.fileMetadata = {};
        
        // Ensure directory exists
        if (!fs.existsSync(fileVaultDir))
        {
            fs.mkdirSync(fileVaultDir, { recursive: true });
            return fileList;
        }
        
        try
        {
            const files = fs.readdirSync(fileVaultDir);
            
            for (const file of files)
            {
                const filePath = path.join(fileVaultDir, file);
                try
                {
                    const stats = fs.statSync(filePath);
                    
                    // Ignore system files - usually hidden files
                    if (file.startsWith('.'))
                        continue;
                    
                    if (!file.endsWith('.enc'))
                    {
                        try
                        {
                            const fileContent = fs.readFileSync(filePath);
                            const fileHash = crypto.createHash('sha256').update(fileContent).digest('hex');

                            if (!config.fileMetadata[fileHash])
                            {
                                config.fileMetadata[fileHash] = {
                                    name: file,
                                    size: stats.size,
                                    createdAt: Date.now(),
                                    sourceEntity: config.userId
                                };
                            }

                            let derivedKey = secureContext.getKey();
                            const { encryptedFile, iv, authTag } = encryptFile(fileContent, derivedKey);
                            
                            const encryptedFilePath = `${filePath}.enc`;
                            const metadata = JSON.stringify({ iv, authTag });
                            fs.writeFileSync(encryptedFilePath, `${metadata}\n\n\n${encryptedFile}`, 'utf8');
                            fs.unlinkSync(filePath);
                            
                            fileList.push({
                                name: file,
                                hash: fileHash,
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
                        const originalName = file.slice(0, -4);
                        try
                        {
                            const derivedKey = secureContext.getKey();
                            const decrypted = await module.exports.decryptFile(file, derivedKey);

                            if (decrypted)
                            {
                                const hash = crypto.createHash('sha256').update(decrypted).digest('hex');
                                if (!config.fileMetadata[hash])
                                {
                                    config.fileMetadata[hash] = {
                                        name: file,
                                        size: stats.size,
                                        createdAt: Date.now(),
                                        sourceEntity: config.userId
                                    };
                                }
                                fileList.push({
                                    name: originalName,
                                    hash: hash,
                                    encryptedName: file,
                                    size: stats.size,
                                });
                            }
                            else
                            {
                                console.error(`Failed to decrypt file ${file}`);
                            }
                        }
                        catch (err)
                        {
                            console.error(`Error decrypting file ${file}:`, err);
                        }

                    }

                    saveConfig(config);
                }
                catch (error)
                {
                    console.error(`Error processing file ${file}:`, error);
                }
            }
        }
        catch (error)
        {
            console.error('Error scanning file vault directory:', error);
        }
        
        return fileList;
    },

    decryptFile: async (fileName, derivedKey, writeToDirectory=false) => {
        try {
            const fileVaultDir = getFileVaultDirectory();
            const filePath = path.join(fileVaultDir, `${fileName}`);
            
            if (!fs.existsSync(filePath))
            {
                console.error(`File does not exist: ${filePath}`);
                return null;
            }
            
            const fileContent = fs.readFileSync(filePath, 'utf8');
            if (!fileContent || fileContent.trim() === '')
            {
                console.error(`Empty file: ${filePath}`);
                return null;
            }
            
            const parts = fileContent.split('\n\n\n');
            if (parts.length < 2)
            {
                console.error(`Invalid file format (missing separator): ${filePath}`);
                return null;
            }
            
            const [metadata, encryptedFile] = parts;
            
            try
            {
                const { iv, authTag } = JSON.parse(metadata);
                
                if (!iv || !authTag)
                {
                    console.error(`Missing required fields in metadata: ${filePath}`);
                    return null;
                }
                
                const decipher = crypto.createDecipheriv(ALGORITHM, derivedKey.substring(0, KEY_LENGTH), Buffer.from(iv, 'hex'));
                decipher.setAuthTag(Buffer.from(authTag, 'hex'));
                
                try
                {
                    let decrypted = Buffer.concat([
                        decipher.update(Buffer.from(encryptedFile, 'hex')), 
                        decipher.final()
                    ]);
                    
                    if (writeToDirectory)
                    {
                        if (fileName.endsWith('.enc'))
                            fileName = fileName.slice(0, -4);
                        const decryptedFilePath = path.join(fileVaultDir, fileName);
                        fs.writeFileSync(decryptedFilePath, decrypted);
                        fs.unlinkSync(`${filePath}.enc`);
                    }
                    return decrypted;
                }
                catch (decryptError)
                {
                    console.error(`Decryption error (possibly wrong key): ${filePath}`, decryptError);
                    return null;
                }
            }
            catch (jsonError)
            {
                console.error(`Invalid metadata JSON: ${filePath}`, jsonError);
                return null;
            }
        }
        catch (error)
        {
            console.error(`Error in decryptFile for ${fileName}:`, error);
            return null;
        }
    },

    writeToVault: async (fileName, fileContent, autoEncrypt=true) => {
        const fileVaultDir = getFileVaultDirectory();
        const filePath = path.join(fileVaultDir, fileName);

        if (Buffer.isBuffer(fileContent))
            fs.writeFileSync(filePath, fileContent);
        else
        {
            fs.writeFileSync(filePath, fileContent, 'utf8');
        }
        
        if (autoEncrypt) {
            const config = readConfig();
            try
            {
                let derivedKey = secureContext.getKey();
                const { encryptedFile, iv, authTag } = await encryptFile(fileContent, derivedKey);
                const encryptedFilePath = `${filePath}.enc`;
    
                const metadata = JSON.stringify({ iv, authTag });
                fs.writeFileSync(encryptedFilePath, `${metadata}\n\n\n${encryptedFile}`, 'utf8');
                fs.unlinkSync(filePath);
                
                return true;
            }
            catch (error)
            {
                console.error(`Error encrypting file ${fileName}:`, error);
                return false;
            }
        }

        return true;
    },

    findAlternativeFileSources: async (fileHash) => {
        const config = readConfig();
        if (!config.fileMetadata || !config.fileMetadata[fileHash])
        {
            return null;
        }

        const fileMetadata = config.fileMetadata[fileHash];
        const alternatives = [];

        const activePeers = mdns.getPeers();

        if (config.trustedPeers)
        {
            const peerNames = Object.keys(config.trustedPeers);
            for (let i = 0; i < peerNames.length; i++)
            {
                const peerName = peerNames[i];
                const peer = config.trustedPeers[peerName];
                if (peer.name == `SecureShare-${fileMetadata.sourceEntity}`)
                {
                    continue;
                }

                const isOnline = activePeers.has(peer.name) ? true : false;
                if (!isOnline)
                {
                    continue;
                }

                const { sendMessageToPeer } = require('./connection');

                try
                {
                    const response = await sendMessageToPeer(peer.host, peer.port, 'REQUEST_FILES_LIST', { peerName: config.serviceName });

                    if (response && response.data?.files)
                    {
                        const matchingFile = response.data.files.find(f => f.hash == fileHash);
                        if (matchingFile)
                        {
                            alternatives.push({
                                peerName: peer.name,
                                fileName: fileMetadata.name,
                                size: fileMetadata.size,
                                host: peer.host,
                                port: peer.port
                            });
                        }
                    }
                }
                catch (err)
                {
                    console.error(`Error requesting file list from peer ${peer.name}:`, err);
                }
            }
        }

        return alternatives;
    }
}

function encryptFile(file, derivedKey)
{
    const data = Buffer.isBuffer(file) ? file : Buffer.from(file);

    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, derivedKey.substring(0, KEY_LENGTH), iv);
    
    const encryptedBuffer = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return { encryptedFile: encryptedBuffer.toString('hex'), iv: iv.toString('hex'), authTag: authTag.toString('hex') };
}