const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { getFileVaultDirectory } = require("./utils");
const { readConfig } = require('./state');

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 16;

module.exports = {
    scanFileVault: () => {
        const fileVaultDir = getFileVaultDirectory();
        const fileList = [];
        const config = readConfig();
        
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
                        const originalName = file.slice(0, -4); // Remove .enc extension
                        fileList.push({
                            name: originalName,
                            encryptedName: file,
                            size: stats.size
                        });
                    }
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

    decryptFile: async (fileName, derivedKey) => {
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
                const { encryptedFile, iv, authTag } = await encryptFile(fileContent, config.derivedKey);
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