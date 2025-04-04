const tls = require('tls');
const fs = require('fs');
const path = require('path');
const utils = require('./utils');
const crypto = require('crypto');
const { readConfig, saveConfig } = require('./state');
const { scanFileVault, decryptFile } = require('./storage');
const { confirm, password } = require('@inquirer/prompts');
const secureContext = require('./secureContext');
const { getPeers } = require('./mdns-discovery');

function handleServerCreation() {
  const certDir = utils.getCertDirectory();
  const config = readConfig();
  const options = {
    key: fs.readFileSync(path.join(certDir, 'server.key')),
    cert: fs.readFileSync(path.join(certDir, 'server.crt')),
    ca: fs.readFileSync(path.join(certDir, 'ca.crt')),
    requestCert: true,
    rejectUnauthorized: true,
    ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256',
    honorCipherOrder: true,
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3'
  };

  const server = tls.createServer(options, async (socket) => {
    socket.on('data', async (data) => {
        let json = JSON.parse(data.toString());
        const config = readConfig();
        const configDir = utils.getConfigDirectory();

        switch (json.type)
        {
            case 'PEER_CONNECTED':
                let publicKey = fs.readFileSync(path.join(configDir, 'client_public.pem'), 'utf8');

                if (!config.trustedPeers[json.data.peerName])
                    config.trustedPeers[json.data.peerName] = {};
                config.trustedPeers[json.data.peerName] = {
                    name: json.data.peerName,
                    publicKey: json.data.publicKey,
                    lastConnected: Date.now()
                };
                saveConfig(config);

                socket.write(JSON.stringify({ type: 'WELCOME', data: { publicKey, keyRevocationList: config.keyRevocationList || [] } }));
                console.log(`${json.data.peerName} has added you as a trusted peer.`);
                break;
            case 'REQUEST_FILES_LIST':
                let files = await scanFileVault();
                socket.write(JSON.stringify({ type: 'FILES_LIST', data: { files } }));
                break;
            case 'REQUEST_FILE':
                let peerName = json.data.peerName;
                let fileName = json.data.fileName;
                let encryptedFileName = `${fileName}.enc`;

                const confirmation = await confirm({ message: `${peerName} is requesting the file ${fileName}. Do you want to send it?` });
                if (confirmation)
                {
                    try
                    {
                        let filePath = path.join(utils.getFileVaultDirectory(), encryptedFileName);
                        if (!fs.existsSync(filePath))
                        {
                            socket.write(JSON.stringify({ type: 'FILE_NOT_FOUND', data: { fileName, peerName } }));
                            break;
                        }
                        
                        let derivedKey = secureContext.getKey()
                        let decryptedBuffer = await decryptFile(encryptedFileName, derivedKey);
                        if (!decryptedBuffer)
                        {
                            socket.write(JSON.stringify({ type: 'FILE_DECRYPTION_FAILED', data: { fileName, peerName } }));
                            break;
                        }
                        
                        const fileHash = crypto.createHash('sha256').update(decryptedBuffer).digest('hex');
                        const fileSize = decryptedBuffer.length;

                        const decryptedPrivateKey = await utils.decryptPrivateKey(config.keypair.privateKey, derivedKey, config.keypair.iv, config.keypair.authTag);
                        const signature = utils.signData(fileHash, decryptedPrivateKey);

                        socket.write(JSON.stringify({ type: 'FILE_METADATA', data: { fileName, fileHash, fileSize, sourceEntity: config.userId, fileSignature: signature } }));

                        setTimeout(() => {
                            socket.write(decryptedBuffer);

                            setTimeout(() => {
                                socket.write('\n\n--FILE_TRANSFER_COMPLETE0--\n\n');
                                console.log(`File ${fileName} sent to ${peerName}`);
                            }, 100);
                        }, 1000);
                    }
                    catch (error)
                    {
                        console.error(`Error processing file ${fileName}:`, error);
                        socket.write(JSON.stringify({ type: 'FILE_ERROR', data: { fileName, peerName } }));
                    }
                }
                else
                {
                    socket.write(JSON.stringify({type: 'FILE_REQUEST_DECLINED', data: { fileName, peerName }}));
                }
                break;
            case 'KEY_REVOCATION':
                const migrationAnnouncement = json.data.migrationAnnouncement;
                const peerPublicKey = config.trustedPeers[migrationAnnouncement.oldUserId]?.publicKey;

                if (!peerPublicKey)
                {
                    // This peer doesn't have any info about the revoking peer. Will not propagate the message since it cannot verify.
                    break;
                }

                const isVerified = utils.verifySignature(JSON.stringify({
                    oldUserId: migrationAnnouncement.oldUserId,
                    newUserId: migrationAnnouncement.newUserId,
                    oldPublicKey: migrationAnnouncement.oldPublicKey,
                    newPublicKey: migrationAnnouncement.newPublicKey,
                    timestamp: migrationAnnouncement.timestamp
                }), migrationAnnouncement.signature, peerPublicKey);
                if (!isVerified)
                {
                    console.error('Signature verification failed for key revocation');
                    break;
                }

                if (!config.trustedPeers[migrationAnnouncement.newUserId])
                    config.trustedPeers[migrationAnnouncement.newUserId] = {};
                config.trustedPeers[migrationAnnouncement.newUserId] = {
                    name: migrationAnnouncement.newUserId,
                    publicKey: migrationAnnouncement.newPublicKey,
                    lastConnected: Date.now()
                };
                delete config.trustedPeers[migrationAnnouncement.oldUserId];
                
                config.keyRevocationList.push({
                    oldUserId: migrationAnnouncement.oldUserId,
                    newUserId: migrationAnnouncement.newUserId,
                    newPublicKey: migrationAnnouncement.newPublicKey,
                    timestamp: Date.now()
                });
                saveConfig(config);

                const peers = getPeers();
                for (const peerName in config.trustedPeers)
                {
                    const peer = peers.get(peerName);
                    if (peer && peer.name !== migrationAnnouncement.oldUserId && peer.name !== migrationAnnouncement.newUserId)
                    {
                        const _ = await sendMessageToPeer(peer.host, peer.port, 'KEY_REVOCATION', { migrationAnnouncement, ackNeeded: false });
                    }
                }
                console.log(`Key revocation request received from ${migrationAnnouncement.oldUserId}. Successfully migrated to ${migrationAnnouncement.newUserId}`);
                const clientPublicKey = fs.readFileSync(path.join(configDir, 'client_public.pem'), 'utf8');
                if (json.data && json.data.ackNeeded !== false)
                    socket.write(JSON.stringify({ type: 'KEY_REVOCATION_ACK', data: { peerName: config.serviceName, publicKey: clientPublicKey } }));
                break;
            default:
                console.log('Unknown message type:', json.type);
                break;
        }
    });

    socket.on('end', () => {
        // noop
    });

    socket.on('error', (err) => {
        console.error('Socket error:', err);
    });
  });

  server.listen(config.port, () => {});

  server.on('tlsClientError', (err) => {
    console.error('Client authentication error:', err);
  });
}

async function handleClientConnection(host, port, timeout=10000) {
    const certDir = utils.getCertDirectory();

    return new Promise((resolve, reject) => {
        const options = {
            host: host,
            port: port,
            key: fs.readFileSync(path.join(certDir, 'client.key')),
            cert: fs.readFileSync(path.join(certDir, 'client.crt')),
            ca: fs.readFileSync(path.join(certDir, 'ca.crt')),
            rejectUnauthorized: true,
            ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256',
            honorCipherOrder: true,
            minVersion: 'TLSv1.3',
            maxVersion: 'TLSv1.3'
        };

        const connectionTimeout = setTimeout(() => {
            console.error('Connection timed out');
            socket.destroy();
            reject(new Error('Connection timed out'));
        }, timeout);

        const socket = tls.connect(options, () => {
            clearTimeout(connectionTimeout);

            let safeToProceed = handleKRLValidation(peerName);
            if (!safeToProceed)
            {
                socket.end();
                return;
            }

            resolve(socket);
        });

        socket.on('error', (err) => {
            console.error('Socket error:', err);
            reject(err);
        });
    });
}

async function sendMessageToPeer(host, port, messageType, messageData={}, timeout=10000)
{
    const certDir = utils.getCertDirectory();

    return new Promise((resolve, reject) => {
        const options = {
            host: host,
            port: port,
            key: fs.readFileSync(path.join(certDir, 'client.key')),
            cert: fs.readFileSync(path.join(certDir, 'client.crt')),
            ca: fs.readFileSync(path.join(certDir, 'ca.crt')),
            rejectUnauthorized: true,
            ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256',
            honorCipherOrder: true,
            minVersion: 'TLSv1.3',
            maxVersion: 'TLSv1.3'
        };

        const connectionTimeout = setTimeout(() => {
            reject('Connection timed out');
        }, timeout);

        let responseData = '';

        const socket = tls.connect(options);

        socket.on('connect', () => {
            clearTimeout(connectionTimeout);

            let safeToProceed = handleKRLValidation(messageData.peerName);
            if (!safeToProceed)
            {
                socket.end();
                return;
            }

            const message = JSON.stringify({
                type: messageType,
                data: messageData
            });

            socket.write(message, (err) => {
                if (err)
                {
                    console.error('Error writing to socket:', err);
                    socket.destroy();
                    reject(err);
                }

                if (messageType === 'KEY_REVOCATION' && !messageData.ackNeeded)
                {
                    clearTimeout(connectionTimeout);
                    socket.end();
                }
            });
        });

        socket.on('data', (data) => {
            responseData += data.toString();
            try
            {
                const response = JSON.parse(responseData);
                clearTimeout(connectionTimeout);
                socket.end();
                resolve(response);
            }
            catch (err)
            {
                // noop
            }
            try
            {
                const response = JSON.parse(responseData);
                clearTimeout(connectionTimeout);
                socket.end();
                resolve(response);
            }
            catch (err)
            {
                // noop
            }
        });

        socket.on('end', () => {
            clearTimeout(connectionTimeout);
            socket.destroy();

            try
            {
                if (responseData)
                {
                    responseData = JSON.parse(responseData);
                    resolve(responseData);
                }
                else
                {
                    resolve(null);
                }
            }
            catch (err)
            {
                console.error('Error parsing response:', err);
                reject(err);
            }
        });

        socket.on('error', (err) => {
            console.error('Socket error:', err);
            socket.destroy();
            reject(err);
        });
    });
}

async function handleRequestFileFromPeer(host, port, fileName, peerName, timeout=30000)
{
    const certDir = utils.getCertDirectory();

    return new Promise((resolve, reject) => {
        const options = {
            host: host,
            port: port,
            key: fs.readFileSync(path.join(certDir, 'client.key')),
            cert: fs.readFileSync(path.join(certDir, 'client.crt')),
            ca: fs.readFileSync(path.join(certDir, 'ca.crt')),
            rejectUnauthorized: true,
            ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256',
            honorCipherOrder: true,
            minVersion: 'TLSv1.3',
            maxVersion: 'TLSv1.3'
        };

        const connectionTimeout = setTimeout(() => {
            socket.destroy();
            reject(new Error('Connection timed out'));
        }, timeout);

        let fileMetadata = null;
        let receivedBytes = 0;
        let fileBuffer = null;
        let responseJson = null;
        let isReceivingFile = false;

        const socket = tls.connect(options, () => {
            clearTimeout(connectionTimeout);

            let safeToProceed = handleKRLValidation(peerName);
            if (!safeToProceed)
            {
                socket.end();
                return;
            }

            const request = JSON.stringify({
                type: 'REQUEST_FILE',
                data: { fileName, peerName }
            });
            
            socket.write(request);
        });

        socket.on('data', (data) => {
            try
            {
                const strData = data.toString();
                if (strData.includes('FILE_TRANSFER_COMPLETE'))
                {
                    console.log('File transfer complete marker received');
                    isReceivingFile = false;
                    socket.end();
                    return;
                }
            } catch (e) {
                // Continue buffer handling
            }
            
            if (fileMetadata && isReceivingFile)
            {
                if (!fileBuffer)
                    fileBuffer = data;
                else
                {
                    fileBuffer = Buffer.concat([fileBuffer, data]);
                }
                
                receivedBytes += data.length;
                
                if (receivedBytes >= fileMetadata.fileSize)
                {
                    console.log('\nFile download complete!');
                    isReceivingFile = false;
                    socket.end();
                }
                
                return;
            }
            
            try
            {
                const jsonStr = data.toString();
                const response = JSON.parse(jsonStr);
                
                switch (response.type)
                {
                    case 'FILE_METADATA':
                        fileMetadata = response.data;
                        isReceivingFile = true;
                        break;
                    case 'FILE_REQUEST_DECLINED':
                    case 'FILE_NOT_FOUND':
                    case 'FILE_DECRYPTION_FAILED':
                    case 'FILE_ERROR':
                        responseJson = response;
                        socket.end();
                        break;
                    default:
                        console.log(`Unknown response type: ${response.type}`);
                        socket.end();
                        process.exit(1);
                        break;
                }
            }
            catch (e)
            {
                if (fileMetadata && !fileBuffer)
                {
                    fileBuffer = data;
                    receivedBytes = data.length;
                }
                else if (fileMetadata)
                {
                    fileBuffer = Buffer.concat([fileBuffer || Buffer.alloc(0), data]);
                    receivedBytes += data.length;
                }
                else
                {
                    console.error('Received non-JSON data before metadata');
                    socket.end();
                }
            }
        });

        socket.on('end', () => {
            clearTimeout(connectionTimeout);
            
            if (responseJson)
            {
                resolve(responseJson);
                return;
            }
            
            if (fileMetadata && fileBuffer)
            {
                console.log(`\nFile transfer complete. Received ${receivedBytes}/${fileMetadata.fileSize} bytes.`);
                
                if (fileMetadata.fileHash)
                {
                    console.log('Verifying file integrity...');
                    const receivedHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
                    
                    if (receivedHash !== fileMetadata.fileHash)
                    {
                        console.error('File integrity check failed!');
                        reject(new Error('File integrity verification failed'));
                        return;
                    }
                    
                    console.log('File integrity verified.');
                }
                
                const config = readConfig();
                if (fileMetadata.fileSignature)
                {
                    let peerPublicKey = config.trustedPeers[`SecureShare-${fileMetadata.sourceEntity}`].publicKey;
                    const isVerified = utils.verifySignature(fileMetadata.fileHash, fileMetadata.fileSignature, peerPublicKey);
                    if (!isVerified)
                    {
                        console.error('File signature verification failed!');
                        reject(new Error('File signature verification failed'));
                        return;
                    }
                    console.log('File signature verified.');
                }

                config.fileMetadata[fileMetadata.fileHash] = {
                    fileName: fileMetadata.fileName,
                    fileSize: fileBuffer.length,
                    fileHash: fileMetadata.fileHash,
                    sourceEntity: fileMetadata.sourceEntity,
                    receivedFrom: peerName,
                }
                saveConfig(config);
                
                resolve({
                    type: 'FILE_RECEIVED',
                    data: {
                        fileName: fileMetadata.fileName,
                        fileContent: fileBuffer,
                        fileSize: fileBuffer.length,
                        fileHash: fileMetadata.fileHash,
                        sourceEntity: fileMetadata.sourceEntity,
                    }
                });
            }
            else
            {
                reject(new Error('Incomplete file transfer'));
            }
        });

        socket.on('error', (err) => {
            clearTimeout(connectionTimeout);
            console.error('Socket error:', err);
            reject(err);
        });
    });
}

function handleKRLValidation(peerName)
{
    const config = readConfig();

    if (!config.keyRevocationList || !Array.isArray(config.keyRevocationList))
        return true;

    const isRevoked = config.keyRevocationList.some(entry => entry.oldUserId === peerName);
    if (isRevoked)
    {
        console.log(`Peer ${peerName} has revoked their key. You may not communicate until re-trusted.`);
        return false;
    }
    else
    {
        return true;
    }
}

module.exports = {
    handleClientConnection,
    handleServerCreation,
    sendMessageToPeer,
    handleRequestFileFromPeer
}
