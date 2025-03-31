const tls = require('tls');
const fs = require('fs');
const path = require('path');
const utils = require('./utils');
const { readConfig } = require('./state');
const { scanFileVault, decryptFile } = require('./storage');
const { confirm } = require('@inquirer/prompts');

const config = readConfig();

function handleServerCreation() {
  const certDir = utils.getCertDirectory();

  const options = {
    key: fs.readFileSync(path.join(certDir, 'server.key')),
    cert: fs.readFileSync(path.join(certDir, 'server.crt')),
    ca: fs.readFileSync(path.join(certDir, 'ca.crt')),
    requestCert: true,
    rejectUnauthorized: false,
    ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
    honorCipherOrder: true
  };

  const server = tls.createServer(options, async (socket) => {
    socket.on('data', async (data) => {
        let json = JSON.parse(data.toString());
        switch (json.type)
        {
            case 'PEER_CONNECTED':
                console.log(`${json.data.peerName} has added you as a trusted peer.`);
                break;
            case 'REQUEST_FILES_LIST':
                let files = scanFileVault();
                socket.write(JSON.stringify({ type: 'FILES_LIST', data: { files } }));
                break;
            case 'REQUEST_FILE':
                let peerName = json.data.peerName;
                let fileName = json.data.fileName;
                const confirmation = await confirm({ message: `${peerName} is requesting the file ${fileName}. Do you want to send it?` });
                if (confirmation)
                {
                    try
                    {
                        let filePath = path.join(utils.getFileVaultDirectory(), fileName);
                        if (!fs.existsSync(filePath))
                        {
                            socket.write(JSON.stringify({ type: 'FILE_NOT_FOUND', data: { fileName, peerName } }));
                            break;
                        }
                        
                        let decryptedBuffer = await decryptFile(fileName, config.derivedKey);
                        if (!decryptedBuffer)
                        {
                            socket.write(JSON.stringify({ type: 'FILE_DECRYPTION_FAILED', data: { fileName, peerName } }));
                            break;
                        }
                        
                        const fileHash = crypto.createHash('sha256').update(decryptedBuffer).digest('hex');
                        const fileSize = decryptedBuffer.length;

                        socket.write(JSON.stringify({ type: 'FILE_METADATA', data: { fileName, fileHash, fileSize, peerName } }));

                        setTimeout(() => {
                            socket.write(decryptedBuffer);
                        }, 100);
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
            default:
                console.log('Unknown message type:', json.type);
                break;
        }
    });

    socket.on('end', () => {
        console.log('Client disconnected');
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
            rejectUnauthorized: false,
            ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
            honorCipherOrder: true
        };

        const connectionTimeout = setTimeout(() => {
            console.error('Connection timed out');
            socket.destroy();
            reject(new Error('Connection timed out'));
        }, timeout);

        const socket = tls.connect(options, () => {
            clearTimeout(connectionTimeout);
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
            rejectUnauthorized: false,
            ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
            honorCipherOrder: true
        };

        const connectionTimeout = setTimeout(() => {
            reject('Connection timed out');
        }, timeout);

        let responseData = '';

        const socket = tls.connect(options);

        socket.on('connect', () => {
            clearTimeout(connectionTimeout);
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
            });
            socket.end();
        });

        socket.on('data', (data) => {
            responseData += data.toString();
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
            rejectUnauthorized: false,
            ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
            honorCipherOrder: true
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
            
            const request = JSON.stringify({
                type: 'REQUEST_FILE',
                data: { fileName, peerName }
            });
            
            socket.write(request);
        });

        socket.on('data', (data) => {
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
                    isReceivingFile = false;
                
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
                        console.log(`Receiving ${fileMetadata.fileName} (${fileMetadata.fileSize} bytes)`);
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
                if (fileMetadata.fileHash)
                {
                    const receivedHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
                    
                    if (receivedHash !== fileMetadata.fileHash)
                    {
                        reject(new Error('File integrity verification failed'));
                        return;
                    }
                }
                
                resolve({
                    type: 'FILE_RECEIVED',
                    data: {
                        fileName: fileMetadata.fileName,
                        fileBuffer,
                        fileSize: fileBuffer.length
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

module.exports = {
    handleClientConnection,
    handleServerCreation,
    sendMessageToPeer,
    handleRequestFileFromPeer
}
