const tls = require('tls');
const fs = require('fs');
const path = require('path');
const utils = require('./utils');
const { readConfig } = require('./state');
const { scanFileVault } = require('./storage');

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

  const server = tls.createServer(options, (socket) => {
    socket.on('data', (data) => {
        let json = JSON.parse(data.toString());
        switch (json.type)
        {
            case 'PEER_CONNECTED':
                console.log(`${json.data.peerName} has added you as a trusted peer.`);
                break;
            case 'REQUEST_FILES':
                console.log('Received REQUEST_FILES');
                let files = scanFileVault();
                socket.write(JSON.stringify({ type: 'FILES_LIST', data: { files } }));
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

module.exports = {
    handleClientConnection,
    handleServerCreation,
    sendMessageToPeer
}
