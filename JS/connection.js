const tls = require('tls');
const fs = require('fs');
const path = require('path');
const config = require('./config');
const utils = require('./utils');

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
        console.log(`Received: ${data.toString()}`);
    });

    socket.on('end', () => {
        console.log('Client disconnected');
    });

    socket.on('error', (err) => {
        console.error('Socket error:', err);
    });
  });

  server.listen(config.port, () => {
    console.log(`Server listening on port ${config.port}`);
  });

  server.on('tlsClientError', (err) => {
    console.error('Client authentication error:', err);
  });
}

async function handleClientConnection(host, port) {
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

        const socket = tls.connect(options, () => {
            console.log('Client connected to server (TLS connection success)');  // Now TLS authenticated

            socket.write('Hello from client\n', (err) => {
                if (err) {
                    console.error("Error writing to socket: ", err);
                    socket.destroy();
                    reject(err);
                    return;
                }
            });
            resolve(socket); // Resolve the promise on successful connection, no error at write time.

        });

        socket.on('data', (data) => {
            console.log(`Received: ${data.toString()}`);
            socket.end();
        });
        socket.on('end', () => {
            console.log('Connection closed');
        });

        socket.on('error', (err) => {
            console.error('Socket error:', err);
            reject(err); // Reject the promise if the error occurred during the connection
        });

    });
}

module.exports = {
    handleClientConnection,
    handleServerCreation
}
