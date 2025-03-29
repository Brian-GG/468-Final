const tls = require('tls');
const fs = require('fs');
const path = require('path');
const { getCertDirectory } = require('./utils');
const config = require('./config');

function handleServerCreation()
{
  const certDir = getCertDirectory();
  const options = {
    key: fs.readFileSync(path.join(certDir, 'server.key')),
    cert: fs.readFileSync(path.join(certDir, 'server.crt')),
    ca: [fs.readFileSync(path.join(certDir, 'ca.crt'))],
    requestCert: true,
    rejectUnauthorized: false
  };

  const server = tls.createServer(options, (socket) => {
    const clientCert = socket.getPeerCertificate();
  
    if (socket.authorized)
    {
      console.log('Client authorized');
    }
    else
    {
      console.log('Client not authorized');
      socket.end('Unauthorized: Invalid certificate');
      socket.destroy();
      return;
    }
    
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
  const certDir = getCertDirectory();
  const options = {
    host,
    port,
    key: fs.readFileSync(path.join(certDir, 'client.key')),
    cert: fs.readFileSync(path.join(certDir, 'client.crt')),
    ca: [fs.readFileSync(path.join(certDir, 'ca.crt'))],
    rejectUnauthorized: false
  };

  return new Promise((resolve, reject) => {
    const socket = tls.connect(options, () => {
      if (!socket.authorized) {
        console.log('Connection not authorized', socket.authorizationError);
        socket.destroy();
        reject (new Error(`TLS Connection not authorized: ${socket.authorizationError}`));
        return;
      }

      console.log('Client connected to server (mTLS auth success)');  //Now mTLS authenticated

      socket.write('Hello from client\n', (err) => {
          if(err) {
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
