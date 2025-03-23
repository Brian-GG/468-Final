const tls = require('tls');
const fs = require('fs');
const path = require('path');
const { getCertDirectory } = require('./utils');

function handleServerCreation()
{
  const options = {
    key: fs.readFileSync(path.join(getCertDirectory(), 'server.key')),
    cert: fs.readFileSync(path.join(getCertDirectory(), 'server.crt')),
    ca: fs.readFileSync(path.join(getCertDirectory(), 'ca.crt')),
    requestCert: true,
    rejectUnauthorized: true
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

  server.listen(8443, () => {
    console.log('Server listening on port 8443');
  });
  
  server.on('tlsClientError', (err) => {
    console.error('Client authentication error:', err);
    if (socket)
      socket.destroy();
  });
}

function handleClientConnection(host, port)
{
  const options = {
    host,
    port,
    key: fs.readFileSync(path.join(getCertDirectory(), 'client.key')),
    cert: fs.readFileSync(path.join(getCertDirectory(), 'client.crt')),
    ca: [fs.readFileSync(path.join(getCertDirectory(), 'ca.crt'))],
    rejectUnauthorized: true
  };

  const socket = tls.connect(options, () => {
    if (!socket.authorized)
    {
      console.log('Connection not authorized');
      socket.end(); socket.destroy();
      return;
    }

    console.log('Client connected to server');
    socket.write('Hello from client');
  });

  socket.on('data', (data) => {
    console.log(`Received: ${data.toString()}`);
    socket.end(); socket.destroy();
  });

  socket.on('end', () => {
    console.log('Connection closed');
  });

  socket.on('error', (err) => {
    console.error(err);
  });
}

module.exports = {
  handleClientConnection,
  handleServerCreation
}