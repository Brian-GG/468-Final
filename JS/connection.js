const tls = require('tls');
const fs = require('fs');
const path = require('path');

const options = {
  key: fs.readFileSync(path.join(__dirname, 'client-key.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'client-cert.pem')),
  ca: fs.readFileSync(path.join(__dirname, 'ca-cert.pem')),
  requestCert: true,
  rejectUnauthorized: true
};

function handleServerCreation()
{
  
  const server = tls.createServer(options, (socket) => {
    const clientCert = socket.getPeerCertificate();
  
    if (clientCert && clientCert.subject)
    {
      console.log(`Client connected: ${clientCert.subject.CN}`);
    }
    else
    {
      console.log('Client did not provide a certificate.');
      socket.end('Unauthorized: No certificate provided');
    }
  
    socket.end('Welcome!');
  });
}

function handleClientConnection(host, port)
{
  const connectionOpts = { ...options, host, port };

  const socket = tls.connect(connectionOpts, () => {
    if (!socket.authorized)
    {
      console.log('Connection not authorized');
      socket.end(); socket.destroy();
      return;
    }
  });

  socket.on('data', (data) => {
    console.log(`Received: ${data.toString()}`);
  });

  socket.on('end', () => {
    console.log('Connection closed');
  });

  socket.on('error', (err) => {
    console.error(err);
  });
}