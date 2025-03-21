const mdns = require('./mdns-discovery');
const config = require('./config');
const { handleClientConnection } = require('./connection'); // Import the function

const PORT = config.port;
const SERVICE_NAME = config.serviceName;
const SERVICE_TYPE = config.serviceType;

const peers = new Map();

console.log(`Starting agent with service name: ${SERVICE_NAME} on port ${PORT}`);
const serviceName = mdns.advertiseService(SERVICE_NAME, PORT);

console.log(`Finding peers for service type: ${SERVICE_TYPE}`);
const browser = mdns.findPeers(handlePeerDiscovered, handlePeerRemoved);

function handlePeerDiscovered(service)
{
    if (service.name === serviceName)
        return;

    console.log(`Peer discovered: ${service.name} on ${service.host}:${service.port}`);

    if (!peers.has(service.name))
    {
        peers.set(service.name, {
            name: service.name,
            host: service.host,
            port: service.port,
            service: service,
            discoveredAt: Date.now(),
            lastSeen: Date.now()
        });
    }

    console.log(`Total peers: ${peers.size}`);
}

function handlePeerRemoved(service)
{
    if (peers.has(service.name))
    {
        console.log(`Peer disconnected: ${service.name}`);
        peers.delete(service.name);
    }
}

function listAvailablePeers()
{
    if (peers.size === 0)
    {
        console.log('No peers available');
        return;
    }

    console.log('Available peers:');
    peers.forEach(peer => {
        console.log(`${peer.name} at ${peer.host}:${peer.port}`);
    });
}

process.on('SIGINT', () => {
    console.log('Shutting down agent');
    mdns.cleanupBonjour();
    process.exit(0);
});

function handleCommand(cmd)
{
    const [command, ...args] = cmd.trim().split(' ');

    switch(command.toLowerCase())
    {
        case 'list':
            listAvailablePeers();
            break;
        default:
            console.log('Unknown command');
            break;
    }
}

if (process.stdin.isTTY)
{
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', handleCommand);

    console.log('Enter a command (list)');
}
else
{
    console.log('No TTY available');
    return;
}