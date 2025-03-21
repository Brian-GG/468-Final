const mdns = require('./mdns-discovery');
const config = require('./config');
const { readConfig, saveConfig } = require('./state');
const readline = require('readline');

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

function checkFirstUse()
{
    const config = readConfig();

    if (config.isFirstRun)
    {
        // generate public/private keypair here
        console.log('First run detected');
        
        config.isFirstRun = false;
        saveConfig(config);
    }

    if (!config.password || config.password.length === 0)
    {
        console.log('Please set a password for this agent');
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout,
            terminal: true
        });
        
        rl.question('Enter password: ', (password) => {
            config.password = password;
            saveConfig(config);
            console.log('Password set successfully');
            rl.close();
            console.log('Welcome back! Enter a command (list)');
            process.stdin.setEncoding('utf-8');
            process.stdin.on('data', handleCommand);
        });
    }
    else
    {
        console.log('Welcome back! Enter a command (list)');
        process.stdin.setEncoding('utf-8');
        process.stdin.on('data', handleCommand);
    }
}

if (process.stdin.isTTY)
{
    checkFirstUse();
}
else
{
    console.log('No TTY available');
    return;
}