const mdns = require('./mdns-discovery');
const config = require('./config');
const { readConfig, saveConfig } = require('./state');
const { input, password } = require('@inquirer/prompts');
const { generateKeyPair, generateSalt, encryptPrivateKey, createRootCACert, createServerCert, createClientCert, getLocalIPv4Address } = require('./utils');
const { handleServerCreation } = require('./connection');

const PORT = config.port;
const SERVICE_NAME = config.serviceName;
const SERVICE_TYPE = config.serviceType;

const peers = new Map();

function initAgent()
{
    console.log(`Starting agent with service name: ${SERVICE_NAME} on port ${PORT}`);
    const serviceName = mdns.advertiseService(SERVICE_NAME, PORT);
    
    console.log(`Finding peers for service type: ${SERVICE_TYPE}`);
    const browser = mdns.findPeers(handlePeerDiscovered, handlePeerRemoved);

    process.on('SIGINT', () => {
        console.log('\nShutting down agent');
        mdns.cleanupBonjour();
        process.exit(0);
    });

    return [serviceName, browser];
}

function handlePeerDiscovered(service)
{
    if (service.name === SERVICE_NAME)
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

async function handleCommands()
{
    console.log(`P2P FILE SHARING APP\n\nAvailable commands: list`);
    
    while (true)
    {
        const menuOpt = await input({message: `Please enter a command: `});
        const command = menuOpt;
        
        switch(command.toLowerCase())
        {
            case 'list':
                listAvailablePeers();
                break;
            case 'exit':
                console.log('Goodbye!');
                mdns.cleanupBonjour();
                process.exit(0);
            default:
                console.log('Unknown command');
                break;
        }
    }
}

async function validatePrerequisites()
{
    const config = readConfig();

    if (config.isFirstRun || !config.keypair)
    {
        console.log('First run detected');
        const { publicKey, privateKey } = generateKeyPair();
        
        console.log('You must set a passphrase to encrypt your downloaded files. Make sure you remember this!\nIf you forget, you will lose access to your files!');
        const userPassphrase = await password({ message: 'Enter password: ' });
        const userPassphraseConfirm = await password({ message: 'Confirm password: ' });

        if (userPassphrase !== userPassphraseConfirm)
        {
            console.log('Passwords do not match. Exiting...');
            process.exit(1);
        }

        const salt = generateSalt();
        const encryptedResults = await encryptPrivateKey(privateKey, userPassphraseConfirm, salt);

        config.keypair = {
            publicKey: publicKey,
            privateKey: encryptedResults.encryptedPrivateKey,
            iv: encryptedResults.iv,
            authTag: encryptedResults.authTag,
            salt: salt
        }

        const localIP = getLocalIPv4Address();

        createRootCACert();
        createServerCert(localIP);
        createClientCert();

        config.isFirstRun = false;
        saveConfig(config);
    }

    
    let [serviceName, browser] = initAgent();
    handleServerCreation(); // Start the server
    await handleCommands();
}

if (process.stdin.isTTY)
{
    validatePrerequisites();
}
else
{
    console.log('No TTY available');
    return;
}