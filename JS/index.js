process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0;
const mdns = require('./mdns-discovery');
const { readConfig, saveConfig } = require('./state');
const { input, password, confirm } = require('@inquirer/prompts');
const { generateKeyPair, generateSalt, encryptPrivateKey, createRootCACert, createServerCert, createClientCert, getLocalIPv4Address, resolveHostnameToIP } = require('./utils');
const { handleServerCreation, handleClientConnection } = require('./connection');
const { scanFileVault } = require('./storage');

var PORT;
var SERVICE_NAME;
var SERVICE_TYPE;

const peers = new Map();
let files = [];

function initAgent()
{
    console.log(`Starting agent with service name: ${SERVICE_NAME} on port ${PORT}`);
    const serviceName = mdns.advertiseService(SERVICE_NAME, PORT);
    
    console.log(`Finding peers for service type: ${SERVICE_TYPE}`);
    const browser = mdns.findPeers(handlePeerDiscovered, handlePeerRemoved);

    files = scanFileVault();

    setInterval(() => {
        files = scanFileVault();
        console.log(`Files in vault: ${files.length}`);
    }, 30 * 1000);

    process.on('SIGINT', () => {
        console.log('\nShutting down agent');
        mdns.cleanupBonjour();
        process.exit(0);
    });

    return [serviceName, browser];
}

async function handlePeerDiscovered(service)
{
    if (service.name === SERVICE_NAME)
        return;

    try
    {
        const ip = await resolveHostnameToIP(service.host);
        console.log(`Peer discovered: ${service.name} on ${ip}:${service.port}`);

        if (!peers.has(service.name))
        {
            peers.set(service.name, {
                name: service.name,
                host: ip,
                port: service.port,
                service: service,
                discoveredAt: Date.now(),
                lastSeen: Date.now()
            });
        }

        console.log(`Total peers: ${peers.size}`);
    } 
    catch (err)
    {
        console.error(`Failed to resolve hostname ${service.host}:`, err);
    }
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

function listTrustedPeers()
{
    const config = readConfig();
    if (!config.trustedPeers || Object.keys(config.trustedPeers).length === 0)
    {
        console.log('You have no trusted peers yet. Use the \`connect` command to add one.');
        return;
    }

    console.log('Trusted peers:');
    Object.keys(config.trustedPeers).forEach(peer => {
        const lastConnectedDate = new Date(config.trustedPeers[peerName].lastConnected);
        const isOnline = peers.has(peerName) ? '(Online)' : '(Offline)';
        console.log(`${peer.name} ${isOnline} - last connected: ${lastConnectedDate}`);
    });
}

async function connectToPeer(peerName) {
    let peer = peers.get(peerName);
    if (!peer)
    {
      console.log(`Peer ${peerName} not found`);
      return false;
    }

    const config = readConfig();
    if (config.trustedPeers && Object.keys(config.trustedPeers).includes(peerName))
    {
        console.log(`Peer ${peerName} is trusted. Proceeding to connect.`);
        return { peer, continueConnecting: true };
    }

    const confirmation = await confirm({ message: `Peer ${peerName} is not trusted. Do you want to trust this peer?` });
    if (!confirmation)
    {
        console.log('Connection cancelled.');
        return false;
    }

    if (!config.trustedPeers)
        config.trustedPeers = {};

    config.trustedPeers[peerName] = {
        name: peer.name,
        host: peer.host,
        port: peer.port,
        firstConnected: Date.now(),
        lastConnected: Date.now()
    };

    saveConfig(config);
    console.log(`Peer ${peerName} trusted.`);

    return { peer, continueConnecting: confirmation };
}

async function handleCommands()
{
    console.log(`P2P FILE SHARING APP\n\nAvailable commands: list`);
    
    while (true)
    {
        const menuOpt = await input({message: `Please enter a command: `});
        const command = menuOpt;
        const config = readConfig();
        
        switch(command.toLowerCase())
        {
            case 'list':
                listAvailablePeers();
                break;
            case 'connect':
                const peerName = await input({message: `Enter the peer name to connect to: `});
                const connectionDetails = await connectToPeer(peerName);

                if (connectionDetails && connectionDetails.continueConnecting)
                {
                    let peer = connectionDetails.peer;
                    console.log(`Connecting to peer ${peer.name} at ${peer.host}:${peer.port}`);

                    try
                    {
                        const peerSocket = await handleClientConnection(peer.host, peer.port);
                        peerSocket.write(JSON.stringify({ type: `PEER_CONNECTED`, data: { peerName: SERVICE_NAME } }), (err) => {
                            if (err)
                            {
                                console.error("Error writing to socket: ", err);
                                peerSocket.destroy();
                                return;
                            }
                        });
                        peerSocket.end();

                        if (config.trustedPeers[peerName])
                        {
                            config.trustedPeers[peerName].lastConnected = Date.now();
                            saveConfig(config);
                        }
                    } 
                    catch (error)
                    {
                        console.error(`Error connecting to peer: ${error.message}`);
                    }
                }
                else
                {
                    console.log(`Peer ${peerName} not found or connection cancelled.`);
                }
                break;
            case 'exit':
                console.log('Goodbye!');
                mdns.cleanupBonjour();
                process.exit(0);
            case 'friends':
                listTrustedPeers();
                break;
            default:
                console.log('Unknown command');
                break;
        }
    }
}

async function validatePrerequisites()
{
    const config = readConfig();
    PORT = config.port;
    SERVICE_NAME = config.serviceName;
    SERVICE_TYPE = config.serviceType;

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

        config.salt = salt;
        config.derivedKey = encryptedResults.derivedKey;

        const localIP = getLocalIPv4Address();

        createRootCACert();
        createServerCert(localIP, { ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256' });
        createClientCert({ ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256' });

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