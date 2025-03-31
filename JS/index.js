process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0;
const mdns = require('./mdns-discovery');
const { readConfig, saveConfig } = require('./state');
const { input, password, confirm } = require('@inquirer/prompts');
const { generateKeyPair, generateSalt, encryptPrivateKey, createRootCACert, createServerCert, createClientCert, getLocalIPv4Address, resolveHostnameToIP } = require('./utils');
const { handleServerCreation, handleClientConnection, sendMessageToPeer, handleRequestFileFromPeer } = require('./connection');
const { scanFileVault, writeToVault } = require('./storage');

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
    Object.values(config.trustedPeers).forEach(peer => {
        const lastConnectedDate = new Date(config.trustedPeers[peer.name].lastConnected).toLocaleString();
        const isOnline = peers.has(peer.name) ? '(Online)' : '(Offline)';
        console.log(`- ${peer.name} ${isOnline}: last connected: ${lastConnectedDate}`);
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

async function getPeerFiles(peerName)
{
    const config = readConfig();
    let peer = peers.get(peerName);
    if (!peer)
    {
        console.log(`Peer ${peerName} not found`);
        return;
    }

    if (!config.trustedPeers || !config.trustedPeers[peerName])
    {
        console.log(`Peer ${peerName} is not trusted. Cannot retrieve files.`);
        return;
    }

    try
    {
        const response = await sendMessageToPeer(peer.host, peer.port, 'REQUEST_FILES_LIST', { peerName: SERVICE_NAME });
        if (response && response.type == 'FILES_LIST')
        {
            if (response.data.files.length === 0)
            {
                console.log(`No files found on peer ${peerName}`);
                return;
            }

            response.data.files.forEach((file, idx) => {
                console.log(`${idx + 1}. ${file.name} (${file.size} bytes)`);
            });

            return response.data.files;
        }
        else
        {
            console.log(`Failed to retrieve files from peer ${peerName}`);
            return;
        }
    }
    catch (error)
    {
        console.error(`Error retrieving files from peer ${peerName}:`, error);
        return;
    }
}

async function requestFileFromPeer()
{
    const peerName = await input({message: `Enter the peer name to request files from: `});
    const peer = peers.get(peerName);
    if (!peer)
    {
        console.error(`Peer ${peerName} not found`);
        return;
    }

    try
    {
        const files = await getPeerFiles(peerName);
        if (files)
        {
            console.log(`Files from ${peerName}:`);
            files.forEach(file => {
                console.log(`- ${file.name}`);
            });
        }
        let fileToRequest = await input({message: `Enter the index of file to request: `});
        console.log(`Requesting consent to downoad file ${fileToRequest} from ${peerName}...`);
        fileToRequest = parseInt(fileToRequest) - 1;
        if (fileToRequest < 0 || fileToRequest >= files.length)
        {
            console.error(`Invalid file index`);
            return;
        }
        
        const file = files[fileToRequest];
        const response = await handleRequestFileFromPeer(peer.host, peer.port, file.name, SERVICE_NAME);
        if (response.type == 'FILE_RECEIVED')
        {
            console.log(`File ${file.name} received from ${peerName}`);
            await writeToVault(response.data.fileName, response.data.fileContent, true);
            console.log(`\nFile ${response.data.fileName} received from ${peerName}`);
        }
        else if (response.type == 'FILE_REQUEST_DECLINED')
        {
            console.error(`File request for ${file.name} declined by ${peerName}`);
            return;
        }
        else if (response.type == 'FILE_NOT_FOUND')
        {
            console.error(`File ${file.name} not found on peer ${peerName}`);
            return;
        }
        else
        {
            console.error(`Unknown response type: ${response.type}`);
            return;
        }
    } catch (error)
    {
        console.error(`Error requesting file from peer ${peerName}:`, error);
        return;
    }
}

async function handleCommands()
{
    const availableCommands = ['list', 'connect', 'exit', 'friends', 'files', 'request', 'help'];
    console.log(`P2P FILE SHARING APP\n\nAvailable commands: ${availableCommands.join(', ')}`);
    
    while (true)
    {
        const menuOpt = await input({message: `Please enter a command: `});
        const command = menuOpt;
        const config = readConfig();
        let peerName;
        
        switch(command.toLowerCase())
        {
            case 'list':
                listAvailablePeers();
                break;
            case 'connect':
                peerName = await input({message: `Enter the peer name to connect to: `});
                const connectionDetails = await connectToPeer(peerName);

                if (connectionDetails && connectionDetails.continueConnecting)
                {
                    let peer = connectionDetails.peer;
                    console.log(`Connecting to peer ${peer.name} at ${peer.host}:${peer.port}`);

                    try
                    {
                        const _ = await sendMessageToPeer(peer.host, peer.port, 'PEER_CONNECTED', { peerName: SERVICE_NAME });
                        
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
            case 'files':
                peerName = await input({message: `Enter the peer name to retrieve file list from: `});
                await getPeerFiles(peerName);
                break;
            case 'request':
                requestFileFromPeer();
                break;
            case 'help':
                console.log(`Available commands: ${availableCommands.join(', ')}`);
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