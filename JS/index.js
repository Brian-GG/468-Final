const mdns = require('./mdns-discovery');
const { readConfig, saveConfig } = require('./state');
const { input, password, confirm } = require('@inquirer/prompts');
const { generateKeyPair, generateSalt, encryptPrivateKey, createServerCert, createClientCert, getLocalIPv4Address, createSha256Hash, placeRootCACert, getConfigDirectory, deriveKeyFromPassword, getFileVaultDirectory, decryptPrivateKey, signData } = require('./utils');
const { handleServerCreation, sendMessageToPeer, handleRequestFileFromPeer } = require('./connection');
const { scanFileVault, writeToVault, decryptFile, findAlternativeFileSources } = require('./storage');
const secureContext = require('./secureContext');
const fs = require('fs');
const path = require('path');

function initAgent()
{
    const config = readConfig();

    console.log(`Starting agent with service name: ${config.serviceName} on port ${config.port}`);
    const serviceName = mdns.advertiseService(config.serviceName, config.port);
    
    console.log(`Finding peers for service type: ${config.serviceType}`);
    const browser = mdns.findPeers();

    files = scanFileVault();

    setInterval(scanFileVault, 30 * 1000);

    process.on('SIGINT', () => {
        console.log('\nShutting down agent');
        mdns.cleanupBonjour();
        process.exit(0);
    });

    return [serviceName, browser];
}

function listAvailablePeers()
{
    const peers = mdns.getPeers();
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
    const peers = mdns.getPeers();
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

async function connectToPeer(peerName)
{
    const peers = mdns.getPeers();
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
    const peers = mdns.getPeers();
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
        return 'NOT_TRUSTED';
    }

    try
    {
        const response = await sendMessageToPeer(peer.host, peer.port, 'REQUEST_FILES_LIST', { peerName: config.serviceName });
        if (response && response.type == 'FILES_LIST')
        {
            if (Object.keys(response.data.files).length === 0)
            {
                console.log(`No files found on peer ${peerName}`);
                return;
            }

            response.data.files.forEach((file, idx) => {
                console.log(`${idx + 1}. ${file.name} (${file.size} bytes) - Hash: ${file.hash}`);
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
    const peers = mdns.getPeers();
    const config = readConfig();
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
        if (files === 'NOT_TRUSTED')
        {
            return;
        }

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

        try
        {
            const response = await handleRequestFileFromPeer(peer.host, peer.port, file.name, config.serviceName);
            if (response.type == 'FILE_RECEIVED')
            {
                await writeToVault(response.data.fileName, response.data.fileContent, true);
                console.log(`\nFile ${response.data.fileName} received from ${peerName} and saved to vault.`);
                return;
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
        }
        catch (error)
        {
            console.error(`Error requesting file from peer ${peerName}. Searching for alternative sources...`);
            const alternativePeers = await findAlternativeFileSources(file.hash);
            if (alternativePeers == null || alternativePeers.length === 0)
            {
                console.error(`No alternative sources found for file ${file.name}`);
                return;
            }

            console.log(`Found alternative sources for file ${file.name}:`);
            alternativePeers.forEach((peer, idx) => {
                console.log(`${idx + 1}. ${peer.peerName} (${peer.host}:${peer.port})`);
            });
            const alternativePeerIndex = await input({message: `Enter the index of the peer to request from: `});
            const alternativePeer = alternativePeers[parseInt(alternativePeerIndex) - 1];
            if (!alternativePeer)
            {
                console.error(`Invalid peer index`);
                return;
            }

            console.log(`Requesting file ${file.name} from alternative peer ${alternativePeer.peerName}...`);
            
            try
            {
                const response = await handleRequestFileFromPeer(alternativePeer.host, alternativePeer.port, file.name, config.serviceName);
                if (response.type == 'FILE_RECEIVED')
                {
                    await writeToVault(response.data.fileName, response.data.fileContent, true);
                    console.log(`\nFile ${response.data.fileName} received from ${alternativePeer.peerName} and saved to vault.`);
                }
                else if (response.type == 'FILE_REQUEST_DECLINED')
                {
                    console.error(`File request for ${file.name} declined by ${alternativePeer.peerName}`);
                }
                else if (response.type == 'FILE_NOT_FOUND')
                {
                    console.error(`File ${file.name} not found on peer ${alternativePeer.peerName}`);
                }
            }
            catch (error)
            {
                console.error(`Error requesting file from alternative peer ${alternativePeer.peerName}:`, error);
            }

            return;
        }
    }
    catch (error)
    {
        console.error(`Error requesting file from peer ${peerName}:`, error);
        return;
    }
}

async function decryptFileInVault()
{
    let fileList = scanFileVault();
    if (fileList.length === 0)
    {
        console.log('No files found in vault');
        return;
    }

    console.log('Files in vault:\n');
    fileList.forEach((file) => {
        console.log(`- ${file.name} (${file.size} bytes)`);
    });

    let fileName = await input({message: `Enter the name of the file to decrypt: `});
    fileName += '.enc';
    const filePath = path.join(getFileVaultDirectory(), `${fileName}`);
    if (!fs.existsSync(filePath))
    {
        console.error(`File ${fileName} not found in vault`);
        return;
    }

    try
    {
        let derivedKey = secureContext.getKey();
        const decryptedFile = await decryptFile(fileName, derivedKey, true);
        if (decryptedFile)
        {
            console.log(`File ${fileName} decrypted successfully.\nFor security reasons, the file will be re-encrypted in 30 seconds.`);
            return decryptedFile;
        }
        else
        {
            console.error(`Failed to decrypt file ${fileName}`);
            return;
        }
    }
    catch (error)
    {
        console.error(`Error decrypting file ${fileName}:`, error);
        return;
    }
}

async function revokeKey()
{
    const peers = mdns.getPeers();
    const config = readConfig();

    if (!config.keyRevocationList)
        config.keyRevocationList = [];

    const confirmation = await confirm({ message: `Are you sure you want to revoke your key? This will invalidate all your trusted connects, and you will need to reauthenticate.` });
    if (!confirmation)
    {
        console.log('Key revocation cancelled.');
        return;
    }

    let oldUserId = config.userId;
    const { publicKey: newPublicKey, privateKey: newPrivateKey } = generateKeyPair();
    let pubkeyHash = createSha256Hash(newPublicKey);
    pubkeyHash = pubkeyHash.substring(0, 8);
    config.userId = pubkeyHash;
    const [derivedKey, salt] = await passwordPrompt(false);
    secureContext.storeKey(derivedKey);

    const encryptedResults = await encryptPrivateKey(newPrivateKey, derivedKey);
    const newKeypair = {
        publicKey: newPublicKey,
        privateKey: encryptedResults.encryptedPrivateKey,
        iv: encryptedResults.iv,
        authTag: encryptedResults.authTag,
        salt: salt
    };

    const configDir = getConfigDirectory();
    const clientPublicKey = fs.readFileSync(path.join(configDir, 'client_public.pem'), 'utf8');
    
    const migrationAnnouncement = {
        oldUserId: `SecureShare-${oldUserId}`,
        newUserId: `SecureShare-${pubkeyHash}`,
        oldPublicKey: config.keypair.publicKey,
        newPublicKey: clientPublicKey,
        timestamp: Date.now(),
        signature: null
    }

    let dataToSign = JSON.stringify({
        oldUserId: migrationAnnouncement.oldUserId,
        newUserId: migrationAnnouncement.newUserId,
        oldPublicKey: migrationAnnouncement.oldPublicKey,
        newPublicKey: migrationAnnouncement.newPublicKey,
        timestamp: migrationAnnouncement.timestamp
    });

    try
    {
        const decryptedPrivateKey = await decryptPrivateKey(config.keypair.privateKey, derivedKey, config.keypair.iv, config.keypair.authTag);
        migrationAnnouncement.signature = signData(dataToSign, decryptedPrivateKey);
    }
    catch (err)
    {
        console.error('Error decrypting private key:', err);
        console.error('Key revocation failed.');
        return;
    }

    for (const peerName in config.trustedPeers)
    {
        const peer = config.trustedPeers[peerName];
        if (peers.has(peer.name))
        {
            const response = await sendMessageToPeer(peer.host, peer.port, 'KEY_REVOCATION', { migrationAnnouncement, ackNeeded: true }); // get acknowledgement from first-hand connections
            // add a timeout to wait for response
            if (!response)
            {
                console.log(`No response from ${peer.name}. Key revocation failed.`);
                continue;
            }

            if (response && response.type == 'KEY_REVOCATION_ACK')
            {
                console.log(`Key revocation acknowledged by ${response.data.peerName}`);
                config.trustedPeers[response.data.peerName] = {
                    ...config.trustedPeers[response.data.peerName],
                    publicKey: response.data.publicKey,
                    lastConnected: Date.now(),
                }
            }
            else
            {
                console.log(`Key revocation failed for ${peer.name}`);
            }
        }
    }

    config.keypair = newKeypair;
    config.salt = salt;
    config.userId = pubkeyHash;
    config.serviceName = `SecureShare-${pubkeyHash}`;
    config.passwordHash = createSha256Hash(derivedKey);

    saveConfig(config);
    console.log(`Key revocation completed. You are now known as ${config.userId}. Goodbye!`);
    process.exit(0);
}

function handleReceivedKRL(krl)
{
    const config = readConfig();
    if (!config.keyRevocationList)
    {
        config.keyRevocationList = krl;
        saveConfig(config);
    }
    else
    {
        const existingKRL = config.keyRevocationList;
        const newKRL = krl;

        newKRL.forEach((newEntry) => {
            const existingEntry = existingKRL.find(entry => entry.oldUserId === newEntry.oldUserId);
            if (!existingEntry)
            {
                existingKRL.push(newEntry);
            }
            else
            {
                // noop
            }
        });

        config.keyRevocationList = existingKRL;
        saveConfig(config);
    }
}

async function handleCommands()
{
    const availableCommands = ['list', 'connect', 'exit', 'friends', 'files', 'request', 'revoke_key', 'decrypt', 'help'];
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
                        const configDir = getConfigDirectory();
                        let publicKey = fs.readFileSync(path.join(configDir, 'client_public.pem'), 'utf8');
                        const response = await sendMessageToPeer(peer.host, peer.port, 'PEER_CONNECTED', { peerName: config.serviceName, publicKey });
                        
                        if (response && response.type == 'WELCOME')
                        {
                            if (!config.trustedPeers[peerName])
                                config.trustedPeers[peerName] = {};
                            config.trustedPeers[peerName].host = peer.host;
                            config.trustedPeers[peerName].port = peer.port;
                            config.trustedPeers[peerName].name = peerName;
                            config.trustedPeers[peerName].publicKey = response.data.publicKey;
                            config.trustedPeers[peerName].lastConnected = Date.now();
                            saveConfig(config);

                            if (response.data.keyRevocationList)
                            {
                                const krl = response.data.keyRevocationList;
                                handleReceivedKRL(krl);
                            }
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
            case 'decrypt':
                decryptFileInVault();
                break;
            case 'revoke_key':
                await revokeKey();
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

async function passwordPrompt(firstRun=false)
{
    const config = readConfig();

    const userPassphrase = await password({ message: 'Enter password: ' });
    if (firstRun)
    {
        const confirmPassphrase = await password({ message: 'Confirm password: ' });
        if (userPassphrase !== confirmPassphrase)
        {
            console.log('Passwords do not match. Exiting...');
            process.exit(1);
        }
    }

    let salt = null;
    if (!config.salt)
        salt = generateSalt();
    else
    {
        salt = config.salt;
    }
    let derivedKey = await deriveKeyFromPassword(userPassphrase, salt)

    return [derivedKey, salt];
}

async function validatePrerequisites()
{
    const config = readConfig();

    if (config.isFirstRun || !config.keypair)
    {
        console.log('First run detected');
        const { publicKey, privateKey } = generateKeyPair();

        let pubkeyHash = createSha256Hash(publicKey);
        pubkeyHash = pubkeyHash.substring(0, 8);

        config.userId = pubkeyHash;
        config.serviceName = `SecureShare-${pubkeyHash}`;

        console.log('You must set a passphrase to encrypt your downloaded files. Make sure you remember this!\nIf you forget, you will lose access to your files!');
        // TODO: Password must be at least 12 characters long
        const [derivedKey, salt] = await passwordPrompt(true);
        secureContext.storeKey(derivedKey);
        let pwHash = createSha256Hash(derivedKey);
        config.passwordHash = pwHash;

        const encryptedResults = await encryptPrivateKey(privateKey, derivedKey);
        
        config.keypair = {
            publicKey: publicKey,
            privateKey: encryptedResults.encryptedPrivateKey,
            iv: encryptedResults.iv,
            authTag: encryptedResults.authTag,
            salt: salt
        }

        config.salt = salt;

        const localIP = getLocalIPv4Address();

        placeRootCACert();
        createServerCert(localIP, { ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256' });
        createClientCert({ ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256' });

        config.isFirstRun = false;
        saveConfig(config);
    }
    else
    {
        console.log(`Please enter the passphrase to unlock your file vault. This is the same passphrase you used when you first started the application.`);
        let [derivedKey, _] = await passwordPrompt();
        let pwHash = createSha256Hash(derivedKey);
        if (pwHash !== config.passwordHash)
        {
            console.log('Incorrect passphrase. Exiting...');
            process.exit(1);
        }
        secureContext.storeKey(derivedKey); 
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