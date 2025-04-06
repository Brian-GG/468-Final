const { readConfig } = require('./state');
const { Bonjour} = require('bonjour-service');
const bonjour = new Bonjour();
let activeService = null;
let activeBrowser = null;

const peers = new Map();

module.exports = {
    getPeers: () => {
        return new Map(peers);  
    },

    advertiseService: (name = config.serviceName, port = config.port) => {
        if (activeService)
        {
            activeService.stop();
        }

        const config = readConfig();

        const serviceName = name || config.serviceName;

        activeService = bonjour.publish({ name: config.serviceName, type: config.serviceType, port });

        return serviceName;
    },

    findPeers: () => {
        if (activeBrowser)
            activeBrowser.stop();

        const config = readConfig();

        activeBrowser = bonjour.find({ type: config.serviceType });

        const onPeerUp = async (service) => {
            const config = readConfig();
            if (service.name === config.serviceName)
                return;
        
            try
            {
                const ip = await resolveHostnameToIP(service.host);
                
                if (!peers.has(service.name))
                {
                    console.log(`New peer discovered: ${service.name} on ${ip}:${service.port}`);
                    peers.set(service.name, {
                        name: service.name,
                        host: ip,
                        port: service.port,
                        service: service,
                        discoveredAt: Date.now(),
                        lastSeen: Date.now()
                    });
                    console.log(`Total peers: ${peers.size}`);
                }
            }
            catch (err)
            {
                console.error(`Error resolving hostname ${service.host}:`, err);
            }
        };

        const onPeerDown = (service) => {
            if (peers.has(service.name))
            {
                console.log(`Peer gone: ${service.name}`);
                peers.delete(service.name);
            }
        };

        if (onPeerUp)
            activeBrowser.on('up', onPeerUp);

        if (onPeerDown)
            activeBrowser.on('down', onPeerDown);

        return activeBrowser;
    },

    cleanupBonjour: () => {
        if (activeService)
            activeService.stop();

        if (activeBrowser)
            activeBrowser.stop();

        peers.clear();
        bonjour.destroy();
    }
}