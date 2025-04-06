const { readConfig } = require('./state');
const { resolveHostnameToIP } = require('./utils');
const bonjour = require('bonjour')();

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

        activeService = bonjour.publish({ name: serviceName, type: '_secureshare._tcp.local.', port, protocol: 'tcp' });

        return serviceName;
    },

    findPeers: () => {
        if (activeBrowser)
            activeBrowser.stop();

        activeBrowser = bonjour.find({});

        const onPeerUp = async (service) => {
            const config = readConfig();

            if (service.name === config.serviceName)
                return;
        
            try
            {
                // Python zeroconf handles service type in a strange way for broadcast
                // which doesn't get picked up by the JS library. So, we do a manual filter
                // here rather than letting the library handle it.
                if (service.host.includes('secureshare'))
                {
                    let ip = service.referer.address
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