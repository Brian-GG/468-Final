const { readConfig } = require('./state');
const bonjour = require('bonjour')();

let activeService = null;
let activeBrowser = null;

module.exports = {
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

    findPeers: (onPeerUp, onPeerDown) => {
        if (activeBrowser)
            activeBrowser.stop();

        const config = readConfig();

        activeBrowser = bonjour.find({ type: config.serviceType });

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

        bonjour.destroy();
    }
}