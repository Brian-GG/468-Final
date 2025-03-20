const bonjour = require('bonjour')();
const config = require('./config');

let activeService = null;
let activeBrowser = null;

const PORT = config.port;
const SERVICE_NAME = config.serviceName;
const SERVICE_TYPE = config.serviceType;

module.exports = {
    advertiseService: (name = null, port = PORT) => {
        if (activeService)
        {
            activeService.stop();
        }

        const serviceName = name || SERVICE_NAME;

        activeService = bonjour.publish({ name: serviceName, type: SERVICE_TYPE, port });

        return serviceName;
    },

    findPeers: (onPeerUp, onPeerDown) => {
        if (activeBrowser)
            activeBrowser.stop();

        activeBrowser = bonjour.find({ type: SERVICE_TYPE });

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