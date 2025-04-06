const fs = require('fs');
const os = require('os');
const path = require('path');

const defaultConfig = { isFirstRun: true, port: 3000, serviceType: 'secureshare', trustedPeers: {}, fileMetadata: {}, keyRevocationList: [] };

function createConfigDirectory()
{
    const homedir = os.homedir();
    const configDir = path.join(homedir, '.p2p-agent');

    if (!fs.existsSync(configDir))
    {
        fs.mkdirSync(configDir);
        fs.mkdirSync(path.join(configDir, 'certs'));
        fs.mkdirSync(path.join(configDir, 'file_vault'));
        fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify(defaultConfig, null, 2));
    }

    return configDir;
}

function getConfigFilePath()
{
    return path.join(createConfigDirectory(), 'config.json');
}

function readConfig()
{
    const configPath = getConfigFilePath();

    if (!fs.existsSync(configPath))
    {
        createConfigDirectory();
        return defaultConfig;
    }

    const config = fs.readFileSync(configPath, 'utf8');
    return JSON.parse(config);
}

function saveConfig(config)
{
    const configPath = getConfigFilePath();
    const configDir = path.dirname(configPath);

    if (!fs.existsSync(configDir))
    {
        createConfigDirectory();
    }

    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
}

module.exports = {
    readConfig,
    saveConfig
};