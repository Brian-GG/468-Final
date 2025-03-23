const { execSync } = require('child_process');
const os = require('os');
module.exports = {
    runOSCommand: (command) => {
        process.chdir(`${os.homedir()}/.p2p-agent/certs`);
        try
        {
            const result = execSync(`${command}`).toString();
            return result.trim();
        }
        catch (error)
        {
            console.error('Error running OpenSSL:', error);
            return null;
        }
    }
}