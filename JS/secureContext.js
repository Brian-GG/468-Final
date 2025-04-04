/*
    This module is intended to provide a secure context to store sensitive data
    such as derived keys. A Symbol is used to create a private context that cannot
    be accessed directly from outside this module.
    
    Note: This is not intended to be a replacement for hardware security modules like
    TPM, or other OS-specific keychains. This is just a simplified representation of
    such a solution.
*/

function createSecureContext()
{
    const keySymbol = Symbol('derivedKey');
    const context = {};

    return {
        storeKey: (key) => {
            const keyBuffer = Buffer.from(key, 'hex');
            context[keySymbol] = keyBuffer;

            if (!process._secureContextCleaned)
            {
                process.on('exit', () => {
                    if (context[keySymbol])
                        context[keySymbol].fill(0);
                });
            }
            process._secureContextCleaned = true;
        },

        getKey: () => context[keySymbol] || null,

        clear: () => {
            if (context[keySymbol])
            {
                context[keySymbol].fill(0);
                delete context[keySymbol];
            }
        }
    }
}

module.exports = createSecureContext();