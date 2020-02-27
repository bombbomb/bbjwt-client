var jwt     = require('jsonwebtoken');
var KmsJwt  = require('kms-jwt');

var winston = require('winston')
var logger = winston.createLogger({
    transports: new winston.transports.Console({
        format: new winston.format.simple()
    }),
    level: 'info'
});

var kmsJwt = null;
var getKmsJwt = () => {
    if (!kmsJwt) {
        kmsJwt = new KmsJwt({
            signingKey: process.env.SIGNING_KEY
        });
    }
    return kmsJwt;
};

module.exports = {
    /**
     * Gets a client id from a token, checks both KMS type and v1 type tokens
     * Calls callback with (null, clientId) if possible
     * @param {*} jwt { string | object} jwt to decode
     * @param {*} callback {(err: any, clientId: string) => any}
     */
    getClientIdFromToken: function(jwt, callback) {
        var self = this;
        if (typeof jwt === 'string') {
            self.decodeToken(jwt, (err, data)  => {
                if(err) {
                    callback(err, null);
                } else {
                    self.getClientIdFromToken(data, callback)
                }
            });
        } else if(jwt && jwt.hasOwnProperty('bbcid')) {
            callback(null, jwt.bbcid)
        } else if(jwt && jwt.hasOwnProperty('clientId')) {
            callback(null, jwt.clientId)
        } else {
            callback('JWT : Error retrieving clientId, token undefined/missing data?', null);
        }
    },
    /**
     * Decodes a token, first trying kms, then v1 token.
     * Callback is called with decoded token.
     * @param {*} token {string} token to decode
     * @param {*} callback {(err: any, decodedToken: {}) => any}
     */
    decodeToken: function(token, callback) {
        var decoded = false;
        // strip Bearer from prefix
        if (token && token.indexOf(' ') > -1) {
            token = token.split(' ')[1];
        }
        var self = this;
        self.decodeWithKms(token, (err, decodedToken) => {
            if(!err && decodedToken) {
                callback(null, decodedToken);
            } else {
                logger.debug('kms token decoding failed, attempt v1 token decode', { kmsError: err.toString() });
                try {
                    decoded = self.decodeV1Token(token);
                    if (decoded) {
                        callback(null, decoded);
                    } else {
                        throw new Error('decodeV1Token failed');
                    }
                } catch(exception) {
                    if (err) {
                        logger.warn('both kms and v1 token decoding failed', { kmsError: err.toString(), v1Error: exception.toString() })
                    } else {
                        logger.warn('v1 token decoding failed', { v1Error: exception.toString() });
                    }
                    callback(exception, decoded);
                }
            }
        });
    },
    /**
     * Attempts to decode V1 token.
     * @param {*} token {string}
     * @returns {false|object} Returns decoded token from jsonwebtoken.verify or false if token expired
     */
    decodeV1Token: function(token) {
        var decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (!decoded.hasOwnProperty('expires') || decoded.expires < Date.now()/1000) {
            logger.info('jwt token expired failed', { jwt: token });
            return false;
        }
        return decoded;
    },
    /**
     * Attempts to decode token using kms.
     * Callback called with decoded token.
     * @param {*} token {string} token to decode
     * @param {*} callback 
     */
    decodeWithKms: function(token, callback) {
        try {
            var kj = getKmsJwt();
            kj.verify(token, (err, decoded) => {
                if (err) {
                    logger.debug('kms verify failed', { kmsError: err.toString() });
                    callback(err, null);
                } else {
                    callback(null, decoded);
                }
            });
        } catch(err) {
            logger.warn('error occurred while trying to decode with kms', { kmsError: err.toString() });
            callback(err, null)
        }
    },
    /**
     * Optionally sets a logger to better control communication.
     * Must comply with winston logger api
     * @param {*} lgr 
     */
    setLogger: function(lgr) {
        logger = lgr;
    }
};
