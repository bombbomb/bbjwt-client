const jwt     = require('jsonwebtoken');
const KmsJwt  = require('kms-jwt');

let kmsJwt = null;

module.exports = {
    getClientIdFromToken: function(jwt, callback)
    {
        const self = this;
        if (typeof jwt === 'string') {
            this.decodeToken(jwt, function(err, data) {
                if(err)
                {
                    callback(err, null);
                }
                else
                {
                    self.getClientIdFromToken(data, callback)
                }
            });
        }
        else if(jwt && jwt.hasOwnProperty('bbcid'))
        {
            callback(null, jwt.bbcid)
        }
        else if(jwt && jwt.hasOwnProperty('clientId'))
        {
            callback(null, jwt.clientId)
        }
        else
        {
            callback('JWT : Error retrieving clientId, token undefined/missing data?', null);
        }

    },

    decodeToken: function(token, callback)
    {
        let decoded = false;
        const self = this;
        if (token)  // strip Bearer from prefix
        {
            if (token.indexOf(' ') > -1)
            {
                token = token.split(' ')[1];
            }
        }
        this.decodeWithKms(token, function(err, decodedToken) {
            if(!err && decodedToken)
            {
                callback(null, decodedToken);
            }
            else
            {
                try
                {
                    decoded = self.decodeV1Token(token);
                    if (decoded)
                    {
                        callback(null, decoded);
                    }
                    else
                    {
                        throw new Error('decodeV1Token failed');
                    }
                }
                catch(exception)
                {
                    err && console.error("decodeWithKms Failed: " + err);
                    console.log("JWT Decode failed: " + token);
                    callback(exception, decoded);
                }
            }
        });
    },

    decodeV1Token: function(token)
    {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (!decoded.hasOwnProperty('expires') || decoded.expires < Date.now()/1000) {
            console.log("JWT token expired failed: " + token);
            return false;
        }
        return decoded;
    },

    decodeWithKms: function(token, callback)
    {
        try
        {
            if (!kmsJwt) {
                kmsJwt = new KmsJwt({
                    signingKey: process.env.SIGNING_KEY
                });
            }
            kmsJwt.verify(token, function(err, decoded) {
                if (err)
                {
                    console.error('KMS Verify Failed: '+err);
                    callback(err, null);
                }
                else
                {
                    callback(null, decoded);
                }
            });
        }
        catch(e)
        {
            callback(e, null)
        }

    }
};




