var jwt     = require('jsonwebtoken'),
    KmsJwt  = require('kms-jwt');



module.exports = {
    getClientIdFromToken: function(jwt, callback)
    {
        var self = this;
        if (typeof jwt == 'string')
        {
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
        else if(jwt.hasOwnProperty('sub'))
        {
            callback(null, jwt.sub)
        }
        else if(jwt.hasOwnProperty('clientId'))
        {
            callback(null, jwt.clientId)
        }

    },

    decodeToken: function(token, callback)
    {
        var decoded = false;
        var self = this;
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
                }
                catch(err)
                {
                    console.log("JWT V1 decode failed: " + token);
                    callback(err, decoded);
                }
            }
        });
    },

    decodeV1Token: function(token)
    {
        var decoded = jwt.verify(token, process.env.JWT_SECRET);
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
            var kmsJwt = new KmsJwt({
                awsConfig: {
                    region: process.env.AWS_REGION,
                    accessKeyId : process.env.AWS_ACCESS_KEY,
                    secretAccessKey: process.env.AWS_SECRET_KEY
                },
                signingKey: process.env.SIGNING_KEY,
                keyArn: process.env.KMS_ARN
            });

            kmsJwt.verify(token, function(err, decoded) {
                if(err)
                {
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
            callback()
        }

    }
};




