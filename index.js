var jwt = require('jsonwebtoken');

module.exports = {
    getClientIdFromToken: function(jwt)
    {
        var payload = this.decodeToken(jwt);
        if (payload === false)
        {
            return false;
        }
        return payload.clientId;
    },

    decodeToken: function(token)
    {
        var decoded = false;
        try
        {
            decoded = this.decodeV1Token(token);
            if(decoded) { return decoded; }
        }
        catch(err)
        {
            console.log("JWT V1 decode failed: " + token);
        }
        try
        {
            decoded = this.decodeV2Token(token);
        }
        catch(err)
        {
            console.log("JWT V2 decode failed: " + token);
        }
        return decoded;
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

    decodeV2Token: function(token)
    {
        var decoded = jwt.verify(token, process.env.JWT_V2_SECRET);
        if (!decoded.hasOwnProperty('expires') || decoded.expires < Date.now()/1000) {
            console.log("JWT token expired failed: " + token);
            return decoded;
        }
        return decoded;
    }
};




