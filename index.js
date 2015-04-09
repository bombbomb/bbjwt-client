var jwt = require('jsonwebtoken');

module.exports = {
    getClientIdFromToken: function(jwt) {
        var payload = this.decodeToken(jwt);
        if (payload === false) {
            return false;
        }
        return decoded.clientId;
    },

    decodeToken: function(token) {
        try {
            var decoded = jwt.verify(token, process.env.JWT_SECRET);

            if (!decoded.hasOwnProperty('expires') || decoded.expires < Date.now()/1000) {
                console.log("JWT token expired failed: " + token);
                return false;
            }

            return decoded;
        } catch(err) {
            console.log("JWT decode failed: " + token);
            return false;
        }
    }
};