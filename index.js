var jwt = require('jsonwebtoken');

module.exports = {
    getClientIdFromToken: function(jwt) {
        var payload = this.decodeToken(jwt);
        if (payload === false) {
            return false;
        }
        return decoded.clientId;
    },

    decodeToken: function(jwt) {
        try {
            var decoded = jwt.verify(jwt, process.env.JWT_SECRET);
            return decoded;
        } catch(err) {
            console.log("JWT decode failed: " + jwt);
            return false;
        }
    }
};