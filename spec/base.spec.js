var assert      = require('assert'),
    sinon       = require('sinon'),
    jwt         = require('jsonwebtoken'),
    mocha       = require('mocha');

var decoder     = require('../index.js'),
    testEnvVars = require('../test.env.inc.js');

function createRandomString(noOfChars)
{
    var secret = '';
    var possibleChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    for(i = 0; i < noOfChars; i++)
    {
        secret += possibleChars.charAt(Math.floor(Math.random() * possibleChars.length));
    }
    return secret;
}

function createUserDetails()
{
    return {
        clientId : createRandomString(20),
        userId : createRandomString(20)
    }
}

function createJwtPayload(user)
{
    return {
        expires : '1h',
        clientId : user.clientId,
        userId : user.userId
    }
}

describe('random test', function() {

    var testUser1, testUser2, jwtPayload1, jwtPayload2, tokenV1, tokenV2, randomToken;

    before(function() {
        process.env.JWT_SECRET = createRandomString(10);
        process.env.JWT_V2_SECRET = createRandomString(50);
        var randomSecret = createRandomString(20);

        testUser1 = createUserDetails();
        testUser2 = createUserDetails();

        jwtPayload1 = createJwtPayload(testUser1);
        jwtPayload2 = createJwtPayload(testUser2);

        tokenV1 = jwt.sign(jwtPayload1, process.env.JWT_SECRET);
        tokenV2 = jwt.sign(jwtPayload2, process.env.JWT_V2_SECRET);
        randomToken = jwt.sign(jwtPayload1, randomSecret);
    });


    it('should decode v1 token', function() {
        var decoded = decoder.decodeV1Token(tokenV1);
        assert(decoded.expires == jwtPayload1.expires, 'expiry time should be equal');
        assert(decoded.iat > ((Date.now()/1000) - 5), 'jwt should have been issued in the last few seconds');
        assert(decoded.clientId == testUser1.clientId, 'clientId should be the same as testUser1');
        assert(decoded.userId == testUser1.userId, 'userId should be the same as testUser1');
    });

    it('should decode v2 token', function() {
        var decoded = decoder.decodeV2Token(tokenV2);
        assert(decoded.expires == jwtPayload1.expires, 'expiry time should be equal');
        assert(decoded.iat > ((Date.now()/1000) - 5), 'jwt should have been issued in the last few seconds');
        assert(decoded.clientId == testUser2.clientId, 'clientId should be the same as testUser2');
        assert(decoded.userId == testUser2.userId, 'userId should be the same as testUser2');
    });

    it('should attempt both secrets for each token', function() {
        var decodedV1 = decoder.decodeToken(tokenV1);
        assert(decodedV1.expires == jwtPayload1.expires, 'expiry time should be equal');
        assert(decodedV1.iat > ((Date.now()/1000) - 5), 'jwt should have been issued in the last few seconds');
        assert(decodedV1.clientId == testUser1.clientId, 'clientId should be the same as testUser1');
        assert(decodedV1.userId == testUser1.userId, 'userId should be the same as testUser1');

        var decodedV2 = decoder.decodeToken(tokenV2);
        assert(decodedV2.expires == jwtPayload1.expires, 'expiry time should be equal');
        assert(decodedV2.iat > ((Date.now()/1000) - 5), 'jwt should have been issued in the last few seconds');
        assert(decodedV2.clientId == testUser2.clientId, 'clientId should be the same as testUser2');
        assert(decodedV2.userId == testUser2.userId, 'userId should be the same as testUser2');
    });

    it('should return the clientIds for both tokens', function() {
        var testUser1ClientId = decoder.getClientIdFromToken(tokenV1);
        assert(testUser1ClientId == testUser1.clientId);

        var testUser2ClientId = decoder.getClientIdFromToken(tokenV2);
        assert(testUser2ClientId == testUser2.clientId);
    });

    it('should return false when an unverified token is used', function() {
        var decoded = decoder.decodeToken(randomToken);
        assert(decoded == false, 'there should be no token decoded');
    });

    it('should return false when an unverified token is used to get a client Id', function() {
        var decoded = decoder.getClientIdFromToken(randomToken);
        assert(decoded == false, 'there should be client ID returned');
    });

});

