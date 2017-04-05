var assert      = require('assert'),
    sinon       = require('sinon'),
    jwt         = require('jsonwebtoken'),
    mocha       = require('mocha'),
    proxyquire  = require('proxyquire'),
    KmsJwt      = require('kms-jwt'),
    testEnvVars = require('../test.env.inc.js');


var mockData = createV2JwtPayload();

KmsJwt.prototype.verify = function(token, callback)
{
    callback(null, mockData)
};

var decoder = proxyquire('../index', {
    'kms-jwt' : KmsJwt
});


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

function createV1JwtPayload(user)
{
    return {
        expires : '1h',
        clientId : user.clientId,
        userId : user.userId
    }
}

function createV2JwtPayload()
{
    return {
        "aud": "DevSiteApiClient",
        "jti": "blahblahblahblahblahblahblahblah",
        "nbf": (Date.now()/1000) + 60,
        "exp": (Date.now()/1000) + 60,
        "sub": "Random-User-Id",
        "scopes": [
            "email:manage",
            "email:read"
        ],
        "bbcid": "Random-Client-Id"
    }
}

describe('random test', function() {

    var testUser1, testUser2, jwtPayload1, jwtPayload2, tokenV1, tokenV2, randomToken;

    before(function() {
        process.env.JWT_SECRET = createRandomString(10);

        var publicTestKey = 'thisisatestkey';
        var randomSecret = createRandomString(20);

        testUser1 = createUserDetails();
        testUser2 = mockData;

        jwtPayload1 = createV1JwtPayload(testUser1);
        jwtPayload2 = createV2JwtPayload();

        tokenV1 = jwt.sign(jwtPayload1, process.env.JWT_SECRET);
        tokenV2 = jwt.sign(jwtPayload2, publicTestKey);
        randomToken = jwt.sign(jwtPayload1, randomSecret);

        var tokenSigner = new KmsJwt({
            awsConfig: {
                region: process.env.AWS_REGION,
                accessKeyId : process.env.AWS_ACCESS_KEY,
                secretAccessKey: process.env.AWS_SECRET_KEY
            },
            keyArn: process.env.KMS_ARN
        });

        tokenSigner.createSigningKey(publicTestKey, function(err, encryptedKey) {
            if(!err)
            {
                process.env.SIGNING_KEY = encryptedKey;
            }
        })

    });


    it('should decode v1 token', function() {
        var decoded = decoder.decodeV1Token(tokenV1);
        assert(decoded.expires == jwtPayload1.expires, 'expiry time should be equal');
        assert(decoded.iat > ((Date.now()/1000) - 60), 'jwt should have been issued in the last few seconds');
        assert(decoded.clientId == testUser1.clientId, 'clientId should be the same as testUser1');
        assert(decoded.userId == testUser1.userId, 'userId should be the same as testUser1');
    });

    it('should decode token using kms', function(done) {
        decoder.decodeWithKms(tokenV2, function(err, data) {
            assert(err == null, 'no errors should be returned');
            assert(data.aud == jwtPayload2.aud, 'object properties must match');
            assert(data.sub == jwtPayload2.sub, 'object properties must match');
            assert(data.jti == jwtPayload2.jti, 'object properties must match');
            assert(data.bbcid == jwtPayload2.bbcid, 'object properties must match');
            done();
        });
    });

    it('should return clientId from kms decode', function(done) {
        decoder.getClientIdFromToken(tokenV2, function(err, clientId) {
            assert(err == null, 'no errors should be returned');
            assert(clientId == testUser2.bbcid);
            done();
        })
    });

    it('using Bearer should return clientId from kms decode', function(done) {
        decoder.getClientIdFromToken('Bearer '+tokenV2, function(err, clientId) {
            assert(err == null, 'no errors should be returned');
            assert(clientId == testUser2.bbcid);
            done();
        })
    });

    it('should decode an encrypted token with v1 secret', function(done) {
        KmsJwt.prototype.verify = KmsJwt.verify;
        decoder.decodeToken(tokenV1, function(err, decoded) {
            assert(err == null, 'there should be no errors returned');
            assert(decoded.expires == jwtPayload1.expires, 'expiry time should be equal');
            assert(decoded.iat > ((Date.now()/1000) - 60), 'jwt should have been issued in the last few seconds');
            assert(decoded.clientId == testUser1.clientId, 'clientId should be the same as testUser1');
            assert(decoded.userId == testUser1.userId, 'userId should be the same as testUser1');
            done();
        })
    });

    it('should return a clientId from v1 token', function(done) {
        decoder.getClientIdFromToken(tokenV1, function(err, clientId) {
            assert(err == null, 'there should be no errors returned');
            assert(clientId == testUser1.clientId, 'clientId should be the same as testUser1');
            done();
        })
    });

    it('should return error from an undefined token', function(done) {
        var undefinedToken;
        decoder.getClientIdFromToken(undefinedToken, function(err, clientId) {
            assert(clientId == null, 'no client id should be coming back from null JWT');
            assert(err == 'JWT : Error retrieving clientId, token undefined/missing data?');
            done();
        });
    });

    it('should return error from a junk token', function(done) {
        var junkToken = 'thisisjunkman';
        decoder.getClientIdFromToken(junkToken, function(err, clientId) {
            assert(clientId == null, 'no client id should be coming back from null JWT');
            assert(err.message == 'jwt malformed');
            assert(err.name == 'JsonWebTokenError');
            done();
        });
    })


});

