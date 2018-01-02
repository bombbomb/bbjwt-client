# bbjwt-client

This module is used to authenticate JSON Web Tokens created by the BombBomb API in NodeJS services.

Install this module into your project with `npm install bbjwt-client --save`.

As of v0.5.3 support new OAuth2 tokens, see http://developer.bombbomb.com/auth/
```js
var token = req.headers.authorization; // or however you intake your token

var bbjwt = require("bbjwt-client");
bbjwt.getClientIdFromToken(token,function(err, clientId){
    if (err)
    {
        console.error("Bad Token " + err);
    }
    else
    {
        console.log("The trusted clientId is: " + clientId);
    }
});
```


Prior to v0.5.2
You then include it in your project like so: 
```js
var token = req.headers.jwt; // or however you intake your token

var bbjwt = require("bbjwt-client");
var clientId = bbjwt.getClientIdFromToken(token);
// clientId will be false if the token doesn't check out
if (clientId==false)
{
  returnError(res, "Bad Token!");
}
console.log("The trusted clientId is: " + clientId);
```

*You must to provide the shared secret for signature validation by setting the environment variable* `JWT_SECRET`.

Get a token by making an authenticated call to `https://app.bombbomb.com/app/api/api.php?method=GetJsonWebToken`
