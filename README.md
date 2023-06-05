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

RipSecrets<br><br>
We implement pipeline secret scanning on all pull request events to prevent credentials from being merged. If the pipeline scanner detects a secret in your changed files it will gate the pull request and you will need to purge the found credential from your code and re-open the PR. To prevent getting gated by this tool and as best practice you should install the secret scanner locally in a pre-commit hook to prevent the secret from ever being committed to the repo in the first place. You can find documentation on how to set it up locally [here](https://bombbomb.atlassian.net/wiki/spaces/CORE/pages/2039775312/Pipeline+Secret+Scanner+Local+Setup)<br>
Ripsecrets has ways to bypass secret scanning although we should not be ignoring secrets that turn up in the scans. If something is out of your control and blocking the pipeline you can bypass it in one of the following ways<br>
1. Adding "# pragma: allowlist secret" to the end of the line with the secret.<br>
2. Adding the specific secret underneath the "[secrets]" block in .secretsignore<br>
3. Adding the filepath to ignore the whole file aboove the "[secrets]" block in .secretsignore