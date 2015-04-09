# bbjwt-client

This module is used to authenticate JSON Web Tokens created by the BombBomb API in NodeJS services.

Install this module into your project with `npm install bbjwt-client --save`.

You then include it in your project like so: 
```js
var token = req.headers.jwt; // or however you intake your token

var bbjwt = require("bbjwt-client");
var clientId = bbjwt.getClientIdFromToken(token);
if (clientId==false) { //clientId will be false if the token doesn't check out
  returnError(res, "Bad Token!");
}
console.log("The trusted clientId is: " + clientId);
```
