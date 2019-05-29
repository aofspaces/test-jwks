import express from 'express'
import bodyParser from 'body-parser'
import { pem2jwk } from 'pem-jwk'
import jwksRsa from 'jwks-rsa'
import jwt from 'jsonwebtoken'
import exJwt from 'express-jwt'
import jwkToPem from 'jwk-to-pem'
import fs from 'fs'

const PORT = 3000
const KEY_ID = 'jwt-auth'

var app = express()

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }))
// parse application/json
app.use(bodyParser.json())

//## Auth routes
// Auth :: GET
// - Get token
function getToken(req, res) {
  const certs = JSON.parse(fs.readFileSync('certs.json'));
  const privateJwk = jwkToPem(certs.keys[0], { private: true });
  const token = jwt.sign({
    id: 1,
    username: 'test'
  }, privateJwk, {
    header: {
      kid: KEY_ID
    },
    algorithm: 'RS256',
    expiresIn: '4h',
    issuer: "http://localhost:3000"
  });

  res.status(200).json({token})
}
// Auth :: POST
// - Verify token
function verifyToken(req, res) {
  res.status(200).json('verify')
}

app.route('/auth')
  .get(getToken)
  .post(exJwt({
    // Dynamically provide a signing key based on the kid in the header and the singing keys provided by the JWKS endpoint.
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: 'http://localhost:3000/jwks'
    }),

    // Validate the audience and the issuer.
    // audience: 'urn:my-resource-server',
    // issuer: 'http://localhost:3000',
    algorithms: [ 'RS256' ]
  }), verifyToken)

//## JWKS
// JWKS :: GET
// - get jwks data
function getJWKS(req, res) {
  const cert = fs.readFileSync('private.pem')
  let jwk = pem2jwk(cert)
  jwk.use = 'sig'
  jwk.kid = KEY_ID
  res.status(200).json({
    keys: [jwk]
  })
}
app.route('/jwks').get(getJWKS)

// Start App
app.listen(PORT, () => console.log(`App listening on port ${PORT}!`))