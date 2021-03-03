--
-- JWT Validation implementation for HAProxy Lua host
--
-- Copyright (c) 2019. Adis Nezirovic <anezirovic@haproxy.com>
-- Copyright (c) 2019. Baptiste Assmann <bassmann@haproxy.com>
-- Copyright (c) 2019. Nick Ramirez <nramirez@haproxy.com>
-- Copyright (c) 2019. HAProxy Technologies LLC
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--    http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- Use HAProxy 'lua-load' to load optional configuration file which
-- should contain config table.
-- Default/fallback config
if not config then
  config = {
      debug = true,
      publicKey = nil,
      issuer = nil,
      audience = nil,
      hmacSecret = nil,
      authHeader = "Authorization"
  }
end

local asn_sequence = require 'asn_sequence'
local json   = require 'cjson'
local base64 = require 'base64'
local openssl = {
  pkey = require 'openssl.pkey',
  digest = require 'openssl.digest',
  x509 = require 'openssl.x509',
  hmac = require 'openssl.hmac'
}

local function log(msg)
  if config.debug then
      core.Debug(tostring(msg))
  end
end

local function dump(o)
  if type(o) == 'table' then
     local s = '{ '
     for k,v in pairs(o) do
        if type(k) ~= 'number' then k = '"'..k..'"' end
        s = s .. '['..k..'] = ' .. dump(v) .. ','
     end
     return s .. '} '
  else
     return tostring(o)
  end
end

function readAll(file)
  log("Reading file " .. file)
  local f = assert(io.open(file, "rb"))
  local content = f:read("*all")
  f:close()
  return content
end

local function decodeJwt(authorizationHeader)
  local headerFields = core.tokenize(authorizationHeader, " .")
  local headerFieldsStart = 1
  
  if config.authHeader == "Authorization" then
    headerFieldsStart = 2
    
    if #headerFields ~= 4 then
      log("Improperly formated Authorization header. Should be 'Bearer' followed by 3 token sections.")
      return nil
    end
    
    if headerFields[1] ~= 'Bearer' then
      log("Improperly formatted Authorization header. Missing 'Bearer' property.")
      return nil
    end
  elseif #headerFields ~= 3 then
    log("The base64 encoded JWT token should contain 3 sections separated with a period (.).")
    return nil
  end

  local token = {}
  token.header = headerFields[headerFieldsStart]
  token.payload = headerFields[headerFieldsStart + 1]
  token.signature = headerFields[headerFieldsStart + 2]
  
  -- Decode JSON
  local ok, header, claims, signature = pcall(function()
    return json.decode(base64.decode(token.header)),
           json.decode(base64.decode(token.payload)),
           base64.decode(token.signature)
  end)
  if not ok then
    log("invalid JSON")
    return nil
  end
  
  token.headerdecoded = header
  token.payloaddecoded = claims
  token.signaturedecoded = signature
  
  log('Authorization header: ' .. authorizationHeader)
  log('Decoded JWT header: ' .. dump(token.headerdecoded))
  log('Decoded JWT payload: ' .. dump(token.payloaddecoded))

  return token
end

local function algorithmIsValid(token)
  if token.headerdecoded.alg == nil then
      log("No 'alg' provided in JWT header.")
      return false
  elseif token.headerdecoded.alg ~= 'HS256' and token.headerdecoded.alg ~= 'RS256' and token.headerdecoded.alg ~= 'ES256' then
      log("HS256, RS256 and ES256 supported. Incorrect alg in JWT: " .. token.headerdecoded.alg)
      return false
  end

  return true
end

--- Verify a JWT signature
--- Snippet fully attributed to Kong jwt_parser: https://github.com/Kong/kong/blob/master/kong/plugins/jwt/jwt_parser.lua
local function es256SignatureIsValid(token, publicKey)
  local pkey, _ = openssl.pkey.new(publicKey)
  if #token.signaturedecoded ~= 64 then
      log("Signature must be 64 bytes.")
      return false
  end
  local asn = {}
  asn[1] = asn_sequence.resign_integer(string.sub(token.signaturedecoded, 1, 32))
  asn[2] = asn_sequence.resign_integer(string.sub(token.signaturedecoded, 33, 64))
  local signatureAsn = asn_sequence.create_simple_sequence(asn)
  local digest = openssl.digest.new("sha256")
  digest:update(token.header .. '.' .. token.payload)
  return pkey:verify(signatureAsn, digest)
end

local function rs256SignatureIsValid(token, publicKey)
  local digest = openssl.digest.new('SHA256')
  digest:update(token.header .. '.' .. token.payload)
  local vkey = openssl.pkey.new(publicKey)
  local isVerified = vkey:verify(token.signaturedecoded, digest)
  return isVerified
end

local function hs256SignatureIsValid(token, secret)
  local hmac = openssl.hmac.new(secret, 'SHA256')
  local checksum = hmac:final(token.header .. '.' .. token.payload)
  return checksum == token.signaturedecoded
end

local function expirationIsValid(token)
  return os.difftime(token.payloaddecoded.exp, core.now().sec) > 0
end

local function issuerIsValid(token, expectedIssuer)
  return token.payloaddecoded.iss == expectedIssuer
end

local function audienceIsValid(token, expectedAudience)
  return token.payloaddecoded.aud == expectedAudience
end

function jwtverify(txn)
  local issuer = config.issuer
  local audience = config.audience
  local hmacSecret = config.hmacSecret
  local pem = config.publicKey -- by default a single certificate is provided

  -- 1. Decode and parse the JWT
  local token = decodeJwt(txn.sf:req_hdr(config.authHeader))

  if token == nil then
    log("Token could not be decoded from " .. config.authHeader .. " header.")
    goto out
  end

  if type(config.publicKey) == 'table' then
    pem = config.publicKey[token.headerdecoded.kid] -- pem file can be a map of key Id to PEM
  end

  -- 2. Verify the signature algorithm is supported (HS256, RS256)
  if algorithmIsValid(token) == false then
      log("Algorithm not valid.")
      goto out
  end
  
  -- 3. Verify the signature with the certificate
  if token.headerdecoded.alg == 'RS256' then
    if rs256SignatureIsValid(token, pem) == false then
      log("Signature not valid.")
      goto out
    end
  elseif token.headerdecoded.alg == 'HS256' then
    if hs256SignatureIsValid(token, hmacSecret) == false then
      log("Signature not valid.")
      goto out
    end
  elseif token.headerdecoded.alg == 'ES256' then
    if es256SignatureIsValid(token, pem) == false then
      log("Signature not valid.")
      goto out
    end
  end

  -- 4. Verify that the token is not expired
  if expirationIsValid(token) == false then
    log("Token is expired.")
    goto out
  end

  -- 5. Verify the issuer
  if issuer ~= nil and issuerIsValid(token, issuer) == false then
    log("Issuer not valid.")
    goto out
  end

  -- 6. Verify the audience
  if audience ~= nil and audienceIsValid(token, audience) == false then
    log("Audience not valid.")
    goto out
  end

  -- 7. Add scopes to variable
  if token.payloaddecoded.scope ~= nil then
    txn.set_var(txn, "txn.oauth_scopes", token.payloaddecoded.scope)
  else
    txn.set_var(txn, "txn.oauth_scopes", "")
  end

  -- 8. Set authorized variable
  log("req.authorized = true")
  txn.set_var(txn, "txn.authorized", true)

  -- exit
  do return end

  -- way out. Display a message when running in debug mode
::out::
 log("req.authorized = false")
 txn.set_var(txn, "txn.authorized", false)
end

-- Called after the configuration is parsed.
-- Loads the OAuth public key for validating the JWT signature.
core.register_init(function()
config.issuer = os.getenv("OAUTH_ISSUER")
config.audience = os.getenv("OAUTH_AUDIENCE")

-- when using an RS256 signature
local publicKeyPath = os.getenv("OAUTH_PUBKEY_PATH") 
local pem = readAll(publicKeyPath)
if publicKeyPath:match(".json$") then
    config.publicKey = json.decode(pem)
else
    config.publicKey = pem
end

-- when using an HS256 signature
config.hmacSecret = os.getenv("OAUTH_HMAC_SECRET")

-- optionally override bearer token header name
local authHeaderName = os.getenv("OAUTH_AUTH_HEADER_NAME")
if (authHeaderName ~= nil and authHeaderName ~= '') then
    config.authHeader = authHeaderName
end

log("PublicKeyPath: " .. publicKeyPath)
log("Issuer: " .. (config.issuer or "<none>"))
log("Audience: " .. (config.audience or "<none>"))
log("JWT Header: " .. (config.authHeader or "<none>"))
end)

-- Called on a request.
core.register_action('jwtverify', {'http-req'}, jwtverify, 0)
