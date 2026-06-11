const express = require('express');
const {
  getClientById,
  verifyClientCredentials,
  getAuthorizationCode,
  markAuthorizationCodeUsed,
  getUserById,
  storeToken,
  getToken,
  generateRefreshToken,
  revokeToken
} = require('../data');
const { signAccessToken } = require('../jwt');
const { verifyCodeChallenge } = require('../pkce');
const config = require('../config');

const router = express.Router();

function parseBasicAuth(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Basic ')) return null;
  const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
  const [clientId, ...rest] = decoded.split(':');
  const clientSecret = rest.join(':');
  return { client_id: clientId, client_secret: clientSecret };
}

function extractClientAuth(req) {
  const basic = parseBasicAuth(req);
  if (basic) return basic;
  if (req.body && req.body.client_id) {
    return {
      client_id: req.body.client_id,
      client_secret: req.body.client_secret || null
    };
  }
  return null;
}

router.post('/token', express.urlencoded({ extended: true }), async (req, res) => {
  const { grant_type, code, redirect_uri, code_verifier, refresh_token, scope } = req.body;

  const clientAuth = extractClientAuth(req);
  if (!clientAuth || !clientAuth.client_id) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Client authentication is required'
    });
  }

  const client = getClientById(clientAuth.client_id);
  if (!client) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Unknown client'
    });
  }

  if (client.client_type === 'confidential') {
    if (!verifyClientCredentials(clientAuth.client_id, clientAuth.client_secret)) {
      return res.status(401).json({
        error: 'invalid_client',
        error_description: 'Invalid client credentials'
      });
    }
  }

  if (grant_type === 'authorization_code') {
    return handleAuthorizationCodeGrant(req, res, client, code, redirect_uri, code_verifier);
  } else if (grant_type === 'refresh_token') {
    return handleRefreshTokenGrant(req, res, client, refresh_token, scope);
  } else {
    return res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Only authorization_code and refresh_token grants are supported (OAuth 2.1)'
    });
  }
});

async function handleAuthorizationCodeGrant(req, res, client, code, redirect_uri, code_verifier) {
  if (!code) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'code is required'
    });
  }

  if (!redirect_uri) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'redirect_uri is required'
    });
  }

  if (!code_verifier) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'code_verifier is required (PKCE)'
    });
  }

  const authCode = getAuthorizationCode(code);
  if (!authCode) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Invalid authorization code'
    });
  }

  if (authCode.used === 1) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Authorization code has already been used'
    });
  }

  const now = Math.floor(Date.now() / 1000);
  if (authCode.expires_at < now) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Authorization code has expired'
    });
  }

  if (authCode.client_id !== client.client_id) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Authorization code was not issued to this client'
    });
  }

  if (authCode.redirect_uri !== redirect_uri) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'redirect_uri does not match'
    });
  }

  if (authCode.code_challenge_method === 'S256') {
    if (!verifyCodeChallenge(code_verifier, authCode.code_challenge)) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'PKCE verification failed'
      });
    }
  } else {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Unsupported code challenge method'
    });
  }

  markAuthorizationCodeUsed(authCode.id);

  const user = getUserById(authCode.user_id);
  if (!user) {
    return res.status(400).json({
      error: 'server_error',
      error_description: 'User not found'
    });
  }

  const refreshTokenValue = generateRefreshToken();
  const refreshExpiresAt = Math.floor(Date.now() / 1000) + config.refreshTokenTTL;

  const accessTokenPayload = {
    sub: user.sub,
    scope: authCode.scope,
    client_id: client.client_id,
    username: user.username,
    name: user.name,
    email: user.email
  };

  const accessToken = await signAccessToken(accessTokenPayload);

  storeToken('access_token', accessToken, client.client_id, user.id, authCode.scope,
    Math.floor(Date.now() / 1000) + config.accessTokenTTL, refreshTokenValue);

  storeToken('refresh_token', refreshTokenValue, client.client_id, user.id, authCode.scope,
    refreshExpiresAt, null);

  return res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: config.accessTokenTTL,
    refresh_token: refreshTokenValue,
    scope: authCode.scope
  });
}

async function handleRefreshTokenGrant(req, res, client, refreshTokenValue, scope) {
  if (!refreshTokenValue) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'refresh_token is required'
    });
  }

  const oldRefreshToken = getToken(refreshTokenValue);
  if (!oldRefreshToken || oldRefreshToken.token_type !== 'refresh_token') {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Invalid refresh token'
    });
  }

  if (oldRefreshToken.revoked === 1) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Refresh token has been revoked'
    });
  }

  const now = Math.floor(Date.now() / 1000);
  if (oldRefreshToken.expires_at && oldRefreshToken.expires_at < now) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Refresh token has expired'
    });
  }

  if (oldRefreshToken.client_id !== client.client_id) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Refresh token was not issued to this client'
    });
  }

  let newScope = oldRefreshToken.scope;
  if (scope) {
    const requestedScopes = scope.split(' ');
    const originalScopes = oldRefreshToken.scope.split(' ');
    const allValid = requestedScopes.every(s => originalScopes.includes(s));
    if (!allValid) {
      return res.status(400).json({
        error: 'invalid_scope',
        error_description: 'Requested scope exceeds original scope'
      });
    }
    newScope = scope;
  }

  const user = getUserById(oldRefreshToken.user_id);
  if (!user) {
    return res.status(400).json({
      error: 'server_error',
      error_description: 'User not found'
    });
  }

  const newRefreshTokenValue = generateRefreshToken();
  const refreshExpiresAt = Math.floor(Date.now() / 1000) + config.refreshTokenTTL;

  const accessTokenPayload = {
    sub: user.sub,
    scope: newScope,
    client_id: client.client_id,
    username: user.username,
    name: user.name,
    email: user.email
  };

  const newAccessToken = await signAccessToken(accessTokenPayload);

  storeToken('access_token', newAccessToken, client.client_id, user.id, newScope,
    Math.floor(Date.now() / 1000) + config.accessTokenTTL, newRefreshTokenValue);

  storeToken('refresh_token', newRefreshTokenValue, client.client_id, user.id, newScope,
    refreshExpiresAt, null);

  revokeToken(refreshTokenValue);

  return res.json({
    access_token: newAccessToken,
    token_type: 'Bearer',
    expires_in: config.accessTokenTTL,
    refresh_token: newRefreshTokenValue,
    scope: newScope
  });
}

module.exports = router;
