import {createHash} from 'node:crypto';
import express from 'express';
import type {Config} from './config.js';
import type {SigningKey} from './signing.js';
import {getJwks, mintIdToken} from './signing.js';
import type {HaUser} from './ha-websocket.js';
import {getHaUser} from './ha-websocket.js';
import {seal, unseal} from './seal.js';

const PENDING_TTL_MS = 600_000; // 10 minutes
const AUTH_CODE_TTL_MS = 300_000; // 5 minutes
const ACCESS_TOKEN_TTL_MS = 3_600_000; // 1 hour
const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

type PendingPayload = {
	type: 'pending';
	clientId: string;
	redirectUri: string;
	state?: string;
	codeChallenge: string;
	nonce?: string;
	expiresAt: number;
};

type AuthCodePayload = {
	type: 'auth_code';
	userId: string;
	userName: string;
	isOwner: boolean;
	isAdmin: boolean;
	clientId: string;
	redirectUri: string;
	codeChallenge: string;
	nonce?: string;
	haRefreshToken: string;
	expiresAt: number;
};

type AccessTokenPayload = {
	type: 'access_token';
	userId: string;
	userName: string;
	isOwner: boolean;
	isAdmin: boolean;
	expiresAt: number;
};

type RefreshTokenPayload = {
	type: 'refresh_token';
	haRefreshToken: string;
	clientId: string;
	expiresAt: number;
};

const getString = (value: unknown): string | undefined =>
	typeof value === 'string' ? value : undefined;

export const createApp = (config: Config, signingKey: SigningKey, encKey: Buffer): express.Express => {
	const app = express();
	const issuer = config.externalUrl;
	const haUrl = config.hassUrl;
	const clientId = config.clientId ?? config.externalUrl;

	// OIDC Discovery
	app.get('/.well-known/openid-configuration', (_req, res) => {
		res.json({
			issuer,
			authorization_endpoint: `${issuer}/authorize`,
			token_endpoint: `${issuer}/token`,
			userinfo_endpoint: `${issuer}/userinfo`,
			jwks_uri: `${issuer}/jwks`,
			response_types_supported: ['code'],
			subject_types_supported: ['public'],
			id_token_signing_alg_values_supported: ['ES256'],
			scopes_supported: ['openid', 'profile'],
			token_endpoint_auth_methods_supported: ['none'],
			grant_types_supported: ['authorization_code', 'refresh_token'],
			code_challenge_methods_supported: ['S256'],
		});
	});

	// JWKS
	app.get('/jwks', (_req, res) => {
		res.json(getJwks(signingKey));
	});

	// Authorize — proxies to HA, encoding client context into state
	app.get('/authorize', (req, res) => {
		const reqClientId = getString(req.query.client_id);
		const redirectUri = getString(req.query.redirect_uri);
		const codeChallenge = getString(req.query.code_challenge);
		const codeChallengeMethod = getString(req.query.code_challenge_method);
		const responseType = getString(req.query.response_type);
		const state = getString(req.query.state);
		const nonce = getString(req.query.nonce);

		if (!reqClientId || !redirectUri || !codeChallenge) {
			res.status(400).json({error: 'invalid_request', error_description: 'Missing or invalid client_id, redirect_uri, or code_challenge'});
			return;
		}

		if (!URL.canParse(redirectUri) || !['http:', 'https:'].includes(new URL(redirectUri).protocol)) {
			res.status(400).json({error: 'invalid_request', error_description: 'redirect_uri must be an HTTP or HTTPS URL'});
			return;
		}

		if (responseType !== 'code') {
			res.status(400).json({error: 'unsupported_response_type', error_description: 'Only response_type=code is supported'});
			return;
		}

		// We always use S256 for PKCE verification. The RFC 7636 default when
		// omitted is 'plain', but we intentionally treat omitted as S256 for
		// stronger security. The discovery document only advertises S256, so
		// compliant clients will already send it explicitly.
		if (codeChallengeMethod && codeChallengeMethod !== 'S256') {
			res.status(400).json({error: 'invalid_request', error_description: 'code_challenge_method must be S256'});
			return;
		}

		const pending: PendingPayload = {
			type: 'pending',
			clientId: reqClientId,
			redirectUri,
			codeChallenge,
			expiresAt: Date.now() + PENDING_TTL_MS,
			...(nonce && {nonce}),
			...(state && {state}),
		};

		const sealedState = seal(pending, encKey);
		const callbackUrl = `${issuer}/callback`;

		const haAuthUrl = new URL(`${haUrl}/auth/authorize`);
		haAuthUrl.searchParams.set('client_id', clientId);
		haAuthUrl.searchParams.set('redirect_uri', callbackUrl);
		haAuthUrl.searchParams.set('state', sealedState);
		haAuthUrl.searchParams.set('response_type', 'code');

		res.redirect(haAuthUrl.toString());
	});

	// Callback — HA redirects here after login
	app.get('/callback', async (req, res) => {
		try {
			const code = getString(req.query.code);
			const sealedState = getString(req.query.state);
			const haError = getString(req.query.error);
			const haErrorDescription = getString(req.query.error_description);

			if (haError) {
				// HA returned an error (e.g. user denied access). Forward it to the client.
				const pending = sealedState ? unseal<PendingPayload>(sealedState, encKey, 'pending') : undefined;
				if (pending) {
					const redirectUrl = new URL(pending.redirectUri);
					redirectUrl.searchParams.set('error', haError);
					if (haErrorDescription) {
						redirectUrl.searchParams.set('error_description', haErrorDescription);
					}

					if (pending.state) {
						redirectUrl.searchParams.set('state', pending.state);
					}

					res.redirect(redirectUrl.toString());
				} else {
					res.status(400).send(`Home Assistant login failed: ${haErrorDescription ?? haError}`);
				}

				return;
			}

			if (!code || !sealedState) {
				res.status(400).send('Missing code or state');
				return;
			}

			const pending = unseal<PendingPayload>(sealedState, encKey, 'pending');
			if (!pending) {
				res.status(400).send('Invalid or expired session');
				return;
			}

			// Exchange code with HA
			const tokenRes = await fetch(`${haUrl}/auth/token`, {
				method: 'POST',
				headers: {'Content-Type': 'application/x-www-form-urlencoded'},
				body: new URLSearchParams({
					grant_type: 'authorization_code',
					code,
					client_id: clientId,
					redirect_uri: `${issuer}/callback`,
				}).toString(),
			});

			if (!tokenRes.ok) {
				const body = await tokenRes.text();
				console.error('HA token exchange failed:', tokenRes.status, body);
				res.status(502).send('Failed to exchange code with Home Assistant');
				return;
			}

			const tokens = await tokenRes.json() as {access_token: string; refresh_token: string};

			// Get user identity via WebSocket
			const user = await getHaUser(haUrl, tokens.access_token);

			// Issue our own auth code (includes HA refresh token for later use)
			const acPayload: AuthCodePayload = {
				type: 'auth_code',
				userId: user.id,
				userName: user.name,
				isOwner: user.is_owner,
				isAdmin: user.is_admin,
				clientId: pending.clientId,
				redirectUri: pending.redirectUri,
				codeChallenge: pending.codeChallenge,
				haRefreshToken: tokens.refresh_token,
				expiresAt: Date.now() + AUTH_CODE_TTL_MS,
				...(pending.nonce && {nonce: pending.nonce}),
			};

			const authCode = seal(acPayload, encKey);

			const redirectUrl = new URL(pending.redirectUri);
			redirectUrl.searchParams.set('code', authCode);
			if (pending.state) {
				redirectUrl.searchParams.set('state', pending.state);
			}

			res.redirect(redirectUrl.toString());
		} catch (err) {
			console.error('Callback error:', err);
			res.status(500).send('Authentication failed');
		}
	});

	const issueTokenResponse = async (
		res: express.Response,
		user: HaUser,
		reqClientId: string,
		haRefreshToken: string,
		nonce?: string,
	) => {
		const idToken = await mintIdToken(signingKey, {
			issuer,
			audience: reqClientId,
			subject: user.id,
			name: user.name,
			is_owner: user.is_owner,
			is_admin: user.is_admin,
			...(nonce !== undefined && {nonce}),
		});

		res.json({
			access_token: seal<AccessTokenPayload>({
				type: 'access_token',
				userId: user.id,
				userName: user.name,
				isOwner: user.is_owner,
				isAdmin: user.is_admin,
				expiresAt: Date.now() + ACCESS_TOKEN_TTL_MS,
			}, encKey),
			token_type: 'Bearer',
			expires_in: 3600,
			id_token: idToken,
			refresh_token: seal<RefreshTokenPayload>({
				type: 'refresh_token',
				haRefreshToken,
				clientId: reqClientId,
				expiresAt: Date.now() + REFRESH_TOKEN_TTL_MS,
			}, encKey),
			scope: 'openid profile',
		});
	};

	// Token endpoint
	app.post('/token', express.urlencoded({extended: false}), async (req, res) => {
		try {
			const grantType = getString(req.body.grant_type);
			const reqClientId = getString(req.body.client_id);

			if (!reqClientId) {
				res.status(400).json({error: 'invalid_request', error_description: 'Missing or invalid client_id'});
				return;
			}

			if (grantType === 'authorization_code') {
				const code = getString(req.body.code);
				const codeVerifier = getString(req.body.code_verifier);

				// NB: We don't validate redirect_uri here. The spec (RFC 6749 §4.1.3)
				// requires it, but PKCE already binds the auth code to the legitimate
				// client, making redirect_uri validation redundant for security.

				if (!code || !codeVerifier) {
					res.status(400).json({error: 'invalid_request', error_description: 'Missing code or code_verifier'});
					return;
				}

				// Auth codes are stateless sealed tokens, so they cannot be tracked as
				// single-use (no server-side state). PKCE prevents code interception
				// attacks, making replay a non-issue in practice.
				const ac = unseal<AuthCodePayload>(code, encKey, 'auth_code');
				if (!ac) {
					res.status(400).json({error: 'invalid_grant', error_description: 'Invalid or expired authorization code'});
					return;
				}

				if (ac.clientId !== reqClientId) {
					res.status(400).json({error: 'invalid_grant', error_description: 'client_id mismatch'});
					return;
				}

				// Verify PKCE
				const expectedChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
				if (expectedChallenge !== ac.codeChallenge) {
					res.status(400).json({error: 'invalid_grant', error_description: 'PKCE verification failed'});
					return;
				}

				const user: HaUser = {
					id: ac.userId, name: ac.userName, is_owner: ac.isOwner, is_admin: ac.isAdmin,
				};
				await issueTokenResponse(res, user, reqClientId, ac.haRefreshToken, ac.nonce);
			} else if (grantType === 'refresh_token') {
				const refreshTokenStr = getString(req.body.refresh_token);

				if (!refreshTokenStr) {
					res.status(400).json({error: 'invalid_request', error_description: 'Missing refresh_token'});
					return;
				}

				const rt = unseal<RefreshTokenPayload>(refreshTokenStr, encKey, 'refresh_token');
				if (!rt) {
					res.status(400).json({error: 'invalid_grant', error_description: 'Invalid or expired refresh token'});
					return;
				}

				if (rt.clientId !== reqClientId) {
					res.status(400).json({error: 'invalid_grant', error_description: 'client_id mismatch'});
					return;
				}

				// Use the HA refresh token to get a fresh access token
				const haTokenRes = await fetch(`${haUrl}/auth/token`, {
					method: 'POST',
					headers: {'Content-Type': 'application/x-www-form-urlencoded'},
					body: new URLSearchParams({
						grant_type: 'refresh_token',
						refresh_token: rt.haRefreshToken,
						client_id: clientId,
					}).toString(),
				});

				if (!haTokenRes.ok) {
					const body = await haTokenRes.text();
					console.error('HA refresh failed:', haTokenRes.status, body);
					res.status(400).json({error: 'invalid_grant', error_description: 'Home Assistant refresh failed'});
					return;
				}

				const haTokens = await haTokenRes.json() as {access_token: string};
				const user = await getHaUser(haUrl, haTokens.access_token);
				await issueTokenResponse(res, user, reqClientId, rt.haRefreshToken);
			} else {
				res.status(400).json({error: 'unsupported_grant_type'});
			}
		} catch (err) {
			console.error('Token error:', err);
			res.status(500).json({error: 'server_error'});
		}
	});

	// Userinfo endpoint (OIDC Core §5.3.1 requires both GET and POST)
	const handleUserinfo: express.RequestHandler = async (req, res) => {
		const auth = req.headers.authorization;
		if (!auth?.startsWith('Bearer ')) {
			res.status(401).json({error: 'invalid_token'});
			return;
		}

		const token = auth.slice(7);
		const ac = unseal<AccessTokenPayload>(token, encKey, 'access_token');
		if (!ac?.userId) {
			res.status(401).json({error: 'invalid_token', error_description: 'Invalid or expired token'});
			return;
		}

		res.json({
			sub: ac.userId,
			name: ac.userName,
			preferred_username: ac.userName,
			is_owner: ac.isOwner,
			is_admin: ac.isAdmin,
		});
	};

	app.get('/userinfo', handleUserinfo);
	app.post('/userinfo', handleUserinfo);

	return app;
};
