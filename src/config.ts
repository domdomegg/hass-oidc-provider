import fs from 'node:fs';

export type Config = {
	/** URL of the Home Assistant instance (default: http://localhost:8123) */
	hassUrl: string;
	/** Public URL of this gateway (used as issuer), e.g. https://oidc.home.example.com */
	externalUrl: string;
	/** OAuth client ID for HA (defaults to externalUrl) */
	clientId?: string;
	/** JWK private key JSON for persistent signing (generated at startup if omitted) */
	signingKey?: string;
	/** Port to listen on (default 3001) */
	port?: number;
	/** Host to bind to (default 0.0.0.0) */
	host?: string;
};

const DEFAULT_CONFIG_PATH = 'hass-oidc-provider.config.json';

export const loadConfig = (): Config => {
	let configStr = process.env.HASS_OIDC_CONFIG;

	if (!configStr && fs.existsSync(DEFAULT_CONFIG_PATH)) {
		configStr = DEFAULT_CONFIG_PATH;
	}

	if (!configStr) {
		console.error('No config found. Set HASS_OIDC_CONFIG or create hass-oidc-provider.config.json');
		process.exit(1);
	}

	let raw: Record<string, unknown>;
	try {
		const parsed: unknown = JSON.parse(configStr);
		if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
			raw = parsed as Record<string, unknown>;
		} else {
			throw new Error('not a config object');
		}
	} catch {
		const json = fs.readFileSync(configStr, 'utf-8');
		raw = JSON.parse(json) as Record<string, unknown>;
	}

	if (!raw.externalUrl || typeof raw.externalUrl !== 'string') {
		throw new Error('Config must have an "externalUrl" string');
	}

	const hassUrl = typeof raw.hassUrl === 'string' ? raw.hassUrl : 'http://localhost:8123';

	return {
		hassUrl: hassUrl.replace(/\/$/, ''),
		externalUrl: raw.externalUrl.replace(/\/$/, ''),
		...(typeof raw.clientId === 'string' && {clientId: raw.clientId}),
		...(typeof raw.signingKey === 'string' && {signingKey: raw.signingKey}),
		...(typeof raw.port === 'number' && {port: raw.port}),
		...(typeof raw.host === 'string' && {host: raw.host}),
	};
};
