#!/usr/bin/env node
import {loadConfig} from './config.js';
import {createSigningKey} from './signing.js';
import {deriveKey} from './seal.js';
import {createApp} from './server.js';

const main = async () => {
	const config = loadConfig();
	const signingKey = await createSigningKey(config.signingKey);
	const encKey = deriveKey(config.signingKey);
	const app = createApp(config, signingKey, encKey);

	const port = config.port ?? 3001;
	const host = config.host ?? '0.0.0.0';
	app.listen(port, host, () => {
		console.log(`hass-oidc-provider listening on ${host}:${port}`);
		console.log(`Home Assistant: ${config.hassUrl}`);
		console.log(`Issuer: ${config.externalUrl}`);
	});
};

main().catch((err: unknown) => {
	console.error(err);
	process.exit(1);
});
