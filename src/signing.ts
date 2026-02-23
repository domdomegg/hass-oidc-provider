import {
	exportJWK, generateKeyPair, importJWK, SignJWT,
} from 'jose';
import type {JWK} from 'jose';

export type SigningKey = {
	privateKey: CryptoKey;
	publicJwk: JWK;
};

const ALG = 'ES256';
const KID = 'default';

export const createSigningKey = async (jwkJson?: string): Promise<SigningKey> => {
	let privateKey: CryptoKey;
	let baseJwk: JWK;

	const stripPrivateFields = (jwk: JWK): JWK =>
		Object.fromEntries(Object.entries(jwk).filter(([k]) => !['d', 'key_ops', 'ext'].includes(k))) as JWK;

	if (jwkJson) {
		const jwk = JSON.parse(jwkJson) as JWK;
		privateKey = await importJWK(jwk, ALG) as CryptoKey;
		baseJwk = stripPrivateFields(jwk);
	} else {
		const keyPair = await generateKeyPair(ALG);
		privateKey = keyPair.privateKey;
		baseJwk = stripPrivateFields(await exportJWK(keyPair.publicKey));
	}

	return {
		privateKey,
		publicJwk: {
			...baseJwk, kid: KID, use: 'sig', alg: ALG,
		},
	};
};

export const getJwks = (key: SigningKey): {keys: JWK[]} => ({
	keys: [key.publicJwk],
});

export const mintIdToken = async (
	key: SigningKey,
	claims: {
		issuer: string;
		audience: string;
		subject: string;
		name?: string;
		is_owner?: boolean;
		is_admin?: boolean;
		nonce?: string;
	},
): Promise<string> => new SignJWT({
	name: claims.name,
	is_owner: claims.is_owner,
	is_admin: claims.is_admin,
	...(claims.nonce !== undefined && {nonce: claims.nonce}),
})
	.setProtectedHeader({alg: ALG, kid: KID})
	.setIssuer(claims.issuer)
	.setAudience(claims.audience)
	.setSubject(claims.subject)
	.setIssuedAt()
	.setExpirationTime('1h')
	.sign(key.privateKey);
