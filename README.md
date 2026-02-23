# hass-oidc-provider

Use your [Home Assistant](https://www.home-assistant.io/) account to login to other apps and services.

Many self-hosted tools (Grafana, Gitea, etc.) let you add a "Log in with..." button using a protocol called [OpenID Connect](https://openid.net/developers/how-connect-works/) (OIDC). Home Assistant doesn't natively support this protocol, so you can't use it as a login provider for these tools.

**hass-oidc-provider** fixes this. It runs alongside Home Assistant and translates between Home Assistant's login system and the OIDC protocol. Your other apps talk to this, users see the normal Home Assistant login page, and it all just works.

Specifically, Home Assistant has OAuth 2.0 support but lacks full OIDC support. This adds the missing pieces:

- `/.well-known/openid-configuration` discovery
- ID tokens (signed JWTs with user identity)
- JWKS endpoint for token verification
- Userinfo endpoint

## Usage

Set `HASS_OIDC_CONFIG` to a JSON config object and run:

```bash
HASS_OIDC_CONFIG='{
  "hassUrl": "https://your-ha-instance.example.com",
  "externalUrl": "https://hass-oidc-provider.yourdomain.com"
}' npx hass-oidc-provider
```

Then point your apps at the `externalUrl` (the public URL where this service is reachable) as the OIDC issuer. They'll auto-discover everything else. When users log in, they'll see the normal Home Assistant login page.

<details>
<summary>Other configuration methods</summary>

The env var can also point to a file path:

```bash
HASS_OIDC_CONFIG=/path/to/config.json npx hass-oidc-provider
```

Or create `hass-oidc-provider.config.json` in the working directory — it's picked up automatically:

```bash
npx hass-oidc-provider
```

</details>

<details>
<summary>Running with Docker</summary>

```bash
docker run -e 'HASS_OIDC_CONFIG={"hassUrl":"https://your-ha-instance.example.com","externalUrl":"https://hass-oidc-provider.yourdomain.com"}' -p 3001:3001 ghcr.io/domdomegg/hass-oidc-provider
```

</details>

### Config

Only `externalUrl` is required. Everything else has sensible defaults.

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `hassUrl` | No | `http://localhost:8123` | URL of your Home Assistant instance |
| `externalUrl` | Yes | | Public URL where this service is reachable |
| `clientId` | No | `externalUrl` | OAuth client ID to register with HA |
| `signingKey` | No | Auto-generated | Signing key for persistent tokens (see below) |
| `port` | No | `3001` | Port to listen on |
| `host` | No | `0.0.0.0` | Host to bind to |

<details>
<summary>Advanced: setting a signing key</summary>

By default, a new signing key is generated each time the server starts. This means users will need to re-authenticate after a restart. Setting a persistent key is also required for running multiple instances behind a load balancer, since all instances need to share the same key. To generate one:

```sh
node -e "crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign']).then(k=>crypto.subtle.exportKey('jwk',k.privateKey)).then(j=>console.log(JSON.stringify(j)))"
```

Then add it to your config:

```json
{
  "hassUrl": "https://your-ha-instance.example.com",
  "externalUrl": "https://hass-oidc-provider.yourdomain.com",
  "signingKey": "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"...\",\"y\":\"...\",\"d\":\"...\"}"
}
```

</details>

## User info

The following claims from the user's Home Assistant account are included in the ID token and available via the `/userinfo` endpoint:

| Field | Description |
|-------|-------------|
| `sub` | Home Assistant user ID |
| `name` | Display name |
| `is_owner` | Whether the user is the HA owner |
| `is_admin` | Whether the user is an HA admin |

## Contributing

Pull requests are welcomed on GitHub! To get started:

1. Install Git and Node.js
2. Clone the repository
3. Install dependencies with `npm install`
4. Run `npm run test` to run tests
5. Build with `npm run build`

## Releases

Versions follow the [semantic versioning spec](https://semver.org/).

To release:

1. Use `npm version <major | minor | patch>` to bump the version
2. Run `git push --follow-tags` to push with tags
3. Wait for GitHub Actions to publish to the NPM registry and GHCR (Docker).
