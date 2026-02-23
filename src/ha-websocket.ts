export type HaUser = {
	id: string;
	name: string;
	is_owner: boolean;
	is_admin: boolean;
};

const isHaUser = (value: unknown): value is HaUser =>
	typeof value === 'object'
	&& value !== null
	&& typeof (value as Record<string, unknown>).id === 'string'
	&& typeof (value as Record<string, unknown>).name === 'string'
	&& typeof (value as Record<string, unknown>).is_owner === 'boolean'
	&& typeof (value as Record<string, unknown>).is_admin === 'boolean';

/**
 * One-shot WebSocket call to Home Assistant to get the current user.
 * Connects, authenticates with the access token, sends auth/current_user, returns the result, disconnects.
 */
export const getHaUser = async (haUrl: string, accessToken: string): Promise<HaUser> => new Promise((resolve, reject) => {
	const wsUrl = `${haUrl.replace(/^http/, 'ws').replace(/\/$/, '')}/api/websocket`;
	const ws = new WebSocket(wsUrl);
	let phase: 'connecting' | 'authenticating' | 'requesting' = 'connecting';
	let settled = false;

	const settle = <T>(fn: (value: T) => void, value: T) => {
		if (settled) {
			return;
		}

		settled = true;
		clearTimeout(timeout);
		ws.close();
		fn(value);
	};

	const timeout = setTimeout(() => {
		settle(reject, new Error('HA WebSocket timed out'));
	}, 10_000);

	ws.addEventListener('message', (event) => {
		try {
			const msg = JSON.parse(String(event.data)) as {type: string; id?: number; result?: unknown};

			if (phase === 'connecting' && msg.type === 'auth_required') {
				phase = 'authenticating';
				ws.send(JSON.stringify({type: 'auth', access_token: accessToken}));
				return;
			}

			if (phase === 'authenticating' && msg.type === 'auth_ok') {
				phase = 'requesting';
				ws.send(JSON.stringify({type: 'auth/current_user', id: 1}));
				return;
			}

			if (phase === 'authenticating' && msg.type === 'auth_invalid') {
				settle(reject, new Error('HA WebSocket auth failed'));
				return;
			}

			if (phase === 'requesting' && msg.type === 'result' && msg.id === 1) {
				if (isHaUser(msg.result)) {
					settle(resolve, msg.result);
				} else {
					settle(reject, new Error('HA WebSocket returned invalid user data'));
				}
			}
		} catch (err) {
			settle(reject, new Error('HA WebSocket message parse error', {cause: err}));
		}
	});

	ws.addEventListener('error', () => {
		settle(reject, new Error('HA WebSocket connection error'));
	});

	ws.addEventListener('close', () => {
		settle(reject, new Error('HA WebSocket closed unexpectedly'));
	});
});
