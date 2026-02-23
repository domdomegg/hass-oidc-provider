import {test, expect} from 'vitest';
import {seal, unseal, deriveKey} from './seal';

test('seal and unseal round-trips', () => {
	const key = deriveKey('test-secret');
	const payload = {type: 'test' as const, foo: 'bar', expiresAt: Date.now() + 60_000};
	const sealed = seal(payload, key);
	const result = unseal<typeof payload>(sealed, key, 'test');
	expect(result).toEqual(payload);
});

test('unseal returns undefined for expired payload', () => {
	const key = deriveKey('test-secret');
	const payload = {type: 'test' as const, foo: 'bar', expiresAt: Date.now() - 1000};
	const sealed = seal(payload, key);
	const result = unseal<typeof payload>(sealed, key, 'test');
	expect(result).toBeUndefined();
});

test('unseal returns undefined for wrong key', () => {
	const key1 = deriveKey('secret-1');
	const key2 = deriveKey('secret-2');
	const payload = {type: 'test' as const, foo: 'bar', expiresAt: Date.now() + 60_000};
	const sealed = seal(payload, key1);
	const result = unseal<typeof payload>(sealed, key2, 'test');
	expect(result).toBeUndefined();
});

test('unseal returns undefined for tampered data', () => {
	const key = deriveKey('test-secret');
	const payload = {type: 'test' as const, foo: 'bar', expiresAt: Date.now() + 60_000};
	const sealed = seal(payload, key);
	const tampered = `X${sealed.slice(1)}`;
	const result = unseal<typeof payload>(tampered, key, 'test');
	expect(result).toBeUndefined();
});

test('unseal returns undefined for wrong type', () => {
	const key = deriveKey('test-secret');
	const payload = {type: 'alpha' as const, foo: 'bar', expiresAt: Date.now() + 60_000};
	const sealed = seal(payload, key);
	const result = unseal<typeof payload>(sealed, key, 'beta' as typeof payload.type);
	expect(result).toBeUndefined();
});
