
import { describe, it, beforeEach, afterEach, mock } from 'node:test';
import assert from 'node:assert';
import { VickyClient } from './vicky-client.js';

// Global fetch mock
const originalFetch = global.fetch;

describe('VickyClient', () => {
    let client;
    let mockFetch;

    beforeEach(() => {
        client = new VickyClient();
        // Reset fetch to a basic mock that throws if not configured
        mockFetch = mock.fn(async () => { throw new Error('Not implemented'); });
        global.fetch = mockFetch;
    });

    afterEach(() => {
        global.fetch = originalFetch;
        mock.reset();
    });

    it('should allow tool execution when API returns ALLOW', async () => {
        mockFetch = mock.fn(async () => ({
            ok: true,
            json: async () => ({ action: 'ALLOW', tier: 'LOW' }),
        }));
        global.fetch = mockFetch;

        const result = await client.checkPermission({ toolName: 'test', arguments: {} });
        assert.deepStrictEqual(result, { action: 'ALLOW', tier: 'LOW' });
        assert.strictEqual(mockFetch.mock.calls.length, 1);
    });

    it('should block execution when API returns BLOCK', async () => {
        mockFetch = mock.fn(async () => ({
            ok: true,
            json: async () => ({ action: 'BLOCK', tier: 'HIGH', blockReason: 'Policy' }),
        }));
        global.fetch = mockFetch;

        const result = await client.checkPermission({ toolName: 'test', arguments: {} });
        assert.deepStrictEqual(result, { action: 'BLOCK', tier: 'HIGH', blockReason: 'Policy' });
    });

    it('should retry on timeout (AbortError) and succeed', async () => {
        let attempts = 0;
        mockFetch = mock.fn(async () => {
            attempts++;
            if (attempts === 1) {
                const err = new Error('Aborted');
                err.name = 'AbortError';
                throw err;
            }
            return {
                ok: true,
                json: async () => ({ action: 'ALLOW', tier: 'LOW' }),
            };
        });
        global.fetch = mockFetch;

        const result = await client.checkPermission({ toolName: 'test', arguments: {} });
        assert.deepStrictEqual(result, { action: 'ALLOW', tier: 'LOW' });
        assert.strictEqual(mockFetch.mock.calls.length, 2);
    });

    it('should retry on 5xx error and succeed', async () => {
        let attempts = 0;
        mockFetch = mock.fn(async () => {
            attempts++;
            if (attempts === 1) {
                return { ok: false, status: 503 };
            }
            return {
                ok: true,
                json: async () => ({ action: 'ALLOW', tier: 'LOW' }),
            };
        });
        global.fetch = mockFetch;

        const result = await client.checkPermission({ toolName: 'test', arguments: {} });
        assert.deepStrictEqual(result, { action: 'ALLOW', tier: 'LOW' });
        assert.strictEqual(mockFetch.mock.calls.length, 2);
    });

    it('should fail-closed (BLOCK) after max retries', async () => {
        mockFetch = mock.fn(async () => {
            const err = new Error('Aborted');
            err.name = 'AbortError';
            throw err;
        });
        global.fetch = mockFetch;

        const result = await client.checkPermission({ toolName: 'test', arguments: {} });

        assert.strictEqual(result.action, 'BLOCK');
        assert.strictEqual(result.tier, 'HIGH');
        assert.strictEqual(mockFetch.mock.calls.length, 3); // Initial + 2 retries
    });

    it('should fail-closed on non-retriable 4xx error without retrying', async () => {
        mockFetch = mock.fn(async () => ({ ok: false, status: 400 }));
        global.fetch = mockFetch;

        const result = await client.checkPermission({ toolName: 'test', arguments: {} });

        assert.strictEqual(result.action, 'BLOCK');
        assert.strictEqual(result.tier, 'HIGH');
        assert.strictEqual(mockFetch.mock.calls.length, 1);
    });
});
