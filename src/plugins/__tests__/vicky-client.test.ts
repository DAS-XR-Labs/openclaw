import { VickyClient, PolicyDeniedError } from "../vicky-client";
import { beforeEach, describe, expect, vi, test } from "vitest";

// Mock Fetch Global
const mockFetch = vi.fn() as any;
global.fetch = mockFetch;

describe("VickyClient", () => {
  const mockSessionKey = "test-session-key";
  const mockSecretToken = "test-secret-token";

  beforeEach(() => {
    mockFetch.mockClear();
    process.env.VICKY_SECRET_TOKEN = mockSecretToken;
  });

  test("anonymize calls API with correct headers and body", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ sanitizedText: "Hello EMAIL_01" }),
    } as Response);

    const result = await VickyClient.anonymize("Hello test@example.com", mockSessionKey);

    expect(result).toBe("Hello EMAIL_01");
    expect(mockFetch).toHaveBeenCalledWith(
      "http://127.0.0.1:3000/api/anonymize",
      expect.objectContaining({
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-openclaw-session-id": mockSessionKey,
          "x-vicky-token": mockSecretToken,
        },
        body: JSON.stringify({ text: "Hello test@example.com" }),
      }),
    );
  });

  test("anonymize throws on API error (Fail-Closed)", async () => {
    // Use mockResolvedValue (persisted) because client retries on 500
    mockFetch.mockResolvedValue({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
    } as Response);

    await expect(VickyClient.anonymize("test", mockSessionKey)).rejects.toThrow(
      "Vicky API Server Error: 500",
    );
  });

  test("restore calls API with correct headers", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ restoredText: "Hello test@example.com" }),
    } as Response);

    const result = await VickyClient.restore("Hello EMAIL_01", mockSessionKey);

    expect(result).toBe("Hello test@example.com");
    expect(mockFetch).toHaveBeenCalledWith(
      "http://127.0.0.1:3000/api/deanonymize",
      expect.objectContaining({
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-openclaw-session-id": mockSessionKey,
          "x-vicky-token": mockSecretToken,
        },
        body: JSON.stringify({ text: "Hello EMAIL_01" }),
      }),
    );
  });

  test("restoreRecursive handles nested objects and arrays", async () => {
    // Mock restore response for "EMAIL_01" -> "test@example.com"
    mockFetch.mockImplementation(async (url: string, init: RequestInit) => {
      const body = JSON.parse((init?.body as string) || "{}");
      if (body.text === "EMAIL_01") {
        return {
          ok: true,
          json: async () => ({ restoredText: "test@example.com" }),
        } as Response;
      }
      if (body.text === "PHONE_01") {
        return {
          ok: true,
          json: async () => ({ restoredText: "555-1234" }),
        } as Response;
      }
      return {
        ok: true,
        json: async () => ({ restoredText: body.text }),
      } as Response;
    });

    const input = {
      user: {
        email: "EMAIL_01",
        details: {
          phone: "PHONE_01",
          address: "123 Main St", // No placeholder
        },
      },
      tags: ["tag1", "EMAIL_01"],
      active: true, // Non-string primitive
    };

    const result = await VickyClient.restoreRecursive(input, mockSessionKey);

    expect(result.user.email).toBe("test@example.com");
    expect(result.user.details.phone).toBe("555-1234");
    expect(result.user.details.address).toBe("123 Main St");
    expect(result.tags[1]).toBe("test@example.com");
    expect(result.active).toBe(true);

    // Assert optimization: only calls API for placeholders
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });

  test("restoreRecursive is idempotent", async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ restoredText: "test@example.com" }),
    } as Response);

    const input = { email: "EMAIL_01" };

    // First pass
    const firstPass = await VickyClient.restoreRecursive(input, mockSessionKey);
    expect(firstPass.email).toBe("test@example.com");

    // Second pass (input is now restored)
    // Since "test@example.com" does not look like a placeholder, it should SKIP the API call
    mockFetch.mockClear();
    const secondPass = await VickyClient.restoreRecursive(firstPass, mockSessionKey);
    expect(secondPass.email).toBe("test@example.com");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  test("restoreRecursive handles varied placeholder formats", async () => {
    // Mock restore response for varied formats
    mockFetch.mockImplementation(async (url: string, init: RequestInit) => {
      const body = JSON.parse((init?.body as string) || "{}");
      if (body.text === "EMAIL-01") {
        return {
          ok: true,
          json: async () => ({ restoredText: "test1@example.com" }),
        } as Response;
      }
      if (body.text === "EMAIL01") {
        return {
          ok: true,
          json: async () => ({ restoredText: "test2@example.com" }),
        } as Response;
      }
      if (body.text === "PHONE_01") {
        return {
          ok: true,
          json: async () => ({ restoredText: "555-0001" }),
        } as Response;
      }
      // Fallback for non-placeholder behavior test
      return {
        ok: true,
        json: async () => ({ restoredText: body.text }),
      } as Response;
    });

    const input = {
      a: "EMAIL-01",
      b: "EMAIL01",
      c: "PHONE_01",
      d: "NORMAL_TEXT",
    };

    const result = await VickyClient.restoreRecursive(input, mockSessionKey);

    expect(result.a).toBe("test1@example.com");
    expect(result.b).toBe("test2@example.com");
    expect(result.c).toBe("555-0001");
    expect(result.d).toBe("NORMAL_TEXT");

    // Should call for 3 placeholders (d is skipped by optimization)
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });
});
