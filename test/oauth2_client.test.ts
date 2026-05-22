import { describe, it, expect, vi } from "vitest";
import {
  FlowAuthClient,
  OAuth2Scope,
  OAuth2ResponseType,
  OAUTH2_CONSTANTS,
} from "../src";

describe("FlowAuthClient", () => {
  const client = new FlowAuthClient({
    server: "https://example.com",
    clientId: "client-id",
    clientSecret: "client-secret",
    redirectUri: "https://example.com/callback",
  });

  it("should create authorize URL", () => {
    const url = client.createAuthorizeUrl([OAuth2Scope.PROFILE], {
      state: "state123",
    });
    expect(url).toContain("response_type=code");
    expect(url).toContain("client_id=client-id");
    expect(url).toContain("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback");
    expect(url).toContain("scope=profile");
    expect(url).toContain("state=state123");
  });

  it("should generate PKCE", async () => {
    const pkce = await FlowAuthClient.generatePKCE();
    expect(pkce).toHaveProperty("codeVerifier");
    expect(pkce).toHaveProperty("codeChallenge");
    expect(pkce).toHaveProperty("codeChallengeMethod");
    expect(typeof pkce.codeVerifier).toBe("string");
    expect(typeof pkce.codeChallenge).toBe("string");
    expect(pkce.codeChallengeMethod).toBe("S256");
    // Base64url 형식 검증
    expect(pkce.codeVerifier).toMatch(/^[A-Za-z0-9\-_]+$/);
    expect(pkce.codeChallenge).toMatch(/^[A-Za-z0-9\-_]+$/);
  });

  it("should generate secure auth params", async () => {
    const authParams = await FlowAuthClient.generateSecureAuthParams();
    expect(authParams).toHaveProperty("pkce");
    expect(authParams).toHaveProperty("state");
    expect(authParams.pkce).toHaveProperty("codeVerifier");
    expect(authParams.pkce).toHaveProperty("codeChallenge");
    expect(authParams.pkce).toHaveProperty("codeChallengeMethod");
    expect(typeof authParams.state).toBe("string");
    expect(authParams.state.length).toBeGreaterThan(0);
  });

  it("should create authorize URL with PKCE", async () => {
    const pkce = await FlowAuthClient.generatePKCE();
    const url = client.createAuthorizeUrl([OAuth2Scope.PROFILE], {
      state: "state123",
      pkce,
    });
    expect(url).toContain("response_type=code");
    expect(url).toContain("client_id=client-id");
    expect(url).toContain("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback");
    expect(url).toContain("scope=profile");
    expect(url).toContain("state=state123");
    expect(url).toContain("code_challenge=");
    expect(url).toContain("code_challenge_method=S256");
    expect(url).toContain(`code_challenge=${pkce.codeChallenge}`);
  });

  it("should create secure authorize URL", async () => {
    const result = await client.createSecureAuthorizeUrl([OAuth2Scope.PROFILE]);
    expect(result).toHaveProperty("authUrl");
    expect(result).toHaveProperty("codeVerifier");
    expect(result).toHaveProperty("state");
    expect(typeof result.authUrl).toBe("string");
    expect(typeof result.codeVerifier).toBe("string");
    expect(typeof result.state).toBe("string");
    expect(result.authUrl).toContain("response_type=code");
    expect(result.authUrl).toContain("code_challenge=");
    expect(result.authUrl).toContain("code_challenge_method=S256");
    expect(result.authUrl).toContain("state=");
  });

  it("should generate state", async () => {
    const state = await FlowAuthClient.generateState();
    expect(typeof state).toBe("string");
    expect(state.length).toBeGreaterThan(0);
    // Base64url 형식 검증 (URL-safe 문자들로만 구성)
    expect(state).toMatch(/^[A-Za-z0-9\-_]+$/);
  });

  it("should generate nonce", async () => {
    const nonce = await FlowAuthClient.generateNonce();
    expect(typeof nonce).toBe("string");
    expect(nonce.length).toBeGreaterThan(0);
    // Base64url 형식 검증 (URL-safe 문자들로만 구성)
    expect(nonce).toMatch(/^[A-Za-z0-9\-_]+$/);
  });

  it("should create OIDC authorize URL", () => {
    const url = client.createAuthorizeUrl(
      [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
      {
        state: "state123",
        nonce: "nonce123",
      },
    );
    expect(url).toContain("response_type=code");
    expect(url).toContain("client_id=client-id");
    expect(url).toContain("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback");
    expect(url).toContain("scope=openid+profile");
    expect(url).toContain("state=state123");
    expect(url).toContain("nonce=nonce123");
  });

  it("should create OIDC authorize URL with openid scope automatically added", () => {
    const url = client.createAuthorizeUrl([OAuth2Scope.PROFILE], {
      state: "state123",
      nonce: "nonce123",
    });
    expect(url).toContain("scope=profile");
  });

  it("should parse callback URL", () => {
    // Authorization Code Grant
    const codeUrl = "https://example.com/callback?code=abc123&state=xyz";
    const codeParams = client.parseCallbackUrl(codeUrl);
    expect(codeParams.code).toBe("abc123");
    expect(codeParams.state).toBe("xyz");

    // Error case
    const errorUrl =
      "https://example.com/callback?error=access_denied&error_description=User+denied&state=xyz";
    const errorParams = client.parseCallbackUrl(errorUrl);
    expect(errorParams.error).toBe("access_denied");
    expect(errorParams.errorDescription).toBe("User denied");
    expect(errorParams.state).toBe("xyz");
  });

  it("should reject callback with invalid state", async () => {
    const callbackUrl =
      "https://example.com/callback?code=authcode123&state=wrongstate";
    await expect(
      client.handleCallback(callbackUrl, "expectedstate"),
    ).rejects.toThrow("State mismatch");
  });

  it("should reject callback with no authorization code", async () => {
    const callbackUrl = "https://example.com/callback?state=teststate";
    await expect(
      client.handleCallback(callbackUrl, "teststate"),
    ).rejects.toThrow("No authorization code found in callback");
  });

  describe("OAuth2 Constants", () => {
    it("should have correct response types", () => {
      expect(OAUTH2_CONSTANTS.RESPONSE_TYPES.CODE).toBe("code");
    });

    it("should have supported response types array", () => {
      expect(OAUTH2_CONSTANTS.SUPPORTED_RESPONSE_TYPES).toContain("code");
      expect(OAUTH2_CONSTANTS.SUPPORTED_RESPONSE_TYPES).toHaveLength(1);
    });
  });

  describe("offline_access scope", () => {
    it("should have OFFLINE_ACCESS in OAuth2Scope enum", () => {
      expect(OAuth2Scope.OFFLINE_ACCESS).toBe("offline_access");
    });

    it("should include offline_access in authorize URL scope", () => {
      const url = client.createAuthorizeUrl(
        [OAuth2Scope.OPENID, OAuth2Scope.PROFILE, OAuth2Scope.OFFLINE_ACCESS],
        { state: "state123" },
      );
      expect(url).toContain("offline_access");
      expect(url).toContain("openid");
      expect(url).toContain("profile");
    });

    it("should send scope param in refreshToken when provided", async () => {
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          access_token: "new-access-token",
          token_type: "Bearer",
          expires_in: 3600,
          scope: "openid profile",
        }),
      });
      const originalFetch = globalThis.fetch;
      (globalThis as { fetch: typeof fetch }).fetch = fetchMock as typeof fetch;

      try {
        const testClient = new FlowAuthClient({
          server: "https://example.com",
          clientId: "client-id",
          clientSecret: "client-secret",
          redirectUri: "https://example.com/callback",
        });

        await testClient.refreshToken("test-refresh-token", "openid profile");

        expect(fetchMock).toHaveBeenCalledOnce();
        const callArgs = fetchMock.mock.calls[0];
        const body = callArgs[1].body as string;
        expect(body).toContain("scope=openid+profile");
      } finally {
        (globalThis as { fetch: typeof fetch }).fetch = originalFetch;
      }
    });

    it("should not send scope param in refreshToken when not provided", async () => {
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          access_token: "new-access-token",
          token_type: "Bearer",
          expires_in: 3600,
        }),
      });
      const originalFetch = globalThis.fetch;
      (globalThis as { fetch: typeof fetch }).fetch = fetchMock as typeof fetch;

      try {
        const testClient = new FlowAuthClient({
          server: "https://example.com",
          clientId: "client-id",
          clientSecret: "client-secret",
          redirectUri: "https://example.com/callback",
        });

        await testClient.refreshToken("test-refresh-token");

        const callArgs = fetchMock.mock.calls[0];
        const body = callArgs[1].body as string;
        expect(body).not.toContain("scope=");
      } finally {
        (globalThis as { fetch: typeof fetch }).fetch = originalFetch;
      }
    });
  });

  describe("Response Type Parameter Support", () => {
    const client = new FlowAuthClient({
      server: "https://example.com",
      clientId: "client-id",
      clientSecret: "client-secret",
      redirectUri: "https://example.com/callback",
    });

    it("should create authorize URL with explicit response type", () => {
      const url = client.createAuthorizeUrl([OAuth2Scope.PROFILE], {
        state: "state123",
        responseType: OAuth2ResponseType.CODE,
      });
      expect(url).toContain("response_type=code");
      expect(url).toContain("scope=profile");
    });

    it("should create secure authorize URL with explicit response type", async () => {
      const result = await client.createSecureAuthorizeUrl(
        [OAuth2Scope.PROFILE],
        OAuth2ResponseType.CODE,
      );
      expect(result.authUrl).toContain("response_type=code");
      expect(result.authUrl).toContain("scope=profile");
      expect(result.codeVerifier).toBeDefined();
      expect(result.state).toBeDefined();
    });

    it("should use default response type when not specified", () => {
      const url = client.createAuthorizeUrl([OAuth2Scope.PROFILE], {
        state: "state123",
      });
      expect(url).toContain("response_type=code");
    });
  });

  describe("UserInfo URL normalization", () => {
    it("should recover nested backend+files domain picture URL", async () => {
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          sub: "1",
          picture:
            "https://authserver.viento.mehttps//files.viento.me/hash-value",
        }),
      });

      const originalFetch = globalThis.fetch;
      (globalThis as { fetch: typeof fetch }).fetch = fetchMock as typeof fetch;

      try {
        const testClient = new FlowAuthClient({
          server: "https://authserver.viento.me",
          clientId: "client-id",
          clientSecret: "client-secret",
          redirectUri: "https://example.com/callback",
        });

        (
          testClient as unknown as { tokenData: { access_token: string } }
        ).tokenData = {
          access_token: "access-token",
        };

        const userInfo = await testClient.getUserInfo();
        expect(userInfo.picture).toBe("https://files.viento.me/hash-value");
      } finally {
        (globalThis as { fetch: typeof fetch }).fetch = originalFetch;
      }
    });

    it("should recover malformed https// avatar URL", async () => {
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          sub: "1",
          avatar: "https//files.viento.me/hash-value",
        }),
      });

      const originalFetch = globalThis.fetch;
      (globalThis as { fetch: typeof fetch }).fetch = fetchMock as typeof fetch;

      try {
        const testClient = new FlowAuthClient({
          server: "https://authserver.viento.me",
          clientId: "client-id",
          clientSecret: "client-secret",
          redirectUri: "https://example.com/callback",
        });

        (
          testClient as unknown as { tokenData: { access_token: string } }
        ).tokenData = {
          access_token: "access-token",
        };

        const userInfo = await testClient.getUserInfo();
        expect(userInfo.avatar).toBe("https://files.viento.me/hash-value");
      } finally {
        (globalThis as { fetch: typeof fetch }).fetch = originalFetch;
      }
    });
  });
});
