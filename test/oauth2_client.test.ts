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
    const url = client.createAuthorizeUrl(
      [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
      { state: "state123" },
    );
    expect(url).toContain("response_type=code+id_token");
    expect(url).toContain("client_id=client-id");
    expect(url).toContain("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback");
    expect(url).toContain("scope=openid+profile");
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
    const url = client.createAuthorizeUrl(
      [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
      { state: "state123", pkce },
    );
    expect(url).toContain("response_type=code+id_token");
    expect(url).toContain("client_id=client-id");
    expect(url).toContain("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback");
    expect(url).toContain("scope=openid+profile");
    expect(url).toContain("state=state123");
    expect(url).toContain("code_challenge=");
    expect(url).toContain("code_challenge_method=S256");
    expect(url).toContain(`code_challenge=${pkce.codeChallenge}`);
  });

  it("should create secure authorize URL", async () => {
    const result = await client.createSecureAuthorizeUrl([
      OAuth2Scope.OPENID,
      OAuth2Scope.PROFILE,
    ]);
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
    expect(url).toContain("scope=openid+profile");
  });

  it("should create secure OIDC authorize URL", async () => {
    const result = await client.createSecureOIDCAuthorizeUrl([
      OAuth2Scope.PROFILE,
    ]);
    expect(result).toHaveProperty("authUrl");
    expect(result).toHaveProperty("codeVerifier");
    expect(result).toHaveProperty("state");
    expect(result).toHaveProperty("nonce");
    expect(typeof result.authUrl).toBe("string");
    expect(typeof result.codeVerifier).toBe("string");
    expect(typeof result.state).toBe("string");
    expect(typeof result.nonce).toBe("string");
    expect(result.authUrl).toContain("response_type=code+id_token");
    expect(result.authUrl).toContain("scope=openid+profile");
    expect(result.authUrl).toContain("nonce=");
    expect(result.authUrl).toContain("code_challenge=");
    expect(result.authUrl).toContain("code_challenge_method=S256");
    expect(result.authUrl).toContain("state=");
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

  it("should handle hybrid callback with authorization code", async () => {
    // Mock fetch for token exchange
    const mockResponse = {
      ok: true,
      json: () =>
        Promise.resolve({
          access_token: "access123",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "refresh123",
          id_token: "idtoken123",
        }),
    } as Response;

    const mockFetch = vi.fn(() => Promise.resolve(mockResponse));

    // Temporarily replace fetch
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mockFetch;

    try {
      const callbackUrl =
        "https://example.com/callback?code=authcode123&state=teststate";
      const result = await client.handleHybridCallback(
        callbackUrl,
        "teststate",
        undefined,
        "codeverifier123",
      );

      expect(result).toHaveProperty("access_token", "access123");
      expect(result).toHaveProperty("token_type", "Bearer");
      expect(result).toHaveProperty("expires_in", 3600);
      expect(result).toHaveProperty("refresh_token", "refresh123");
      expect(result).toHaveProperty("id_token", "idtoken123");

      expect(mockFetch).toHaveBeenCalledWith(
        "https://example.com/oauth2/token",
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            "Content-Type": "application/x-www-form-urlencoded",
          }),
          body: expect.stringContaining("grant_type=authorization_code"),
        }),
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
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
      expect(OAUTH2_CONSTANTS.SUPPORTED_RESPONSE_TYPES).toContain("id_token");
      expect(OAUTH2_CONSTANTS.SUPPORTED_RESPONSE_TYPES).toContain(
        "code id_token",
      );
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

    it("should create OIDC authorize URL with explicit response type", () => {
      const url = client.createOIDCAuthorizeUrl(
        [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
        "state123",
        "nonce123",
        undefined,
        OAuth2ResponseType.ID_TOKEN,
      );
      expect(url).toContain("response_type=id_token");
      expect(url).toContain("scope=openid+profile");
      expect(url).toContain("nonce=nonce123");
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

    it("should use OIDC default response type when not specified", () => {
      const url = client.createOIDCAuthorizeUrl(
        [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
        "state123",
        "nonce123",
      );
      expect(url).toContain("response_type=code+id_token");
    });
  });
});
