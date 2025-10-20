import { describe, it, expect, vi } from "vitest";
import { FlowAuthClient, OAuth2Scope, OAUTH2_CONSTANTS } from "../src";

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
      "state123",
    );
    expect(url).toContain("response_type=code");
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
      "state123",
      pkce,
    );
    expect(url).toContain("response_type=code");
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
    const url = client.createOIDCAuthorizeUrl(
      [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
      "state123",
      "nonce123",
    );
    expect(url).toContain("response_type=code+id_token");
    expect(url).toContain("client_id=client-id");
    expect(url).toContain("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback");
    expect(url).toContain("scope=openid+profile");
    expect(url).toContain("state=state123");
    expect(url).toContain("nonce=nonce123");
  });

  it("should create OIDC authorize URL with openid scope automatically added", () => {
    const url = client.createOIDCAuthorizeUrl(
      [OAuth2Scope.PROFILE],
      "state123",
      "nonce123",
    );
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
    expect(codeParams.idToken).toBeUndefined();

    // Hybrid Flow
    const hybridUrl =
      "https://example.com/callback?code=abc123&state=xyz#id_token=token456";
    const hybridParams = client.parseCallbackUrl(hybridUrl);
    expect(hybridParams.code).toBe("abc123");
    expect(hybridParams.state).toBe("xyz");
    expect(hybridParams.idToken).toBe("token456");

    // Implicit Flow
    const implicitUrl =
      "https://example.com/callback#access_token=token123&id_token=idtoken456&token_type=Bearer&expires_in=3600&state=xyz";
    const implicitParams = client.parseCallbackUrl(implicitUrl);
    expect(implicitParams.accessToken).toBe("token123");
    expect(implicitParams.idToken).toBe("idtoken456");
    expect(implicitParams.tokenType).toBe("Bearer");
    expect(implicitParams.expiresIn).toBe(3600);
    expect(implicitParams.state).toBe("xyz");

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

  it("should handle hybrid callback with implicit tokens", async () => {
    // Mock validateIdToken to avoid network calls
    const validateIdTokenSpy = vi
      .spyOn(client, "validateIdToken")
      .mockResolvedValue({
        iss: "https://example.com",
        aud: "client-id",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        sub: "user123",
        nonce: undefined,
      });

    try {
      const callbackUrl =
        "https://example.com/callback#access_token=implicit123&id_token=idtoken456&token_type=Bearer&expires_in=3600&state=teststate";
      const result = await client.handleHybridCallback(
        callbackUrl,
        "teststate",
      );

      expect(result).toHaveProperty("access_token", "implicit123");
      expect(result).toHaveProperty("id_token", "idtoken456");
      expect(result).toHaveProperty("token_type", "Bearer");
      expect(result).toHaveProperty("expires_in", 3600);
    } finally {
      validateIdTokenSpy.mockRestore();
    }
  });

  it("should reject hybrid callback with invalid state", async () => {
    const callbackUrl =
      "https://example.com/callback?code=authcode123&state=wrongstate";
    await expect(
      client.handleHybridCallback(callbackUrl, "expectedstate"),
    ).rejects.toThrow("State mismatch");
  });

  it("should reject hybrid callback with no valid tokens", async () => {
    const callbackUrl = "https://example.com/callback?state=teststate";
    await expect(
      client.handleHybridCallback(callbackUrl, "teststate"),
    ).rejects.toThrow("No authorization code or access token found");
  });

  // 새로운 response_type 관련 테스트들
  describe("Response Type Methods", () => {
    it("should create Implicit Grant URL (token only)", () => {
      const url = client.createImplicitGrantUrl(
        [OAuth2Scope.PROFILE],
        "state123",
      );
      expect(url).toContain("response_type=token");
      expect(url).toContain("client_id=client-id");
      expect(url).toContain(
        "redirect_uri=https%3A%2F%2Fexample.com%2Fcallback",
      );
      expect(url).toContain("scope=profile");
      expect(url).toContain("state=state123");
    });

    it("should create OIDC Implicit URL (id_token only)", () => {
      const url = client.createOIDCImplicitUrl(
        [OAuth2Scope.OPENID],
        "state123",
        "nonce123",
      );
      expect(url).toContain("response_type=id_token");
      expect(url).toContain("scope=openid");
      expect(url).toContain("state=state123");
      expect(url).toContain("nonce=nonce123");
    });

    it("should create OIDC Implicit Token URL (token + id_token)", () => {
      const url = client.createOIDCImplicitTokenUrl(
        [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
        "state123",
        "nonce123",
      );
      expect(url).toContain("response_type=token+id_token");
      expect(url).toContain("scope=openid+profile");
      expect(url).toContain("state=state123");
      expect(url).toContain("nonce=nonce123");
    });

    it("should create authorize URL with custom response type", () => {
      const url = client.createAuthorizeUrlWithResponseType(
        "code",
        [OAuth2Scope.PROFILE],
        "state123",
      );
      expect(url).toContain("response_type=code");
      expect(url).toContain("scope=profile");
      expect(url).toContain("state=state123");
    });

    it("should automatically add openid scope for OIDC methods", () => {
      const url1 = client.createOIDCImplicitUrl(
        [OAuth2Scope.PROFILE],
        "state123",
        "nonce123",
      );
      expect(url1).toContain("scope=openid+profile");

      const url2 = client.createOIDCImplicitTokenUrl(
        [OAuth2Scope.EMAIL],
        "state123",
        "nonce123",
      );
      expect(url2).toContain("scope=openid+email");
    });
  });

  describe("OAuth2 Constants", () => {
    it("should have correct response types", () => {
      expect(OAUTH2_CONSTANTS.RESPONSE_TYPES.CODE).toBe("code");
      expect(OAUTH2_CONSTANTS.RESPONSE_TYPES.TOKEN).toBe("token");
      expect(OAUTH2_CONSTANTS.RESPONSE_TYPES.ID_TOKEN).toBe("id_token");
      expect(OAUTH2_CONSTANTS.RESPONSE_TYPES.CODE_ID_TOKEN).toBe(
        "code id_token",
      );
      expect(OAUTH2_CONSTANTS.RESPONSE_TYPES.TOKEN_ID_TOKEN).toBe(
        "token id_token",
      );
    });

    it("should have supported response types array", () => {
      expect(OAUTH2_CONSTANTS.SUPPORTED_RESPONSE_TYPES).toContain("code");
      expect(OAUTH2_CONSTANTS.SUPPORTED_RESPONSE_TYPES).toContain("token");
      expect(OAUTH2_CONSTANTS.SUPPORTED_RESPONSE_TYPES).toContain("id_token");
      expect(OAUTH2_CONSTANTS.SUPPORTED_RESPONSE_TYPES).toContain(
        "code id_token",
      );
      expect(OAUTH2_CONSTANTS.SUPPORTED_RESPONSE_TYPES).toContain(
        "token id_token",
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
      const url = client.createAuthorizeUrl(
        [OAuth2Scope.PROFILE],
        "state123",
        undefined,
        undefined,
        "token",
      );
      expect(url).toContain("response_type=token");
      expect(url).toContain("scope=profile");
    });

    it("should create OIDC authorize URL with explicit response type", () => {
      const url = client.createOIDCAuthorizeUrl(
        [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
        "state123",
        "nonce123",
        undefined,
        "id_token",
      );
      expect(url).toContain("response_type=id_token");
      expect(url).toContain("scope=openid+profile");
      expect(url).toContain("nonce=nonce123");
    });

    it("should create secure authorize URL with explicit response type", async () => {
      const result = await client.createSecureAuthorizeUrl(
        [OAuth2Scope.PROFILE],
        "token",
      );
      expect(result.authUrl).toContain("response_type=token");
      expect(result.authUrl).toContain("scope=profile");
      expect(result.codeVerifier).toBeDefined();
      expect(result.state).toBeDefined();
    });

    it("should create secure OIDC authorize URL with explicit response type", async () => {
      const result = await client.createSecureOIDCAuthorizeUrl(
        [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
        "id_token",
      );
      expect(result.authUrl).toContain("response_type=id_token");
      expect(result.authUrl).toContain("scope=openid+profile");
      expect(result.codeVerifier).toBeDefined();
      expect(result.state).toBeDefined();
      expect(result.nonce).toBeDefined();
    });

    it("should use default response type when not specified", () => {
      const url = client.createAuthorizeUrl([OAuth2Scope.PROFILE], "state123");
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
