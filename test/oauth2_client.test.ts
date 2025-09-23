import { describe, it, expect } from "vitest";
import { FlowAuthClient } from "../src";

describe("FlowAuthClient", () => {
  const client = new FlowAuthClient({
    server: "https://example.com",
    clientId: "client-id",
    clientSecret: "client-secret",
    redirectUri: "https://example.com/callback",
  });

  it("should create authorize URL", () => {
    const url = client.createAuthorizeUrl(["read:user"], "state123");
    expect(url).toContain("response_type=code");
    expect(url).toContain("client_id=client-id");
    expect(url).toContain("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback");
    expect(url).toContain("scope=read%3Auser");
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
    const url = client.createAuthorizeUrl(["read:user"], "state123", pkce);
    expect(url).toContain("response_type=code");
    expect(url).toContain("client_id=client-id");
    expect(url).toContain("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback");
    expect(url).toContain("scope=read%3Auser");
    expect(url).toContain("state=state123");
    expect(url).toContain("code_challenge=");
    expect(url).toContain("code_challenge_method=S256");
    expect(url).toContain(`code_challenge=${pkce.codeChallenge}`);
  });

  it("should create secure authorize URL", async () => {
    const result = await client.createSecureAuthorizeUrl(["read:user"]);
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
});
