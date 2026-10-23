import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FlowAuthClient } from "../src/client/flowauth-client";
import { MemoryStorage } from "../src/utils/storage";
import { EnvironmentUtils } from "../src/utils/environment";
import { OIDCUtils } from "../src/utils/oidc";
import type { TokenData, TokenResponse } from "../src/types/token";

const config = {
  server: "https://issuer.example.com",
  clientId: "client-id",
  clientSecret: "server-secret",
  redirectUri: "https://app.example.com/callback",
};
const key = "flowauth_tokens_client-id";
const now = Date.UTC(2026, 9, 23);
const idToken = `${Buffer.from(JSON.stringify({ alg: "RS256", kid: "key" })).toString("base64url")}.${Buffer.from(JSON.stringify({ exp: now / 1000 + 3600 })).toString("base64url")}.signature`;

function response(body: unknown, status = 200): Response {
  return {
    ok: status < 400,
    status,
    statusText: status < 400 ? "OK" : "Bad Request",
    json: async () => body,
  } as Response;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => {
    resolve = done;
  });
  return { promise, resolve };
}

function session(overrides: Partial<TokenData> = {}): TokenData {
  return {
    access_token: "old-access",
    refresh_token: "refresh-token",
    id_token: idToken,
    token_type: "Bearer",
    expires_at: now + 3600000,
    scope: "openid profile",
    ...overrides,
  };
}

function setup(data?: TokenData) {
  const storage = new MemoryStorage();
  if (data) storage.setItem(key, JSON.stringify(data));
  return { storage, client: new FlowAuthClient({ ...config, storage }) };
}

const fresh: TokenResponse = {
  access_token: "fresh-access",
  token_type: "Bearer",
  expires_in: 3600,
};

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(now);
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("Token lifecycle regression coverage", () => {
  it("restores an expired refreshable session and refreshes before UserInfo", async () => {
    const { client, storage } = setup(session({ expires_at: now }));
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(response(fresh))
      .mockResolvedValueOnce(response({ sub: "user" }));
    vi.stubGlobal("fetch", fetch);
    expect(client.getStoredAccessToken()).toBeNull();
    expect(client.getStoredIdToken()).toBe(idToken);
    await expect(client.getUserInfo()).resolves.toMatchObject({ sub: "user" });
    expect(fetch.mock.calls[0][1].body).toContain(
      "refresh_token=refresh-token",
    );
    expect(fetch.mock.calls[1][1].headers.Authorization).toBe(
      "Bearer fresh-access",
    );
    expect(JSON.parse(storage.getItem(key) ?? "{}").refresh_token).toBe(
      "refresh-token",
    );
  });

  it("restores the ID token used by default validation", async () => {
    const { client } = setup(session());
    vi.spyOn(OIDCUtils, "getDiscoveryDocument").mockResolvedValue({
      issuer: config.server,
      jwks_uri: `${config.server}/jwks`,
    } as Awaited<ReturnType<typeof OIDCUtils.getDiscoveryDocument>>);
    const verify = vi
      .spyOn(OIDCUtils, "validateAndParseIdTokenWithCrypto")
      .mockResolvedValue({ sub: "user" } as Awaited<
        ReturnType<typeof OIDCUtils.validateAndParseIdTokenWithCrypto>
      >);
    await client.validateIdToken();
    expect(verify).toHaveBeenCalledWith(
      idToken,
      `${config.server}/jwks`,
      config.server,
      config.clientId,
      undefined,
    );
  });

  it("discards expired sessions without a refresh token", () => {
    const { client, storage } = setup(
      session({ expires_at: now, refresh_token: undefined }),
    );
    expect(client.getTokenInfo()).toBeNull();
    expect(storage.getItem(key)).toBeNull();
  });

  it.each([null, "later", {}, []])(
    "rejects malformed stored expiration %j",
    expiration => {
      const storage = new MemoryStorage();
      storage.setItem(
        key,
        JSON.stringify({ ...session(), expires_at: expiration }),
      );
      const client = new FlowAuthClient({ ...config, storage });
      expect(client.getTokenInfo()).toBeNull();
      expect(storage.getItem(key)).toBeNull();
    },
  );

  it("honors a zero-second access token lifetime", async () => {
    const { client } = setup();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(response({ ...fresh, expires_in: 0 })),
    );
    await client.exchangeCode("code");
    expect(client.getTokenInfo()?.expires_at).toBe(now);
    expect(client.getStoredAccessToken()).toBeNull();
    await expect(client.validateToken()).resolves.toBe(false);
  });

  it.each([-1, NaN, Infinity, "3600", null])(
    "rejects invalid token response lifetime %j",
    async expires => {
      const { client } = setup();
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(response({ ...fresh, expires_in: expires })),
      );
      await expect(client.exchangeCode("code")).rejects.toThrow();
      expect(client.getTokenInfo()).toBeNull();
    },
  );

  it("keeps in-memory tokens when persistent storage is unavailable", async () => {
    vi.spyOn(EnvironmentUtils, "isBrowser").mockReturnValue(false);
    vi.spyOn(EnvironmentUtils, "isNode").mockReturnValue(false);
    const client = new FlowAuthClient(config);
    vi.spyOn(EnvironmentUtils, "btoa").mockImplementation(value =>
      Buffer.from(value).toString("base64"),
    );
    vi.spyOn(EnvironmentUtils, "getFetch").mockReturnValue(
      vi.fn().mockResolvedValue(response(fresh)),
    );
    await client.exchangeCode("code");
    expect(client.getStoredAccessToken()).toBe("fresh-access");
  });

  it("clears memory before reporting a persistent logout failure", () => {
    const { client, storage } = setup(session());
    vi.spyOn(storage, "removeItem").mockImplementation(() => {
      throw new Error("Storage unavailable");
    });
    expect(() => client.logout()).toThrow("Storage unavailable");
    expect(client.getStoredAccessToken()).toBeNull();
    expect(client.getStoredIdToken()).toBeNull();
    expect(client.getTokenInfo()).toBeNull();
  });

  it("preserves omitted refresh metadata but clears old ID tokens on a new grant", async () => {
    const { client } = setup(session());
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response(fresh)));
    await client.refreshToken();
    expect(client.getTokenInfo()).toMatchObject({
      refresh_token: "refresh-token",
      id_token: idToken,
      scope: "openid profile",
    });
    await client.exchangeCode("new-grant");
    expect(client.getStoredIdToken()).toBeNull();
    expect(client.getTokenInfo()?.refresh_token).toBeUndefined();
  });

  it("uses an explicit UserInfo token without refreshing or replacing it", async () => {
    const { client } = setup(session({ expires_at: now }));
    const fetch = vi.fn().mockResolvedValue(response({ sub: "external-user" }));
    vi.stubGlobal("fetch", fetch);
    await client.getUserInfo("external-token");
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls[0][1].headers.Authorization).toBe(
      "Bearer external-token",
    );
  });

  it("does not fall back to a stored token for an empty explicit token", async () => {
    const { client } = setup(session());
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    await expect(client.getUserInfo("")).rejects.toThrow("No access token");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("shares a refresh between manual and concurrent automatic requests", async () => {
    const { client } = setup(session({ expires_at: now }));
    const pending = deferred<Response>();
    const fetch = vi
      .fn()
      .mockImplementation((url: string) =>
        url.endsWith("/token")
          ? pending.promise
          : Promise.resolve(response({ sub: "user" })),
      );
    vi.stubGlobal("fetch", fetch);
    const manual = client.refreshToken();
    const first = client.getUserInfo();
    const second = client.getUserInfo();
    expect(fetch).toHaveBeenCalledTimes(1);
    pending.resolve(response({ ...fresh, refresh_token: "rotated" }));
    await Promise.all([manual, first, second]);
    expect(
      fetch.mock.calls.filter(([url]) => url.endsWith("/token")),
    ).toHaveLength(1);
    expect(client.getTokenInfo()?.refresh_token).toBe("rotated");
  });

  it("clears ID tokens and nonce on logout and rejects a late refresh", async () => {
    const { client, storage } = setup(session());
    client.createAuthorizeUrl(undefined, { nonce: "old-nonce" });
    const pending = deferred<Response>();
    vi.stubGlobal("fetch", vi.fn().mockReturnValue(pending.promise));
    const refresh = client.refreshToken();
    const rejected = expect(refresh).rejects.toThrow();
    client.logout();
    pending.resolve(response({ ...fresh, id_token: idToken }));
    await rejected;
    expect(client.getStoredIdToken()).toBeNull();
    expect(client.getTokenInfo()).toBeNull();
    expect(storage.getItem(key)).toBeNull();
  });

  it.each([200, 400])(
    "does not overwrite or clear a newer login after an old refresh returns %i",
    async status => {
      const { client } = setup(session());
      const pending = deferred<Response>();
      vi.stubGlobal(
        "fetch",
        vi
          .fn()
          .mockReturnValueOnce(pending.promise)
          .mockResolvedValueOnce(
            response({ ...fresh, access_token: "new-login" }),
          ),
      );
      const refresh = client.refreshToken();
      const rejected = expect(refresh).rejects.toThrow();
      await client.exchangeCode("new-login-code");
      pending.resolve(
        response(status === 200 ? fresh : { error: "invalid_grant" }, status),
      );
      await rejected;
      expect(client.getStoredAccessToken()).toBe("new-login");
    },
  );

  it("does not restore a late code exchange after logout", async () => {
    const { client } = setup();
    const pending = deferred<Response>();
    vi.stubGlobal("fetch", vi.fn().mockReturnValue(pending.promise));
    const exchange = client.exchangeCode("code");
    const rejected = expect(exchange).rejects.toThrow();
    client.logout();
    pending.resolve(response(fresh));
    await rejected;
    expect(client.getTokenInfo()).toBeNull();
  });

  it("does not return stored-session UserInfo after logout", async () => {
    const { client } = setup(session());
    const pending = deferred<Response>();
    const fetch = vi.fn().mockReturnValue(pending.promise);
    vi.stubGlobal("fetch", fetch);
    const info = client.getUserInfo();
    const rejected = expect(info).rejects.toThrow();
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    client.logout();
    pending.resolve(response({ sub: "old-user" }));
    await rejected;
  });

  it("does not expose mutable internal token metadata", () => {
    const { client } = setup(session());
    const info = client.getTokenInfo();
    if (info) info.access_token = "replaced";
    expect(client.getStoredAccessToken()).toBe("old-access");
  });
  it("does not carry identity or scope across an explicit refresh-token switch", async () => {
    const { client } = setup(session());
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response(fresh)));
    await client.refreshToken("another-session-refresh");
    expect(client.getStoredIdToken()).toBeNull();
    expect(client.getTokenInfo()?.scope).toBeUndefined();
    expect(client.getTokenInfo()?.refresh_token).toBe(
      "another-session-refresh",
    );
  });

  it("does not fall back for empty explicit validation or return valid after logout", async () => {
    const { client } = setup(session());
    const pending = deferred<Response>();
    const fetch = vi.fn().mockReturnValue(pending.promise);
    vi.stubGlobal("fetch", fetch);
    await expect(client.validateToken("")).resolves.toBe(false);
    expect(fetch).not.toHaveBeenCalled();
    const validating = client.validateToken();
    client.logout();
    pending.resolve(response({ sub: "old-user" }));
    await expect(validating).resolves.toBe(false);
  });

  it("does not trust a discovery issuer outside the configured server", async () => {
    const { client } = setup(session());
    vi.spyOn(OIDCUtils, "getDiscoveryDocument").mockResolvedValue({
      issuer: "https://attacker.example.com",
      jwks_uri: "https://attacker.example.com/jwks",
    } as Awaited<ReturnType<typeof OIDCUtils.getDiscoveryDocument>>);
    const verify = vi.spyOn(OIDCUtils, "validateAndParseIdTokenWithCrypto");
    await expect(client.validateIdToken()).rejects.toThrow("Discovery issuer");
    expect(verify).not.toHaveBeenCalled();
  });

  it("does not complete default ID-token validation after logout", async () => {
    const { client } = setup(session());
    const discovery =
      deferred<Awaited<ReturnType<typeof OIDCUtils.getDiscoveryDocument>>>();
    vi.spyOn(OIDCUtils, "getDiscoveryDocument").mockReturnValue(
      discovery.promise,
    );
    const validating = client.validateIdToken();
    const rejected = expect(validating).rejects.toThrow(
      "Authentication state changed",
    );
    client.logout();
    discovery.resolve({
      issuer: config.server,
      jwks_uri: `${config.server}/jwks`,
    } as Awaited<ReturnType<typeof OIDCUtils.getDiscoveryDocument>>);
    await rejected;
  });

  it("uses a fresh grant's nonce and clears it after logout or a later grant", async () => {
    const { client } = setup();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(response({ ...fresh, id_token: idToken })),
    );
    vi.spyOn(OIDCUtils, "getDiscoveryDocument").mockResolvedValue({
      issuer: config.server,
      jwks_uri: `${config.server}/jwks`,
    } as Awaited<ReturnType<typeof OIDCUtils.getDiscoveryDocument>>);
    const verify = vi
      .spyOn(OIDCUtils, "validateAndParseIdTokenWithCrypto")
      .mockResolvedValue({ sub: "user" } as Awaited<
        ReturnType<typeof OIDCUtils.validateAndParseIdTokenWithCrypto>
      >);
    client.createAuthorizeUrl(undefined, { nonce: "fresh-nonce" });
    await client.exchangeCode("first-code");
    await client.validateIdToken();
    expect(verify.mock.calls[0][4]).toBe("fresh-nonce");
    client.logout();
    await client.exchangeCode("second-code");
    await client.validateIdToken();
    expect(verify.mock.calls[1][4]).toBeUndefined();
    client.createAuthorizeUrl(undefined, { nonce: "another-nonce" });
    client.createAuthorizeUrl();
    await client.exchangeCode("third-code");
    await client.validateIdToken();
    expect(verify.mock.calls[2][4]).toBeUndefined();
  });

  it("records requested downscoping when the refresh response omits scope", async () => {
    const { client } = setup(session());
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response(fresh)));
    await client.refreshToken(undefined, "openid");
    expect(client.getTokenInfo()?.scope).toBe("openid");
  });

  it.each(["refresh_token", "id_token", "scope"])(
    "rejects an invalid refresh response %s",
    async field => {
      const { client } = setup(session());
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(response({ ...fresh, [field]: null })),
      );
      await expect(client.refreshToken()).rejects.toThrow();
      expect(client.getTokenInfo()).toBeNull();
    },
  );

  it("rejects conflicting concurrent refresh scopes without corrupting the active request", async () => {
    const { client } = setup(session());
    const pending = deferred<Response>();
    const fetch = vi.fn().mockReturnValue(pending.promise);
    vi.stubGlobal("fetch", fetch);
    const first = client.refreshToken(undefined, "openid");
    await expect(client.refreshToken(undefined, "profile")).rejects.toThrow(
      "already in progress",
    );
    expect(fetch).toHaveBeenCalledTimes(1);
    pending.resolve(response(fresh));
    await first;
    expect(client.getStoredAccessToken()).toBe("fresh-access");
    expect(client.getTokenInfo()?.scope).toBe("openid");
  });
  it("never sends an expired stored access token with auto refresh disabled", async () => {
    const storage = new MemoryStorage();
    storage.setItem(key, JSON.stringify(session({ expires_at: now })));
    const client = new FlowAuthClient({
      ...config,
      storage,
      autoRefresh: false,
    });
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    await expect(client.getUserInfo()).rejects.toThrow("No access token");
    expect(fetch).not.toHaveBeenCalled();
    expect(client.getTokenInfo()?.refresh_token).toBe("refresh-token");
  });

  it("allows only the newest overlapping code exchange to establish a session", async () => {
    const { client } = setup();
    const firstResponse = deferred<Response>();
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockReturnValueOnce(firstResponse.promise)
        .mockResolvedValueOnce(
          response({ ...fresh, access_token: "second-login" }),
        ),
    );
    const first = client.exchangeCode("first");
    const rejected = expect(first).rejects.toThrow(
      "Authentication state changed",
    );
    await client.exchangeCode("second");
    firstResponse.resolve(response(fresh));
    await rejected;
    expect(client.getStoredAccessToken()).toBe("second-login");
  });
});
