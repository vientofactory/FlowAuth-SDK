import { webcrypto } from "node:crypto";
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { OIDCUtils } from "../src/utils/oidc";
import { EnvironmentUtils } from "../src/utils/environment";
import type { JWKSKey } from "../src/types/oauth2";

interface SigningKeys {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

const crypto = webcrypto as unknown as Crypto;
const issuer = "https://issuer.example.com";
const audience = "client-id";
const jwksUri = `${issuer}/jwks`;
const now = 1792713600;
const keys = new Map<string, SigningKeys>();
const jwks: JWKSKey[] = [];

beforeAll(async () => {
  for (const alg of ["RS256", "ES256"]) {
    const pair = (await crypto.subtle.generateKey(
      alg === "RS256"
        ? {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
          }
        : { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as SigningKeys;
    keys.set(alg, pair);
    jwks.push({
      ...(await crypto.subtle.exportKey("jwk", pair.publicKey)),
      kid: alg,
      alg,
      use: "sig",
      kty: alg === "RS256" ? "RSA" : "EC",
    });
  }
});
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(now * 1000);
  vi.stubGlobal("crypto", crypto);
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(new Response(JSON.stringify({ keys: jwks }))),
  );
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

function claims() {
  return {
    iss: issuer,
    aud: audience,
    sub: "user",
    iat: now - 10,
    exp: now + 3600,
    nonce: "nonce",
  };
}
function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}
async function sign(
  alg: string,
  payload: Record<string, unknown>,
): Promise<string> {
  const input = `${encode({ alg, kid: alg })}.${encode(payload)}`;
  const pair = keys.get(alg);
  if (!pair) throw new Error("Missing test key");
  const signature = await crypto.subtle.sign(
    alg === "RS256" ? "RSASSA-PKCS1-v1_5" : { name: "ECDSA", hash: "SHA-256" },
    pair.privateKey,
    new TextEncoder().encode(input),
  );
  return `${input}.${Buffer.from(signature).toString("base64url")}`;
}
function verify(token: string) {
  return OIDCUtils.validateAndParseIdTokenWithCrypto(
    token,
    jwksUri,
    issuer,
    audience,
    "nonce",
  );
}

describe("Real ID token signature verification", () => {
  it.each(["RS256", "ES256"])("verifies a real %s signature", async alg => {
    await expect(verify(await sign(alg, claims()))).resolves.toMatchObject({
      sub: "user",
    });
  });

  it.each(["HS256", "none", "RS512", "ES384"])(
    "rejects %s before fetching a key",
    async alg => {
      const token = `${encode({ alg, kid: "key" })}.${encode(claims())}.signature`;
      await expect(verify(token)).rejects.toThrow("Unsupported algorithm");
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it.each(["RS256", "ES256"])("rejects a tampered %s payload", async alg => {
    const parts = (await sign(alg, claims())).split(".");
    parts[1] = encode({ ...claims(), sub: "attacker" });
    await expect(verify(parts.join("."))).rejects.toThrow("signature");
  });

  it.each([undefined, null, "later", now, now - 1, NaN, Infinity])(
    "rejects a signed token with expiration %j",
    async exp => {
      await expect(
        verify(await sign("RS256", { ...claims(), exp })),
      ).rejects.toThrow();
    },
  );

  it.each([
    { iss: "https://other.example.com" },
    { aud: "other-client" },
    { nonce: "other-nonce" },
    { sub: "" },
    { iat: undefined },
    { iat: "yesterday" },
    { iat: now + 1 },
    { nbf: now + 1 },
  ])("rejects signed invalid claims %j", async overrides => {
    await expect(
      verify(await sign("ES256", { ...claims(), ...overrides })),
    ).rejects.toThrow();
  });

  it.each([undefined, null, "later", now, now - 1])(
    "treats invalid or boundary expiry %j as expired",
    exp => {
      expect(
        EnvironmentUtils.isTokenExpired(
          `${encode({ alg: "RS256" })}.${encode({ exp })}.signature`,
        ),
      ).toBe(true);
    },
  );

  it("marks claims-only parsing as unable to accept HS256", () => {
    const token = `${encode({ alg: "HS256" })}.${encode(claims())}.signature`;
    expect(() =>
      OIDCUtils.validateAndParseIdToken(token, issuer, audience),
    ).toThrow("Unsupported algorithm");
  });
  it("rechecks expiration after asynchronous key retrieval", async () => {
    const token = await sign("RS256", { ...claims(), exp: now + 1 });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async () => {
        vi.setSystemTime((now + 1) * 1000);
        return new Response(JSON.stringify({ keys: jwks }));
      }),
    );
    await expect(verify(token)).rejects.toThrow("Token is expired");
  });
});
