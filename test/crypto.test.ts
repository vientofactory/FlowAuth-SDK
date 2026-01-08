import { describe, it, expect, beforeEach, vi } from "vitest";
import { OIDCUtils } from "../src/utils/oidc";
import { JWKSResponse } from "../src/types/oauth2";

describe("Crypto Support", () => {
  describe("RSA Key Handling", () => {
    const mockRsaJwks: JWKSResponse = {
      keys: [
        {
          kty: "RSA",
          kid: "rsa-test-key",
          n: "test-modulus",
          e: "AQAB",
          alg: "RS256",
          use: "sig",
        },
      ],
    };

    it("should get RSA public key from JWKS", async () => {
      // Mock fetch
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockRsaJwks),
      });

      // Mock crypto
      const mockKey = { type: "public" } as CryptoKey;
      const mockImportKey = vi.fn().mockResolvedValue(mockKey);
      vi.stubGlobal("crypto", {
        subtle: {
          importKey: mockImportKey,
        },
      });

      const key = await OIDCUtils.getPublicKey(
        "https://test.com/jwks",
        "rsa-test-key",
        "RS256",
      );

      expect(key).toBe(mockKey);
      expect(mockImportKey).toHaveBeenCalledWith(
        "jwk",
        expect.objectContaining({
          kty: "RSA",
          n: "test-modulus",
          e: "AQAB",
          alg: "RS256",
        }),
        {
          name: "RSASSA-PKCS1-v1_5",
          hash: "SHA-256",
        },
        false,
        ["verify"],
      );
    });

    it("should validate RSA key parameters", async () => {
      const invalidRsaJwks: JWKSResponse = {
        keys: [
          {
            kty: "RSA",
            kid: "rsa-invalid-key",
            alg: "RS256",
            // Missing n and e parameters
          },
        ],
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(invalidRsaJwks),
      });

      await expect(
        OIDCUtils.getPublicKey(
          "https://test.com/jwks",
          "rsa-invalid-key",
          "RS256",
        ),
      ).rejects.toThrow("Invalid RSA key: missing n or e parameter");
    });
  });

  describe("ECDSA Key Handling", () => {
    const mockEcdsaJwks: JWKSResponse = {
      keys: [
        {
          kty: "EC",
          kid: "ecdsa-test-key",
          crv: "P-256",
          x: "test-x-coordinate",
          y: "test-y-coordinate",
          alg: "ES256",
          use: "sig",
        },
      ],
    };

    it("should get ECDSA public key from JWKS", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockEcdsaJwks),
      });

      const mockKey = { type: "public" } as CryptoKey;
      const mockImportKey = vi.fn().mockResolvedValue(mockKey);
      vi.stubGlobal("crypto", {
        subtle: {
          importKey: mockImportKey,
        },
      });

      const key = await OIDCUtils.getPublicKey(
        "https://test.com/jwks",
        "ecdsa-test-key",
        "ES256",
      );

      expect(key).toBe(mockKey);
      expect(mockImportKey).toHaveBeenCalledWith(
        "jwk",
        expect.objectContaining({
          kty: "EC",
          crv: "P-256",
          x: "test-x-coordinate",
          y: "test-y-coordinate",
          alg: "ES256",
        }),
        {
          name: "ECDSA",
          namedCurve: "P-256",
        },
        false,
        ["verify"],
      );
    });

    it("should validate ECDSA key parameters", async () => {
      const invalidEcdsaJwks: JWKSResponse = {
        keys: [
          {
            kty: "EC",
            kid: "ecdsa-invalid-key",
            alg: "ES256",
            // Missing x, y, crv parameters
          },
        ],
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(invalidEcdsaJwks),
      });

      await expect(
        OIDCUtils.getPublicKey(
          "https://test.com/jwks",
          "ecdsa-invalid-key",
          "ES256",
        ),
      ).rejects.toThrow("Invalid ECDSA key: missing x, y, or crv parameter");
    });

    it("should reject unsupported ECDSA curves", async () => {
      const unsupportedCurveJwks: JWKSResponse = {
        keys: [
          {
            kty: "EC",
            kid: "ecdsa-unsupported-key",
            crv: "P-384", // Unsupported curve
            x: "test-x-coordinate",
            y: "test-y-coordinate",
            alg: "ES256",
            use: "sig",
          },
        ],
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(unsupportedCurveJwks),
      });

      await expect(
        OIDCUtils.getPublicKey(
          "https://test.com/jwks",
          "ecdsa-unsupported-key",
          "ES256",
        ),
      ).rejects.toThrow(
        "Unsupported ECDSA curve: P-384. Only P-256 is supported.",
      );
    });
  });

  describe("Algorithm Validation", () => {
    it("should reject unsupported algorithms", async () => {
      const jwks: JWKSResponse = {
        keys: [
          {
            kty: "RSA",
            kid: "test-key",
            n: "test-modulus",
            e: "AQAB",
            alg: "RS256",
            use: "sig",
          },
        ],
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(jwks),
      });

      await expect(
        OIDCUtils.getPublicKey("https://test.com/jwks", "test-key", "HS256"),
      ).rejects.toThrow(
        "Key algorithm 'RS256' does not match expected 'HS256'",
      );
    });

    it("should validate algorithm match", async () => {
      const jwks: JWKSResponse = {
        keys: [
          {
            kty: "RSA",
            kid: "test-key",
            n: "test-modulus",
            e: "AQAB",
            alg: "RS256",
            use: "sig",
          },
        ],
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(jwks),
      });

      await expect(
        OIDCUtils.getPublicKey("https://test.com/jwks", "test-key", "ES256"),
      ).rejects.toThrow(
        "Key algorithm 'RS256' does not match expected 'ES256'",
      );
    });
  });

  describe("Key Type Validation", () => {
    it("should reject RSA algorithm with EC key", async () => {
      const jwks: JWKSResponse = {
        keys: [
          {
            kty: "EC",
            kid: "test-key",
            crv: "P-256",
            x: "test-x-coordinate",
            y: "test-y-coordinate",
            alg: "ES256",
            use: "sig",
          },
        ],
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(jwks),
      });

      await expect(
        OIDCUtils.getPublicKey("https://test.com/jwks", "test-key", "RS256"),
      ).rejects.toThrow(
        "Key algorithm 'ES256' does not match expected 'RS256'",
      );
    });

    it("should reject ECDSA algorithm with RSA key", async () => {
      const jwks: JWKSResponse = {
        keys: [
          {
            kty: "RSA",
            kid: "test-key",
            n: "test-modulus",
            e: "AQAB",
            alg: "RS256",
            use: "sig",
          },
        ],
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(jwks),
      });

      await expect(
        OIDCUtils.getPublicKey("https://test.com/jwks", "test-key", "ES256"),
      ).rejects.toThrow(
        "Key algorithm 'RS256' does not match expected 'ES256'",
      );
    });
  });

  describe("Signature Verification", () => {
    let mockVerify: any;

    beforeEach(() => {
      mockVerify = vi.fn();
      // Use vi.stubGlobal instead of direct assignment
      vi.stubGlobal("crypto", {
        subtle: {
          verify: mockVerify,
        },
      });
    });

    it("should verify RSA signature", async () => {
      mockVerify.mockResolvedValue(true);

      const mockKey = { type: "public" } as CryptoKey;
      const idToken =
        "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";

      // Access private method for testing
      const result = await (OIDCUtils as any).verifySignature(
        idToken,
        mockKey,
        "RS256",
        "signature",
      );

      expect(result).toBe(true);
      expect(mockVerify).toHaveBeenCalledWith(
        "RSASSA-PKCS1-v1_5",
        mockKey,
        expect.any(ArrayBuffer),
        expect.any(Uint8Array),
      );
    });

    it("should verify ECDSA signature", async () => {
      mockVerify.mockResolvedValue(true);

      const mockKey = { type: "public" } as CryptoKey;
      const idToken =
        "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";

      const result = await (OIDCUtils as any).verifySignature(
        idToken,
        mockKey,
        "ES256",
        "signature",
      );

      expect(result).toBe(true);
      expect(mockVerify).toHaveBeenCalledWith(
        {
          name: "ECDSA",
          hash: "SHA-256",
        },
        mockKey,
        expect.any(ArrayBuffer),
        expect.any(Uint8Array),
      );
    });
  });
});
