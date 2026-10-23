import { EnvironmentUtils } from "./environment";
import {
  IdTokenPayload,
  JWKSKey,
  JWKSResponse,
  OIDCDiscoveryDocument,
} from "../types/oauth2";

/**
 * OpenID Connect 유틸리티 클래스
 * OIDC 관련 기능을 제공합니다.
 */
export class OIDCUtils {
  /**
   * OIDC Discovery 문서를 가져옵니다.
   * @param issuer Issuer URL
   * @returns Discovery 문서
   */
  static async getDiscoveryDocument(
    issuer: string,
  ): Promise<OIDCDiscoveryDocument> {
    const discoveryUrl = `${issuer}/.well-known/openid-configuration`;
    const response = await EnvironmentUtils.getFetch()(discoveryUrl);

    if (!response.ok) {
      throw new Error(`Failed to fetch discovery document: ${response.status}`);
    }

    return await response.json();
  }

  /**
   * JWKS (JSON Web Key Set)를 가져옵니다.
   * @param jwksUri JWKS URI
   * @returns JWKS
   */
  static async getJwks(jwksUri: string): Promise<JWKSResponse> {
    const response = await EnvironmentUtils.getFetch()(jwksUri);

    if (!response.ok) {
      throw new Error(`Failed to fetch JWKS: ${response.status}`);
    }

    return await response.json();
  }

  /**
   * 공개키를 JWKS에서 가져옵니다 (RSA/ECDSA 모두 지원).
   * @param jwksUri JWKS 엔드포인트 URI
   * @param kid Key ID
   * @param alg 알고리즘 (RS256, ES256)
   * @returns 공개키 (CryptoKey)
   */
  static async getPublicKey(
    jwksUri: string,
    kid: string,
    alg: string,
  ): Promise<CryptoKey> {
    const jwks = await this.getJwks(jwksUri);
    const key = jwks.keys.find((k: JWKSKey) => k.kid === kid);

    if (!key) {
      throw new Error(`Key with kid '${kid}' not found in JWKS`);
    }

    if (key.alg && key.alg !== alg) {
      throw new Error(
        `Key algorithm '${key.alg}' does not match expected '${alg}'`,
      );
    }

    const crypto = EnvironmentUtils.getCrypto();
    if (!crypto) {
      throw new Error("Crypto API is not available");
    }

    if (alg === "RS256") {
      return this.importRsaKey(crypto, key);
    } else if (alg === "ES256") {
      return this.importEcdsaKey(crypto, key);
    } else {
      throw new Error(`Unsupported algorithm: ${alg}`);
    }
  }

  /**
   * RSA 공개키를 가져옵니다 (호환성을 위한 래퍼).
   * @param jwksUri JWKS 엔드포인트 URI
   * @param kid Key ID
   * @returns RSA 공개키 (CryptoKey)
   */
  static async getRsaPublicKey(
    jwksUri: string,
    kid: string,
  ): Promise<CryptoKey> {
    return this.getPublicKey(jwksUri, kid, "RS256");
  }

  /**
   * ECDSA 공개키를 가져옵니다.
   * @param jwksUri JWKS 엔드포인트 URI
   * @param kid Key ID
   * @returns ECDSA 공개키 (CryptoKey)
   */
  static async getEcdsaPublicKey(
    jwksUri: string,
    kid: string,
  ): Promise<CryptoKey> {
    return this.getPublicKey(jwksUri, kid, "ES256");
  }

  /**
   * RSA 키를 CryptoKey로 가져옵니다.
   * @private
   */
  private static async importRsaKey(
    crypto: Crypto,
    key: JWKSKey,
  ): Promise<CryptoKey> {
    if (key.kty !== "RSA") {
      throw new Error(`Expected RSA key, got ${key.kty}`);
    }

    if (!key.n || !key.e) {
      throw new Error("Invalid RSA key: missing n or e parameter");
    }

    const publicKey = {
      kty: key.kty,
      n: key.n,
      e: key.e,
      alg: key.alg || "RS256",
      kid: key.kid,
      use: key.use || "sig",
    };

    return await crypto.subtle.importKey(
      "jwk",
      publicKey,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
      },
      false,
      ["verify"],
    );
  }

  /**
   * ECDSA 키를 CryptoKey로 가져옵니다.
   * @private
   */
  private static async importEcdsaKey(
    crypto: Crypto,
    key: JWKSKey,
  ): Promise<CryptoKey> {
    if (key.kty !== "EC") {
      throw new Error(`Expected EC key, got ${key.kty}`);
    }

    if (!key.x || !key.y || !key.crv) {
      throw new Error("Invalid ECDSA key: missing x, y, or crv parameter");
    }

    if (key.crv !== "P-256") {
      throw new Error(
        `Unsupported ECDSA curve: ${key.crv}. Only P-256 is supported.`,
      );
    }

    const publicKey = {
      kty: key.kty,
      crv: key.crv,
      x: key.x,
      y: key.y,
      alg: key.alg || "ES256",
      kid: key.kid,
      use: key.use || "sig",
    };

    return await crypto.subtle.importKey(
      "jwk",
      publicKey,
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      false,
      ["verify"],
    );
  }

  /** Verify an RS256/ES256 signature and all required ID token claims. */
  static async validateAndParseIdTokenWithCrypto(
    idToken: string,
    jwksUri: string,
    expectedIssuer: string,
    expectedAudience: string,
    expectedNonce?: string,
  ): Promise<IdTokenPayload> {
    try {
      const { header, signature } = EnvironmentUtils.parseJwt(idToken);
      const alg = header.alg;
      if (alg !== "RS256" && alg !== "ES256") {
        throw new Error(`Unsupported algorithm: ${String(alg)}`);
      }
      if (typeof header.kid !== "string" || !header.kid.trim()) {
        throw new Error("Key ID (kid) not found in token header");
      }
      // Reject malformed claims before fetching keys, but never authenticate
      // until the signature has been checked against the issuer's public key.
      this.validateAndParseIdToken(
        idToken,
        expectedIssuer,
        expectedAudience,
        expectedNonce,
      );
      const publicKey = await this.getPublicKey(jwksUri, header.kid, alg);
      if (!(await this.verifySignature(idToken, publicKey, alg, signature))) {
        throw new Error(`Invalid ${alg} signature`);
      }
      // Key retrieval and verification can outlast the token's remaining life.
      return this.validateAndParseIdToken(
        idToken,
        expectedIssuer,
        expectedAudience,
        expectedNonce,
      );
    } catch (error) {
      throw new Error(
        `Crypto ID token validation failed: ${error instanceof Error ? error.message : "Unknown error"}`,
        { cause: error },
      );
    }
  }

  /**
   * RSA 서명 검증을 포함한 ID 토큰 검증 (호환성을 위한 래퍼)
   * @param idToken ID 토큰
   * @param jwksUri JWKS 엔드포인트 URI
   * @param expectedIssuer 예상 issuer
   * @param expectedAudience 예상 audience
   * @param expectedNonce 예상 nonce
   * @returns 검증된 토큰 페이로드
   */
  static async validateAndParseIdTokenWithRsa(
    idToken: string,
    jwksUri: string,
    expectedIssuer: string,
    expectedAudience: string,
    expectedNonce?: string,
  ): Promise<IdTokenPayload> {
    return this.validateAndParseIdTokenWithCrypto(
      idToken,
      jwksUri,
      expectedIssuer,
      expectedAudience,
      expectedNonce,
    );
  }

  /**
   * 서명을 검증합니다 (RSA/ECDSA).
   * @private
   */
  private static async verifySignature(
    idToken: string,
    publicKey: CryptoKey,
    algorithm: string,
    signature: string,
  ): Promise<boolean> {
    const crypto = EnvironmentUtils.getCrypto();
    if (!crypto) {
      throw new Error("Crypto API is not available");
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(
      `${idToken.split(".")[0]}.${idToken.split(".")[1]}`,
    );

    // 서명 디코딩
    const signatureBytes = this.decodeSignature(signature);

    // 알고리즘에 따른 서명 검증
    if (algorithm === "RS256") {
      return await crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5",
        publicKey,
        signatureBytes,
        data,
      );
    } else if (algorithm === "ES256") {
      return await crypto.subtle.verify(
        {
          name: "ECDSA",
          hash: "SHA-256",
        },
        publicKey,
        signatureBytes,
        data,
      );
    } else {
      throw new Error(`Unsupported signature algorithm: ${algorithm}`);
    }
  }

  /**
   * Base64URL 서명을 ArrayBuffer로 디코딩합니다.
   * @private
   */
  private static decodeSignature(signature: string): ArrayBuffer {
    if (EnvironmentUtils.isNode()) {
      // Node.js 환경: Buffer 사용
      const signatureBase64 = signature.replace(/-/g, "+").replace(/_/g, "/");
      const globalWithBuffer = globalThis as {
        Buffer?: {
          from: (
            input: string,
            encoding: string,
          ) => {
            buffer: ArrayBuffer;
            byteOffset: number;
            byteLength: number;
          };
        };
      };
      const buffer = globalWithBuffer.Buffer?.from(signatureBase64, "base64");
      if (!buffer) {
        throw new Error("Buffer is not available in Node.js environment");
      }
      return buffer.buffer.slice(
        buffer.byteOffset,
        buffer.byteOffset + buffer.byteLength,
      );
    } else {
      // 브라우저 환경: atob 사용
      const decoded = EnvironmentUtils.atob(
        signature.replace(/-/g, "+").replace(/_/g, "/"),
      );
      return Uint8Array.from(decoded, c => c.charCodeAt(0)).buffer;
    }
  }

  /**
   * Parse and check claims without verifying the signature.
   * This compatibility utility must never be used to authenticate a token.
   * Use validateAndParseIdTokenWithCrypto for trusted identity decisions.
   */
  static validateAndParseIdToken(
    idToken: string,
    expectedIssuer: string,
    expectedAudience: string,
    expectedNonce?: string,
  ): IdTokenPayload {
    if (typeof idToken !== "string" || !idToken) {
      throw new Error("Invalid ID token: string required");
    }
    if (idToken.length > 8192) throw new Error("ID token too large");
    const parts = idToken.split(".");
    if (parts.length !== 3) throw new Error("Invalid JWT format");
    if (parts.some(part => !/^[A-Za-z0-9_-]+$/.test(part))) {
      throw new Error("Invalid JWT encoding");
    }
    const { header, payload } = EnvironmentUtils.parseJwt(idToken);
    if (header.alg !== "RS256" && header.alg !== "ES256") {
      throw new Error(`Unsupported algorithm: ${String(header.alg)}`);
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new Error("Invalid payload structure");
    }
    if (typeof payload.iss !== "string" || payload.iss !== expectedIssuer) {
      throw new Error("Invalid issuer");
    }
    if (typeof payload.aud !== "string" || payload.aud !== expectedAudience) {
      throw new Error("Invalid audience");
    }
    if (typeof payload.sub !== "string" || !payload.sub.trim()) {
      throw new Error("Missing or invalid subject claim");
    }
    const now = Math.floor(Date.now() / 1000);
    if (
      typeof payload.iat !== "number" ||
      !Number.isFinite(payload.iat) ||
      payload.iat > now
    ) {
      throw new Error("Missing or invalid issued at claim");
    }
    if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) {
      throw new Error("Missing or invalid expiration claim");
    }
    if (EnvironmentUtils.isTokenExpired(idToken))
      throw new Error("Token is expired");
    if (
      payload.nbf !== undefined &&
      (typeof payload.nbf !== "number" ||
        !Number.isFinite(payload.nbf) ||
        payload.nbf > now)
    ) {
      throw new Error("Invalid not before claim");
    }
    if (expectedNonce !== undefined && payload.nonce !== expectedNonce) {
      throw new Error("Invalid nonce");
    }
    return payload as IdTokenPayload;
  }
}
