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

  /**
   * 암호화 서명 검증을 포함한 ID 토큰 검증 (RSA/ECDSA 모두 지원)
   * @param idToken ID 토큰
   * @param jwksUri JWKS 엔드포인트 URI
   * @param expectedIssuer 예상 issuer
   * @param expectedAudience 예상 audience
   * @param expectedNonce 예상 nonce
   * @returns 검증된 토큰 페이로드
   */
  static async validateAndParseIdTokenWithCrypto(
    idToken: string,
    jwksUri: string,
    expectedIssuer: string,
    expectedAudience: string,
    expectedNonce?: string,
  ): Promise<IdTokenPayload> {
    try {
      const { header, payload, signature } = EnvironmentUtils.parseJwt(idToken);

      // 개발 환경 토큰은 검증 건너뛰기 (HMAC 서명)
      if (header.alg === "HS256") {
        return payload as IdTokenPayload;
      }

      // 알고리즘 확인
      const alg = header.alg as string;
      if (!alg || (!alg.startsWith("RS") && !alg.startsWith("ES"))) {
        throw new Error(`Unsupported algorithm: ${alg}`);
      }

      // 헤더에서 key ID 추출
      const kid = header.kid as string;
      if (!kid) {
        throw new Error("Key ID (kid) not found in token header");
      }

      // 공개키 가져오기 (RSA 또는 ECDSA)
      const publicKey = await this.getPublicKey(jwksUri, kid, alg);

      // 서명 검증
      const isValidSignature = await this.verifySignature(
        idToken,
        publicKey,
        alg,
        signature,
      );

      if (!isValidSignature) {
        throw new Error(`Invalid ${alg} signature`);
      }

      // 기본 검증
      if (payload.iss !== expectedIssuer) {
        throw new Error("Invalid issuer");
      }

      if (payload.aud !== expectedAudience) {
        throw new Error("Invalid audience");
      }

      // 만료 확인
      if (EnvironmentUtils.isTokenExpired(idToken)) {
        throw new Error("Token is expired");
      }

      // nonce 검증 (있는 경우)
      if (expectedNonce && payload.nonce !== expectedNonce) {
        throw new Error("Invalid nonce");
      }

      return payload as IdTokenPayload;
    } catch (error) {
      throw new Error(
        `Crypto ID token validation failed: ${error instanceof Error ? error.message : "Unknown error"}`,
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
   * 기본 ID 토큰 검증 (RSA 서명 검증 제외)
   * @param idToken ID 토큰
   * @param expectedIssuer 예상 issuer
   * @param expectedAudience 예상 audience
   * @param expectedNonce 예상 nonce
   * @returns 검증된 토큰 페이로드
   */
  static validateAndParseIdToken(
    idToken: string,
    expectedIssuer: string,
    expectedAudience: string,
    expectedNonce?: string,
  ): IdTokenPayload {
    // Input validation
    if (!idToken || typeof idToken !== "string") {
      throw new Error("Invalid ID token: string required");
    }

    // Token length validation
    if (idToken.length > 8192) {
      throw new Error("ID token too large");
    }

    // Basic JWT format validation
    const parts = idToken.split(".");
    if (parts.length !== 3) {
      throw new Error("Invalid JWT format");
    }

    // Validate each part is Base64URL
    for (const part of parts) {
      if (!/^[A-Za-z0-9_-]*$/.test(part)) {
        throw new Error("Invalid JWT encoding");
      }
    }

    try {
      const { payload } = EnvironmentUtils.parseJwt(idToken);

      // Enhanced payload validation
      if (!payload || typeof payload !== "object") {
        throw new Error("Invalid payload structure");
      }

      // Basic validation
      if (typeof payload.iss !== "string" || payload.iss !== expectedIssuer) {
        throw new Error("Invalid issuer");
      }

      if (typeof payload.aud !== "string" || payload.aud !== expectedAudience) {
        throw new Error("Invalid audience");
      }

      // Required claims validation
      if (!payload.sub || typeof payload.sub !== "string") {
        throw new Error("Missing or invalid subject claim");
      }

      if (!payload.iat || typeof payload.iat !== "number") {
        throw new Error("Missing or invalid issued at claim");
      }

      if (!payload.exp || typeof payload.exp !== "number") {
        throw new Error("Missing or invalid expiration claim");
      }

      // 만료 확인
      if (EnvironmentUtils.isTokenExpired(idToken)) {
        throw new Error("Token is expired");
      }

      // nonce 검증 (있는 경우)
      if (expectedNonce) {
        if (
          typeof payload.nonce !== "string" ||
          payload.nonce !== expectedNonce
        ) {
          throw new Error("Invalid nonce");
        }
      }

      return payload as IdTokenPayload;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error("ID token validation failed: Unknown error");
    }
  }
}
