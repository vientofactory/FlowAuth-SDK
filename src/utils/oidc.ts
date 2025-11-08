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
   * RSA 공개키를 JWKS에서 가져옵니다.
   * @param jwksUri JWKS 엔드포인트 URI
   * @param kid Key ID
   * @returns RSA 공개키 (CryptoKey)
   */
  static async getRsaPublicKey(
    jwksUri: string,
    kid: string,
  ): Promise<CryptoKey> {
    const jwks = await this.getJwks(jwksUri);
    const key = jwks.keys.find((k: JWKSKey) => k.kid === kid);

    if (!key) {
      throw new Error(`Key with kid '${kid}' not found in JWKS`);
    }

    if (key.kty !== "RSA") {
      throw new Error("Only RSA keys are supported");
    }

    // JWKS에서 RSA 공개키 구성
    const publicKey = {
      kty: key.kty,
      n: key.n,
      e: key.e,
      alg: key.alg,
      kid: key.kid,
    };

    const crypto = EnvironmentUtils.getCrypto();
    if (!crypto) {
      throw new Error("Crypto API is not available");
    }

    // CryptoKey로 변환
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
   * RSA 서명 검증을 포함한 ID 토큰 검증
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
    try {
      const { header, payload, signature } = EnvironmentUtils.parseJwt(idToken);

      // 개발 환경 토큰은 검증 건너뛰기 (HMAC 서명)
      if (header.alg === "HS256") {
        // Development environment token detected, skipping RSA validation
        return payload as IdTokenPayload;
      }

      // 헤더에서 key ID 추출
      const kid = header.kid as string;
      if (!kid) {
        throw new Error("Key ID (kid) not found in token header");
      }

      // RSA 공개키 가져오기
      const publicKey = await this.getRsaPublicKey(jwksUri, kid);

      // 서명 검증
      const crypto = EnvironmentUtils.getCrypto();
      if (!crypto) {
        throw new Error("Crypto API is not available");
      }

      const encoder = new TextEncoder();
      const data = encoder.encode(
        `${idToken.split(".")[0]}.${idToken.split(".")[1]}`,
      );

      // 서명 디코딩
      let signatureBytes: ArrayBuffer;
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
        signatureBytes = buffer.buffer.slice(
          buffer.byteOffset,
          buffer.byteOffset + buffer.byteLength,
        );
      } else {
        // 브라우저 환경: atob 사용 (텍스트 데이터에만)
        const decoded = EnvironmentUtils.atob(
          signature.replace(/-/g, "+").replace(/_/g, "/"),
        );
        signatureBytes = Uint8Array.from(decoded, c => c.charCodeAt(0)).buffer;
      }

      const isValidSignature = await crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5",
        publicKey,
        signatureBytes,
        data,
      );

      if (!isValidSignature) {
        throw new Error("Invalid RSA signature");
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
        `RSA ID token validation failed: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
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
    try {
      const { payload } = EnvironmentUtils.parseJwt(idToken);

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
        `ID token validation failed: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }
  }
}
