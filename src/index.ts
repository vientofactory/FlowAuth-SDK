/**
 * OAuth2 클라이언트 설정 인터페이스
 */
interface OAuth2ClientConfig {
  /** FlowAuth 백엔드 서버 URL */
  server: string;
  /** OAuth2 클라이언트 ID */
  clientId: string;
  /** OAuth2 클라이언트 시크릿 */
  clientSecret: string;
  /** 인증 후 리다이렉트될 URI */
  redirectUri: string;
  /** 토큰 저장을 위한 스토리지 (기본값: 브라우저 sessionStorage) */
  storage?: Storage;
  /** 자동 토큰 리프래시 활성화 여부 (기본값: true) */
  autoRefresh?: boolean;
}

/**
 * PKCE (Proof Key for Code Exchange) 코드 객체 인터페이스
 */
interface PKCECodes {
  /** PKCE 코드 검증자 */
  codeVerifier: string;
  /** PKCE 코드 챌린지 */
  codeChallenge: string;
  /** 코드 챌린지 메소드 (기본값: "S256") */
  codeChallengeMethod?: string;
}

/**
 * OAuth2 스코프 열거형
 * FlowAuth에서 지원하는 권한 스코프들을 정의합니다.
 */
export enum OAuth2Scope {
  /** OpenID Connect 인증을 위한 기본 스코프 */
  OPENID = "openid",
  /** 사용자 프로필 정보 (이름, 생년월일, 지역, 사진 등) 접근 */
  PROFILE = "profile",
  /** 사용자 이메일 주소 읽기 */
  EMAIL = "email",
  /** 계정의 기본 정보 읽기 (사용자 ID, 이름 등) - 레거시 */
  IDENTIFY = "identify",
}

/**
 * 기본 스코프 목록
 * 새로운 클라이언트에 기본적으로 부여되는 스코프들입니다.
 */
export const DEFAULT_SCOPES: OAuth2Scope[] = [OAuth2Scope.OPENID, OAuth2Scope.PROFILE];

/**
 * OIDC ID 토큰 페이로드 인터페이스
 */
interface IdTokenPayload {
  /** 발급자 (Issuer) */
  iss: string;
  /** 대상자 (Audience) */
  aud: string;
  /** 만료 시간 (Expiration Time) */
  exp: number;
  /** 발급 시간 (Issued At) */
  iat: number;
  /** 주체 (Subject) - 사용자 ID */
  sub: string;
  /** 인증 시간 (Authentication Time) */
  auth_time?: number;
  /** Nonce 값 (Replay Attack 방지) */
  nonce?: string;
  /** 인증 컨텍스트 클래스 참조 */
  acr?: string;
  /** 허용된 인증 방법 */
  amr?: string[];
  /** 권한 부여자 */
  azp?: string;
  /** 추가 클레임들 */
  [key: string]: any;
}

/**
 * JWKS (JSON Web Key Set) 키 인터페이스
 */
interface JWKSKey {
  /** 키 타입 */
  kty: string;
  /** 키 ID */
  kid: string;
  /** RSA 모듈러스 (Base64URL) */
  n: string;
  /** RSA 공개 지수 (Base64URL) */
  e: string;
  /** 알고리즘 */
  alg: string;
}

/**
 * JWKS 응답 인터페이스
 */
interface JWKSResponse {
  keys: JWKSKey[];
}

/**
 * OIDC Discovery 문서 인터페이스
 */
interface OIDCDiscoveryDocument {
  /** 발급자 */
  issuer: string;
  /** 인증 엔드포인트 */
  authorization_endpoint: string;
  /** 토큰 엔드포인트 */
  token_endpoint: string;
  /** UserInfo 엔드포인트 */
  userinfo_endpoint: string;
  /** JWKS URI */
  jwks_uri: string;
  /** 지원하는 스코프들 */
  scopes_supported: string[];
  /** 지원하는 응답 타입들 */
  response_types_supported: string[];
  /** 지원하는 토큰 엔드포인트 인증 방법들 */
  token_endpoint_auth_methods_supported: string[];
  /** 지원하는 ID 토큰 서명 알고리즘들 */
  id_token_signing_alg_values_supported: string[];
  /** 지원하는 클레임들 */
  claims_supported: string[];
}

/**
 * 환경 감지 및 호환성 유틸리티 클래스
 * 브라우저와 Node.js 환경 간의 API 차이를 처리합니다.
 */
class EnvironmentUtils {
  /**
   * 현재 환경이 브라우저인지 확인합니다.
   * @returns 브라우저 환경이면 true
   */
  static isBrowser(): boolean {
    return typeof window !== "undefined" && typeof window.document !== "undefined";
  }

  /**
   * 현재 환경이 Node.js인지 확인합니다.
   * @returns Node.js 환경이면 true
   */
  static isNode(): boolean {
    return typeof globalThis !== "undefined" && typeof (globalThis as any).process !== "undefined";
  }

  /**
   * 환경에 맞는 Crypto API를 반환합니다.
   * @returns Crypto API 인스턴스
   * @throws {Error} Crypto API를 사용할 수 없는 환경에서 발생
   */
  static getCrypto(): Crypto {
    if (this.isBrowser()) {
      return window.crypto;
    } else if (this.isNode()) {
      // Node.js 환경에서 crypto 모듈 사용
      try {
        // Node.js 15+에서는 globalThis.crypto.webcrypto 사용
        if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.subtle) {
          return globalThis.crypto;
        }
        // 구버전 Node.js에서는 crypto 모듈 import
        const nodeCrypto = (globalThis as any).require?.("crypto");
        if (nodeCrypto?.webcrypto) {
          return nodeCrypto.webcrypto as Crypto;
        }
        // crypto가 없는 환경에서는 에러 대신 null 반환 (테스트 환경 등)
        return null as any;
      } catch (error) {
        // crypto가 없는 환경에서는 null 반환
        return null as any;
      }
    }
    throw new Error("Crypto API is not available in this environment");
  }

  /**
   * 환경에 맞는 Base64 인코딩 함수를 사용하여 문자열을 인코딩합니다.
   * @param input - 인코딩할 문자열
   * @returns Base64로 인코딩된 문자열
   * @throws {Error} btoa를 사용할 수 없는 환경에서 발생
   */
  static btoa(input: string): string {
    if (this.isBrowser()) {
      return window.btoa(input);
    } else if (this.isNode()) {
      // Node.js Buffer 사용
      const Buffer = (globalThis as any).Buffer;
      if (Buffer) {
        return Buffer.from(input, "binary").toString("base64");
      }
      throw new Error("Buffer is not available in this Node.js environment");
    }
    throw new Error("btoa is not available in this environment");
  }

  /**
   * 브라우저 환경에서 사용할 기본 스토리지를 반환합니다.
   * @returns 사용할 수 있는 Storage 인스턴스 또는 undefined
   */
  static getDefaultStorage(): Storage | undefined {
    if (this.isBrowser()) {
      try {
        // sessionStorage를 먼저 시도, 실패하면 localStorage
        return window.sessionStorage || window.localStorage;
      } catch {
        // Private browsing 모드 등에서 storage가 제한될 수 있음
        return undefined;
      }
    }
    return undefined;
  }

  /**
   * 환경에 맞는 Fetch API를 반환합니다.
   * @returns Fetch API 함수
   * @throws {Error} fetch를 사용할 수 없는 환경에서 발생
   */
  static getFetch(): typeof fetch {
    if (this.isBrowser()) {
      return window.fetch;
    } else if (this.isNode()) {
      // Node.js 18+에서는 globalThis.fetch가 있지만, 구버전 호환을 위해
      if (typeof globalThis.fetch !== "undefined") {
        return globalThis.fetch;
      }
      // node-fetch 등의 polyfill이 필요할 수 있음
      const nodeFetch = (globalThis as any).require?.("node-fetch");
      if (nodeFetch) {
        return nodeFetch;
      }
      throw new Error("fetch is not available. Please install node-fetch or use Node.js 18+");
    }
    throw new Error("fetch is not available in this environment");
  }

  /**
   * JWT 토큰을 파싱합니다.
   * @param token JWT 토큰 문자열
   * @returns 헤더, 페이로드, 서명
   */
  static parseJwt(token: string): { header: any; payload: any; signature: string } {
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new Error("Invalid JWT token format");
    }

    const header = JSON.parse(this.atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
    const payload = JSON.parse(this.atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    const signature = parts[2];

    return { header, payload, signature };
  }

  /**
   * JWT 토큰의 만료 여부를 확인합니다.
   * @param token JWT 토큰 문자열
   * @returns 만료되었으면 true
   */
  static isTokenExpired(token: string): boolean {
    try {
      const { payload } = this.parseJwt(token);
      const currentTime = Math.floor(Date.now() / 1000);
      return payload.exp < currentTime;
    } catch {
      return true; // 파싱 실패 시 만료된 것으로 간주
    }
  }

  /**
   * Base64URL 디코딩 함수
   * @param input Base64URL 문자열
   * @returns 디코딩된 문자열
   */
  static atob(input: string): string {
    if (this.isBrowser()) {
      return window.atob(input.replace(/-/g, "+").replace(/_/g, "/"));
    } else if (this.isNode()) {
      const Buffer = (globalThis as any).Buffer;
      if (Buffer) {
        return Buffer.from(input.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString();
      }
      throw new Error("Buffer is not available in this Node.js environment");
    }
    throw new Error("atob is not available in this environment");
  }
}

/**
 * OpenID Connect 유틸리티 클래스
 * OIDC 관련 기능을 제공합니다.
 */
class OIDCUtils {
  /**
   * OIDC Discovery 문서를 가져옵니다.
   * @param issuer Issuer URL
   * @returns Discovery 문서
   */
  static async getDiscoveryDocument(issuer: string): Promise<OIDCDiscoveryDocument> {
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
  static async getRsaPublicKey(jwksUri: string, kid: string): Promise<CryptoKey> {
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
      ["verify"]
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
    expectedNonce?: string
  ): Promise<IdTokenPayload> {
    try {
      const { header, payload, signature } = EnvironmentUtils.parseJwt(idToken);

      // 개발 환경 토큰은 검증 건너뛰기 (HMAC 서명)
      if (header.alg === "HS256") {
        console.log("Development environment token detected, skipping RSA validation");
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
      const data = encoder.encode(`${idToken.split(".")[0]}.${idToken.split(".")[1]}`);
      const signatureBytes = Uint8Array.from(EnvironmentUtils.atob(signature.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

      const isValidSignature = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signatureBytes, data);

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
      throw new Error(`RSA ID token validation failed: ${error instanceof Error ? error.message : "Unknown error"}`);
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
  static validateAndParseIdToken(idToken: string, expectedIssuer: string, expectedAudience: string, expectedNonce?: string): IdTokenPayload {
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
      throw new Error(`ID token validation failed: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  }
}

/**
 * OAuth2 토큰 응답 인터페이스
 */

/**
 * OAuth2 토큰 응답 인터페이스
 */
interface TokenResponse {
  /** 액세스 토큰 */
  access_token: string;
  /** 리프래시 토큰 (선택적) */
  refresh_token?: string;
  /** ID 토큰 (OIDC 사용 시) */
  id_token?: string;
  /** 토큰 타입 (일반적으로 "Bearer") */
  token_type: string;
  /** 토큰 만료까지 남은 시간(초) */
  expires_in?: number;
  /** 토큰에 부여된 스코프 */
  scope?: string;
  /** 토큰 만료 시각 (Unix timestamp, 내부 사용) */
  expires_at?: number;
}

interface UserInfo {
  /** 사용자 고유 식별자 */
  sub: string;
  /** 사용자 이메일 (선택적) */
  email?: string;
  /** 사용자 이름 (선택적) */
  username?: string;
  /** 추가 사용자 정보 (확장 가능) */
  [key: string]: any;
}

interface TokenStorage {
  /** 액세스 토큰 */
  access_token: string;
  /** 리프래시 토큰 (선택적) */
  refresh_token?: string;
  /** ID 토큰 (OIDC 사용 시) */
  id_token?: string;
  /** 토큰 타입 */
  token_type: string;
  /** 토큰 만료 시각 (Unix timestamp) */
  expires_at: number;
  /** 토큰 스코프 */
  scope?: string;
}

class OAuth2Error extends Error {
  /**
   * OAuth2Error 생성자
   * @param message - 에러 메시지
   * @param status - HTTP 상태 코드 (선택적)
   * @param code - OAuth2 에러 코드 (선택적)
   */
  constructor(message: string, public status?: number, public code?: string) {
    super(message);
    this.name = "OAuth2Error";
  }
}

/**
 * FlowAuth OAuth2 클라이언트 SDK
 *
 * FlowAuth와의 OAuth2 통합을 위한 완전한 클라이언트 구현체입니다.
 * Authorization Code Grant 플로우를 지원하며, 자동 토큰 관리와 리프래시 기능을 제공합니다.
 *
 * @example
 * ```typescript
 * const client = new FlowAuthClient({
 *   server: 'https://flowauth.example.com',
 *   clientId: 'my-client-id',
 *   clientSecret: 'my-client-secret',
 *   redirectUri: 'https://myapp.com/callback'
 * });
 *
 * // 인증 URL 생성
 * const authUrl = client.createAuthorizeUrl([OAuth2Scope.PROFILE]);
 *
 * // 토큰 교환
 * const tokens = await client.exchangeCode('auth-code');
 *
 * // 사용자 정보 조회 (자동 토큰 리프래시)
 * const userInfo = await client.getUserInfo();
 * ```
 */
export class FlowAuthClient {
  /** OAuth2 클라이언트 ID */
  private clientId: string;
  /** OAuth2 클라이언트 시크릿 */
  private clientSecret: string;
  /** 인증 후 리다이렉트 URI */
  private redirectUri: string;
  /** FlowAuth 서버 URL */
  private server: string;
  /** 토큰 저장을 위한 스토리지 */
  private storage?: Storage;
  /** 자동 토큰 리프래시 활성화 여부 */
  private autoRefresh: boolean;
  /** 저장된 토큰 데이터 */
  private tokenData?: TokenStorage;
  /** 진행 중인 리프래시 작업 */
  private refreshPromise?: Promise<TokenResponse>;
  /** OIDC Discovery 문서 캐시 */
  private discoveryDocument?: OIDCDiscoveryDocument;
  /** 저장된 ID 토큰 */
  private idToken?: string;
  /** 저장된 nonce 값 */
  private nonce?: string;

  /**
   * FlowAuthClient 생성자
   *
   * @param config - OAuth2 클라이언트 설정
   * @throws {Error} 필수 파라미터가 누락된 경우
   *
   * @example
   * ```typescript
   * const client = new FlowAuthClient({
   *   server: 'https://flowauth.example.com',
   *   clientId: 'client-id',
   *   clientSecret: 'client-secret',
   *   redirectUri: 'https://myapp.com/callback',
   *   autoRefresh: true
   * });
   * ```
   */
  /**
   * FlowAuthClient 생성자
   * @param config - OAuth2 클라이언트 설정 객체
   * @throws {Error} 필수 파라미터가 누락된 경우
   */
  constructor(config: OAuth2ClientConfig) {
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.redirectUri = config.redirectUri;
    this.server = config.server;
    this.storage = config.storage || EnvironmentUtils.getDefaultStorage();
    this.autoRefresh = config.autoRefresh !== false;

    if (!this.clientId || !this.clientSecret || !this.redirectUri || !this.server) {
      throw new Error("All parameters (server, clientId, clientSecret, redirectUri) are required.");
    }

    // Load stored tokens
    this.loadStoredTokens();
  }

  /**
   * 인증 URL 생성
   *
   * 사용자를 FlowAuth 인증 페이지로 리다이렉트하기 위한 URL을 생성합니다.
   * 생성된 URL로 사용자를 이동시키면 OAuth2 인증 플로우가 시작됩니다.
   *
   * @param scopes - 요청할 권한 스코프 배열 (기본값: [OAuth2Scope.PROFILE])
   * @param state - CSRF 방지를 위한 상태값 (권장)
   * @param pkce - PKCE 코드 챌린지 (보안 강화용, 권장)
   * @param nonce - OIDC nonce 값 (openid 스코프 사용 시 필수)
   * @returns 완성된 인증 URL
   *
   * @example
   * ```typescript
   * // 기본 사용
   * const authUrl = client.createAuthorizeUrl([OAuth2Scope.PROFILE, OAuth2Scope.EMAIL], 'random-state-123');
   * window.location.href = authUrl;
   *
   * // OIDC 사용 (ID 토큰 포함)
   * const nonce = await FlowAuthClient.generateNonce();
   * const authUrl = client.createAuthorizeUrl([OAuth2Scope.OPENID, OAuth2Scope.PROFILE], 'state', undefined, nonce);
   *
   * // PKCE와 함께 사용
   * const pkce = await FlowAuthClient.generatePKCE();
   * const authUrl = client.createAuthorizeUrl([OAuth2Scope.PROFILE], 'state', pkce);
   * // pkce.codeVerifier를 안전하게 저장하여 토큰 교환 시 사용
   * ```
   */
  createAuthorizeUrl(scopes: OAuth2Scope[] = [OAuth2Scope.PROFILE], state?: string, pkce?: PKCECodes, nonce?: string): string {
    // OIDC를 사용하는 경우 response_type에 id_token 포함
    const hasOpenId = scopes.includes(OAuth2Scope.OPENID);
    const responseType = hasOpenId ? "code id_token" : "code";

    const params = new URLSearchParams({
      response_type: responseType,
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: scopes.join(" "),
    });

    if (state) params.set("state", state);
    if (nonce) {
      params.set("nonce", nonce);
      this.nonce = nonce; // nonce 저장
    }
    if (pkce) {
      params.set("code_challenge", pkce.codeChallenge);
      params.set("code_challenge_method", pkce.codeChallengeMethod || "S256");
    }

    return `${this.server}/oauth2/authorize?${params.toString()}`;
  }

  /**
   * 토큰 교환
   *
   * Authorization Code를 사용하여 Access Token과 Refresh Token을 교환합니다.
   * 성공 시 토큰이 자동으로 저장되어 이후 요청에서 사용할 수 있습니다.
   *
   * @param code - 인증 후 받은 authorization code
   * @param codeVerifier - PKCE 코드 검증자 (PKCE를 사용한 경우 필수)
   * @returns 토큰 응답 객체 (access_token, refresh_token, expires_in 등)
   * @throws {OAuth2Error} 토큰 교환 실패 시 (잘못된 코드, 네트워크 에러 등)
   *
   * @example
   * ```typescript
   * try {
   *   const tokens = await client.exchangeCode('auth-code-from-callback');
   *   console.log('Access Token:', tokens.access_token);
   * } catch (error) {
   *   console.error('Token exchange failed:', error.message);
   * }
   * ```
   */
  async exchangeCode(code: string, codeVerifier?: string): Promise<TokenResponse> {
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.clientId,
      code: code,
      redirect_uri: this.redirectUri,
    });

    if (codeVerifier) params.set("code_verifier", codeVerifier);

    const response = await EnvironmentUtils.getFetch()(`${this.server}/oauth2/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${EnvironmentUtils.btoa(`${this.clientId}:${this.clientSecret}`)}`,
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new OAuth2Error(`Token exchange failed: ${response.status} ${response.statusText}`, response.status, errorData.error);
    }

    const tokenResponse: TokenResponse = await response.json();
    this.saveTokens(tokenResponse);
    return tokenResponse;
  }

  /**
   * 사용자 정보 조회
   *
   * Access Token을 사용하여 사용자 정보를 조회합니다.
   * 토큰이 제공되지 않으면 저장된 토큰을 자동으로 사용하며,
   * 토큰이 만료되었을 경우 자동으로 리프래시를 시도합니다.
   *
   * @param accessToken - 사용할 액세스 토큰 (선택적, 기본값: 저장된 토큰)
   * @returns 사용자 정보 객체 (sub, email, username 등)
   * @throws {OAuth2Error} 토큰이 없거나, API 요청 실패 시
   *
   * @example
   * ```typescript
   * // 저장된 토큰 사용
   * const userInfo = await client.getUserInfo();
   * console.log('User ID:', userInfo.sub);
   * console.log('Email:', userInfo.email);
   *
   * // 특정 토큰 사용
   * const userInfo2 = await client.getUserInfo('custom-access-token');
   * ```
   */
  async getUserInfo(accessToken?: string): Promise<UserInfo> {
    let token = accessToken || this.getStoredAccessToken();

    if (!token) {
      throw new OAuth2Error("No access token available");
    }

    // 자동 리프래시 시도
    await this.refreshTokenIfNeeded();
    token = this.getStoredAccessToken() || token;

    const response = await EnvironmentUtils.getFetch()(`${this.server}/oauth2/userinfo`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new OAuth2Error(`User info request failed: ${response.status} ${response.statusText}`, response.status, errorData.error);
    }

    return response.json();
  }

  /**
   * 토큰 리프래시
   *
   * Refresh Token을 사용하여 새로운 Access Token을 발급받습니다.
   * 성공 시 새로운 토큰이 자동으로 저장됩니다.
   *
   * @param refreshToken - 사용할 리프래시 토큰 (선택적, 기본값: 저장된 토큰)
   * @returns 새로운 토큰 응답 객체
   * @throws {OAuth2Error} 리프래시 토큰이 없거나, API 요청 실패 시
   *
   * @example
   * ```typescript
   * try {
   *   const newTokens = await client.refreshToken();
   *   console.log('New access token:', newTokens.access_token);
   * } catch (error) {
   *   console.error('Token refresh failed:', error.message);
   *   // 필요시 재인증
   * }
   * ```
   */
  async refreshToken(refreshToken?: string): Promise<TokenResponse> {
    const token = refreshToken || this.tokenData?.refresh_token;

    if (!token) {
      throw new OAuth2Error("No refresh token available");
    }

    const params = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: this.clientId,
      refresh_token: token,
    });

    const response = await EnvironmentUtils.getFetch()(`${this.server}/oauth2/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${EnvironmentUtils.btoa(`${this.clientId}:${this.clientSecret}`)}`,
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      this.clearStoredTokens();
      throw new OAuth2Error(`Token refresh failed: ${response.status} ${response.statusText}`, response.status, errorData.error);
    }

    const tokenResponse: TokenResponse = await response.json();
    this.saveTokens(tokenResponse);
    return tokenResponse;
  }

  /**
   * 저장된 토큰 로드
   */
  private loadStoredTokens(): void {
    if (!this.storage) return;

    try {
      const stored = this.storage.getItem(`flowauth_tokens_${this.clientId}`);
      if (stored) {
        this.tokenData = JSON.parse(stored);
        // 만료된 토큰 제거
        if (this.isTokenExpired()) {
          this.clearStoredTokens();
        }
      }
    } catch (error) {
      console.warn("Failed to load stored tokens:", error);
    }
  }

  /**
   * 토큰 저장
   */
  private saveTokens(tokenResponse: TokenResponse): void {
    if (!this.storage) return;

    const expiresAt = Date.now() + (tokenResponse.expires_in || 3600) * 1000;
    this.tokenData = {
      access_token: tokenResponse.access_token,
      refresh_token: tokenResponse.refresh_token,
      id_token: tokenResponse.id_token,
      token_type: tokenResponse.token_type,
      expires_at: expiresAt,
      scope: tokenResponse.scope,
    };

    // ID 토큰 별도 저장
    if (tokenResponse.id_token) {
      this.idToken = tokenResponse.id_token;
    }

    try {
      this.storage.setItem(`flowauth_tokens_${this.clientId}`, JSON.stringify(this.tokenData));
    } catch (error) {
      console.warn("Failed to save tokens:", error);
    }
  }

  /**
   * 저장된 토큰 제거
   */
  private clearStoredTokens(): void {
    if (!this.storage) return;

    this.storage.removeItem(`flowauth_tokens_${this.clientId}`);
    this.tokenData = undefined;
  }

  /**
   * 토큰 만료 확인
   */
  private isTokenExpired(): boolean {
    return !this.tokenData || Date.now() >= this.tokenData.expires_at;
  }

  /**
   * 자동 토큰 리프래시
   */
  private async refreshTokenIfNeeded(): Promise<void> {
    if (!this.autoRefresh || !this.tokenData?.refresh_token || !this.isTokenExpired()) {
      return;
    }

    if (this.refreshPromise) {
      // 이미 리프래시 중이면 기다림
      await this.refreshPromise;
      return;
    }

    this.refreshPromise = this.refreshToken(this.tokenData.refresh_token);
    try {
      const newTokens = await this.refreshPromise;
      this.saveTokens(newTokens);
    } catch (error) {
      console.error("Auto refresh failed:", error);
      this.clearStoredTokens();
      throw error;
    } finally {
      this.refreshPromise = undefined;
    }
  }

  /**
   * PKCE 코드 챌린지 생성
   *
   * Proof Key for Code Exchange (PKCE)를 위한 코드 검증자와 챌린지를 생성합니다.
   * 보안 강화를 위해 OAuth2 인증 시 사용을 권장합니다.
   *
   * @returns PKCE 코드 객체
   * @throws {Error} Crypto API를 사용할 수 없는 환경에서 발생
   *
   * @example
   * ```typescript
   * const pkce = await FlowAuthClient.generatePKCE();
   *
   * // 인증 URL 생성 시 PKCE 객체 사용
   * const authUrl = client.createAuthorizeUrl([OAuth2Scope.IDENTIFY], 'state', pkce);
   *
   * // 토큰 교환 시 codeVerifier 사용
   * const tokens = await client.exchangeCode('auth-code', pkce.codeVerifier);
   * ```
   */
  static async generatePKCE(): Promise<PKCECodes> {
    const crypto = EnvironmentUtils.getCrypto();
    if (!crypto) {
      throw new Error("Crypto API is not available. Please use a browser environment or Node.js 15+ with crypto support.");
    }

    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const codeVerifier = EnvironmentUtils.btoa(String.fromCharCode(...array)).replace(/[+/=]/g, (m) => ({ "+": "-", "/": "_", "=": "" }[m] || ""));
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const hash = await crypto.subtle.digest("SHA-256", data);
    const codeChallenge = EnvironmentUtils.btoa(String.fromCharCode(...new Uint8Array(hash))).replace(
      /[+/=]/g,
      (m) => ({ "+": "-", "/": "_", "=": "" }[m] || "")
    );
    return {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: "S256",
    };
  }

  /**
   * OAuth2 State 파라미터 생성
   *
   * CSRF 공격 방지를 위한 state 파라미터를 생성합니다.
   * OAuth2 인증 플로우에서 보안을 강화하기 위해 사용됩니다.
   *
   * @returns 랜덤하게 생성된 state 문자열
   * @throws {Error} Crypto API를 사용할 수 없는 환경에서 발생
   *
   * @example
   * ```typescript
   * const state = await FlowAuthClient.generateState();
   *
   * // 인증 URL 생성 시 state 사용
   * const authUrl = client.createAuthorizeUrl([OAuth2Scope.PROFILE], state);
   *
   * // 콜백에서 state 검증
   * if (receivedState !== state) {
   *   throw new Error('State mismatch - possible CSRF attack');
   * }
   * ```
   */
  static async generateState(): Promise<string> {
    const crypto = EnvironmentUtils.getCrypto();
    if (!crypto) {
      throw new Error("Crypto API is not available. Please use a browser environment or Node.js 15+ with crypto support.");
    }

    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const state = EnvironmentUtils.btoa(String.fromCharCode(...array)).replace(/[+/=]/g, (m) => ({ "+": "-", "/": "_", "=": "" }[m] || ""));
    return state;
  }

  /**
   * OIDC Nonce 파라미터 생성
   *
   * Replay Attack 방지를 위한 nonce 파라미터를 생성합니다.
   * OIDC 인증 플로우에서 ID 토큰의 무결성을 보장하기 위해 사용됩니다.
   *
   * @returns 랜덤하게 생성된 nonce 문자열
   * @throws {Error} Crypto API를 사용할 수 없는 환경에서 발생
   *
   * @example
   * ```typescript
   * const nonce = await FlowAuthClient.generateNonce();
   *
   * // OIDC 인증 URL 생성 시 nonce 사용
   * const authUrl = client.createOIDCAuthorizeUrl([OAuth2Scope.OPENID, OAuth2Scope.PROFILE], 'state', nonce);
   *
   * // ID 토큰 검증 시 nonce 검증
   * const payload = await client.validateIdToken(idToken, nonce);
   * ```
   */
  static async generateNonce(): Promise<string> {
    const crypto = EnvironmentUtils.getCrypto();
    if (!crypto) {
      throw new Error("Crypto API is not available. Please use a browser environment or Node.js 15+ with crypto support.");
    }

    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const nonce = EnvironmentUtils.btoa(String.fromCharCode(...array)).replace(/[+/=]/g, (m) => ({ "+": "-", "/": "_", "=": "" }[m] || ""));
    return nonce;
  }

  /**
   * PKCE와 State를 함께 생성
   *
   * 보안 강화를 위해 PKCE 코드와 State 파라미터를 함께 생성합니다.
   * OAuth2 인증 플로우에서 CSRF 방지와 코드 교환 공격 방지에 모두 사용됩니다.
   *
   * @returns PKCE 코드와 State를 포함한 객체
   * @throws {Error} Crypto API를 사용할 수 없는 환경에서 발생
   *
   * @example
   * ```typescript
   * const authParams = await FlowAuthClient.generateSecureAuthParams();
   *
   * // 인증 URL 생성
   * const authUrl = client.createAuthorizeUrl([OAuth2Scope.IDENTIFY], authParams.state, authParams.pkce);
   *
   * // 콜백에서 검증 및 토큰 교환
   * const tokens = await client.exchangeCode('auth-code', authParams.pkce.codeVerifier);
   * ```
   */
  static async generateSecureAuthParams(): Promise<{ pkce: PKCECodes; state: string }> {
    const [pkce, state] = await Promise.all([this.generatePKCE(), this.generateState()]);

    return {
      pkce: {
        codeVerifier: pkce.codeVerifier,
        codeChallenge: pkce.codeChallenge,
        codeChallengeMethod: "S256",
      },
      state,
    };
  }

  /**
   * PKCE를 사용한 보안 인증 URL 생성
   *
   * PKCE와 State를 자동으로 생성하여 보안이 강화된 인증 URL을 생성합니다.
   * 이 메소드를 사용하면 별도로 PKCE 코드를 관리할 필요가 없습니다.
   *
   * @param scopes - 요청할 권한 스코프 배열 (기본값: [OAuth2Scope.PROFILE])
   * @returns 인증 URL과 PKCE 코드 검증자를 포함한 객체
   * @throws {Error} Crypto API를 사용할 수 없는 환경에서 발생
   *
   * @example
   * ```typescript
   * const { authUrl, codeVerifier, state } = await client.createSecureAuthorizeUrl([OAuth2Scope.PROFILE, OAuth2Scope.EMAIL]);
   *
   * // 사용자를 인증 페이지로 리다이렉트
   * window.location.href = authUrl;
   *
   * // 콜백에서 토큰 교환 (codeVerifier와 state를 세션에 저장해두어야 함)
   * const tokens = await client.exchangeCode('auth-code', codeVerifier);
   * ```
   */
  async createSecureAuthorizeUrl(scopes: OAuth2Scope[] = [OAuth2Scope.PROFILE]): Promise<{ authUrl: string; codeVerifier: string; state: string }> {
    const authParams = await FlowAuthClient.generateSecureAuthParams();

    const authUrl = this.createAuthorizeUrl(scopes, authParams.state, authParams.pkce);

    return {
      authUrl,
      codeVerifier: authParams.pkce.codeVerifier,
      state: authParams.state,
    };
  }

  /**
   * 저장된 액세스 토큰 가져오기
   *
   * 브라우저 스토리지에 저장된 액세스 토큰을 반환합니다.
   * 토큰이 없거나 만료되었을 경우 null을 반환합니다.
   *
   * @returns 저장된 액세스 토큰 문자열 또는 null
   *
   * @example
   * ```typescript
   * const token = client.getStoredAccessToken();
   * if (token) {
   *   console.log('Stored token exists:', token.substring(0, 20) + '...');
   * } else {
   *   console.log('No stored token');
   * }
   * ```
   */
  getStoredAccessToken(): string | null {
    return this.tokenData?.access_token || null;
  }

  /**
   * 토큰 유효성 검증
   *
   * 액세스 토큰의 유효성을 서버에 확인하여 검증합니다.
   * 토큰이 제공되지 않으면 저장된 토큰을 사용합니다.
   *
   * @param accessToken - 검증할 액세스 토큰 (선택적)
   * @returns 토큰이 유효하면 true, 그렇지 않으면 false
   *
   * @example
   * ```typescript
   * const isValid = await client.validateToken();
   * if (!isValid) {
   *   console.log('Token is invalid, need re-authentication');
   * }
   * ```
   */
  async validateToken(accessToken?: string): Promise<boolean> {
    const token = accessToken || this.getStoredAccessToken();
    if (!token) return false;

    try {
      const response = await EnvironmentUtils.getFetch()(`${this.server}/oauth2/userinfo`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * 로그아웃 (토큰 제거)
   *
   * 저장된 모든 토큰을 제거하고 클라이언트를 초기화합니다.
   * 이후 API 요청 시 새로운 인증이 필요합니다.
   *
   * @example
   * ```typescript
   * client.logout();
   * console.log('Logged out successfully');
   * ```
   */
  logout(): void {
    this.clearStoredTokens();
  }

  /**
   * 현재 토큰 정보 가져오기
   *
   * 저장된 토큰의 상세 정보를 반환합니다.
   * 토큰 만료 시간, 스코프 등의 정보를 확인할 수 있습니다.
   *
   * @returns 토큰 정보 객체 또는 null (토큰이 없을 경우)
   *
   * @example
   * ```typescript
   * const tokenInfo = client.getTokenInfo();
   * if (tokenInfo) {
   *   console.log('Token expires at:', new Date(tokenInfo.expires_at));
   *   console.log('Token scopes:', tokenInfo.scope);
   * }
   * ```
   */
  getTokenInfo(): TokenStorage | null {
    return this.tokenData || null;
  }

  /**
   * OIDC Discovery 문서 가져오기
   *
   * 서버의 OIDC Discovery 문서를 가져와서 캐시합니다.
   * Discovery 문서에는 인증 엔드포인트, JWKS URI 등의 정보가 포함됩니다.
   *
   * @returns OIDC Discovery 문서
   *
   * @example
   * ```typescript
   * const discovery = await client.getDiscoveryDocument();
   * console.log('Authorization endpoint:', discovery.authorization_endpoint);
   * console.log('JWKS URI:', discovery.jwks_uri);
   * ```
   */
  async getDiscoveryDocument(): Promise<OIDCDiscoveryDocument> {
    if (this.discoveryDocument) {
      return this.discoveryDocument;
    }

    this.discoveryDocument = await OIDCUtils.getDiscoveryDocument(this.server);
    return this.discoveryDocument;
  }

  /**
   * ID 토큰 검증 및 파싱
   *
   * RSA 서명 검증을 포함하여 ID 토큰을 검증하고 페이로드를 반환합니다.
   * 저장된 ID 토큰을 사용하거나 직접 토큰을 제공할 수 있습니다.
   *
   * @param idToken - 검증할 ID 토큰 (선택적, 기본값: 저장된 토큰)
   * @param expectedNonce - 예상 nonce 값 (선택적)
   * @returns 검증된 ID 토큰 페이로드
   * @throws {Error} 토큰 검증 실패 시
   *
   * @example
   * ```typescript
   * try {
   *   const payload = await client.validateIdToken();
   *   console.log('User ID:', payload.sub);
   *   console.log('Email:', payload.email);
   * } catch (error) {
   *   console.error('ID token validation failed:', error.message);
   * }
   * ```
   */
  async validateIdToken(idToken?: string, expectedNonce?: string): Promise<IdTokenPayload> {
    const token = idToken || this.idToken;
    if (!token) {
      throw new Error("No ID token available");
    }

    const discovery = await this.getDiscoveryDocument();
    if (!discovery.jwks_uri) {
      throw new Error("JWKS URI not found in discovery document");
    }

    return await OIDCUtils.validateAndParseIdTokenWithRsa(token, discovery.jwks_uri, this.server, this.clientId, expectedNonce || this.nonce);
  }

  /**
   * 저장된 ID 토큰 가져오기
   *
   * 저장된 ID 토큰을 반환합니다.
   *
   * @returns 저장된 ID 토큰 문자열 또는 null
   *
   * @example
   * ```typescript
   * const idToken = client.getStoredIdToken();
   * if (idToken) {
   *   console.log('ID Token:', idToken.substring(0, 50) + '...');
   * }
   * ```
   */
  getStoredIdToken(): string | null {
    return this.idToken || null;
  }

  /**
   * OIDC 인증 URL 생성 (ID 토큰 포함)
   *
   * OpenID Connect를 위한 인증 URL을 생성합니다.
   * ID 토큰이 포함된 응답을 받을 수 있습니다.
   *
   * @param scopes - 요청할 권한 스코프 배열 (openid 스코프 포함 권장)
   * @param state - CSRF 방지를 위한 상태값
   * @param nonce - Replay Attack 방지를 위한 nonce 값
   * @param pkce - PKCE 코드 챌린지
   * @returns 완성된 OIDC 인증 URL
   *
   * @example
   * ```typescript
   * const nonce = await FlowAuthClient.generateNonce();
   * const authUrl = client.createOIDCAuthorizeUrl(
   *   [OAuth2Scope.OPENID, OAuth2Scope.PROFILE, OAuth2Scope.EMAIL],
   *   'random-state',
   *   nonce
   * );
   * window.location.href = authUrl;
   * ```
   */
  createOIDCAuthorizeUrl(
    scopes: OAuth2Scope[] = [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
    state?: string,
    nonce?: string,
    pkce?: PKCECodes
  ): string {
    // openid 스코프가 포함되어 있지 않으면 추가
    if (!scopes.includes(OAuth2Scope.OPENID)) {
      scopes = [OAuth2Scope.OPENID, ...scopes];
    }

    return this.createAuthorizeUrl(scopes, state, pkce, nonce);
  }

  /**
   * OIDC 보안 인증 URL 생성 (Hybrid Flow)
   *
   * PKCE, State, Nonce를 자동으로 생성하여 OIDC Hybrid Flow 인증 URL을 생성합니다.
   * Hybrid Flow는 Authorization Code와 ID Token을 동시에 받아서 보안성과 사용자 경험을 모두 제공합니다.
   *
   * @param scopes - 요청할 권한 스코프 배열 (openid 스코프 포함 권장)
   * @returns 인증 URL과 보안 파라미터들을 포함한 객체
   * @throws {Error} Crypto API를 사용할 수 없는 환경에서 발생
   *
   * @example
   * ```typescript
   * const { authUrl, codeVerifier, state, nonce } = await client.createSecureOIDCAuthorizeUrl([
   *   OAuth2Scope.OPENID,
   *   OAuth2Scope.PROFILE,
   *   OAuth2Scope.EMAIL
   * ]);
   *
   * // 사용자를 인증 페이지로 리다이렉트
   * window.location.href = authUrl;
   *
   * // 콜백에서 검증에 사용할 파라미터들 저장
   * sessionStorage.setItem('oauth_state', state);
   * sessionStorage.setItem('oauth_nonce', nonce);
   * sessionStorage.setItem('oauth_code_verifier', codeVerifier);
   *
   * // 콜백 페이지에서:
   * const tokens = await client.handleHybridCallback(
   *   window.location.href,
   *   sessionStorage.getItem('oauth_state'),
   *   sessionStorage.getItem('oauth_nonce'),
   *   sessionStorage.getItem('oauth_code_verifier')
   * );
   * ```
   */
  async createSecureOIDCAuthorizeUrl(
    scopes: OAuth2Scope[] = [OAuth2Scope.OPENID, OAuth2Scope.PROFILE]
  ): Promise<{ authUrl: string; codeVerifier: string; state: string; nonce: string }> {
    const [pkce, state] = await Promise.all([FlowAuthClient.generatePKCE(), FlowAuthClient.generateState()]);

    const nonce = await FlowAuthClient.generateNonce();

    const authUrl = this.createOIDCAuthorizeUrl(scopes, state, nonce, pkce);

    return {
      authUrl,
      codeVerifier: pkce.codeVerifier,
      state,
      nonce,
    };
  }

  /**
   * 콜백 URL 파싱 유틸리티
   *
   * OAuth2 콜백 URL에서 파라미터들을 파싱합니다.
   * Authorization Code Grant, Implicit Grant, Hybrid Flow 모두 지원합니다.
   *
   * @param callbackUrl - 콜백 URL (전체 URL 또는 query string + hash)
   * @returns 파싱된 콜백 파라미터들
   *
   * @example
   * ```typescript
   * // 전체 URL에서 파싱
   * const params = client.parseCallbackUrl('https://app.com/callback?code=abc&state=xyz#id_token=token');
   * console.log(params.code); // 'abc'
   * console.log(params.idToken); // 'token'
   *
   * // 현재 페이지 URL에서 파싱
   * const params = client.parseCallbackUrl(window.location.href);
   * ```
   */
  parseCallbackUrl(callbackUrl: string): {
    code?: string;
    state?: string;
    idToken?: string;
    accessToken?: string;
    tokenType?: string;
    expiresIn?: number;
    error?: string;
    errorDescription?: string;
  } {
    const url = new URL(callbackUrl);

    // Query parameters 파싱
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const error = url.searchParams.get("error");
    const errorDescription = url.searchParams.get("error_description");

    // Fragment parameters 파싱 (수정됨)
    const hash = url.hash.substring(1); // # 제거
    if (hash) {
      const hashParams = new URLSearchParams(hash);
      const idToken = hashParams.get("id_token");
      const accessToken = hashParams.get("access_token");
      const tokenType = hashParams.get("token_type");
      const expiresIn = hashParams.get("expires_in");
      const fragmentState = hashParams.get("state"); // fragment에서도 state 파싱

      // state는 query나 fragment 중 하나만 사용 (query 우선)
      const finalState = state || fragmentState;

      return {
        code: code || undefined,
        state: finalState || undefined,
        idToken: idToken || undefined,
        accessToken: accessToken || undefined,
        tokenType: tokenType || undefined,
        expiresIn: expiresIn ? parseInt(expiresIn) : undefined,
        error: error || undefined,
        errorDescription: errorDescription || undefined,
      };
    }

    return {
      code: code || undefined,
      state: state || undefined,
      idToken: undefined,
      accessToken: undefined,
      tokenType: undefined,
      expiresIn: undefined,
      error: error || undefined,
      errorDescription: errorDescription || undefined,
    };
  }

  /**
   * Hybrid Flow 콜백 처리
   *
   * Hybrid Flow (code id_token) 콜백을 처리합니다.
   * URL에서 code와 id_token을 추출하여 검증하고 토큰을 교환합니다.
   *
   * @param callbackUrl - 콜백 URL
   * @param expectedState - 예상 state 값 (CSRF 방지)
   * @param expectedNonce - 예상 nonce 값 (replay attack 방지)
   * @param codeVerifier - PKCE 코드 검증자
   * @returns 토큰 응답 객체
   * @throws {OAuth2Error} 콜백 처리 실패 시
   *
   * @example
   * ```typescript
   * try {
   *   // 콜백 URL에서 파라미터 추출 및 검증
   *   const tokens = await client.handleHybridCallback(
   *     window.location.href,
   *     sessionStorage.getItem('oauth_state'),
   *     sessionStorage.getItem('oauth_nonce'),
   *     sessionStorage.getItem('oauth_code_verifier')
   *   );
   *
   *   console.log('Access Token:', tokens.access_token);
   *   console.log('ID Token:', tokens.id_token);
   * } catch (error) {
   *   console.error('Hybrid callback failed:', error.message);
   * }
   * ```
   */
  async handleHybridCallback(callbackUrl: string, expectedState?: string, expectedNonce?: string, codeVerifier?: string): Promise<TokenResponse> {
    const params = this.parseCallbackUrl(callbackUrl);

    // 에러 처리
    if (params.error) {
      throw new OAuth2Error(
        `OAuth2 callback error: ${params.error}${params.errorDescription ? ` - ${params.errorDescription}` : ""}`,
        undefined,
        params.error
      );
    }

    // State 검증
    if (expectedState && params.state !== expectedState) {
      throw new OAuth2Error("State mismatch - possible CSRF attack");
    }

    // ID token 검증 및 저장
    if (params.idToken) {
      try {
        await this.validateIdToken(params.idToken, expectedNonce);
        this.idToken = params.idToken;
      } catch (error) {
        console.warn("ID token validation failed:", error);
        // ID token 검증 실패해도 계속 진행 (선택적)
      }
    }

    // Authorization code가 있으면 토큰 교환
    if (params.code) {
      return await this.exchangeCode(params.code, codeVerifier);
    }

    // Implicit tokens가 있는 경우 (fallback)
    if (params.accessToken) {
      const tokenResponse: TokenResponse = {
        access_token: params.accessToken,
        token_type: params.tokenType || "Bearer",
        expires_in: params.expiresIn || 3600,
        id_token: params.idToken,
      };

      this.saveTokens(tokenResponse);
      return tokenResponse;
    }

    throw new OAuth2Error("No authorization code or access token found in callback");
  }
}
