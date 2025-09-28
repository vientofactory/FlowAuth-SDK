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
  /** 계정의 기본 정보 읽기 (사용자 ID, 이름 등) */
  IDENTIFY = "identify",
  /** 사용자 이메일 주소 읽기 */
  EMAIL = "email",
}

/**
 * 기본 스코프 목록
 * 새로운 클라이언트에 기본적으로 부여되는 스코프들입니다.
 */
export const DEFAULT_SCOPES: OAuth2Scope[] = [OAuth2Scope.IDENTIFY];

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
}

/**
 * OAuth2 토큰 응답 인터페이스
 */
interface TokenResponse {
  /** 액세스 토큰 */
  access_token: string;
  /** 리프래시 토큰 (선택적) */
  refresh_token?: string;
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
 * const authUrl = client.createAuthorizeUrl([OAuth2Scope.IDENTIFY]);
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
   * @param scopes - 요청할 권한 스코프 배열 (기본값: [OAuth2Scope.READ_USER])
   * @param state - CSRF 방지를 위한 상태값 (권장)
   * @param pkce - PKCE 코드 챌린지 (보안 강화용, 권장)
   * @returns 완성된 인증 URL
   *
   * @example
   * ```typescript
   * // 기본 사용
   * const authUrl = client.createAuthorizeUrl([OAuth2Scope.READ_USER, OAuth2Scope.EMAIL], 'random-state-123');
   * window.location.href = authUrl;
   *
   * // PKCE와 함께 사용
   * const pkce = await FlowAuthClient.generatePKCE();
   * const authUrl = client.createAuthorizeUrl([OAuth2Scope.READ_USER], 'state', pkce);
   * // pkce.codeVerifier를 안전하게 저장하여 토큰 교환 시 사용
   * ```
   */
  createAuthorizeUrl(scopes: OAuth2Scope[] = [OAuth2Scope.IDENTIFY], state?: string, pkce?: PKCECodes): string {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: scopes.join(" "),
    });

    if (state) params.set("state", state);
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
      token_type: tokenResponse.token_type,
      expires_at: expiresAt,
      scope: tokenResponse.scope,
    };

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
   * const authUrl = client.createAuthorizeUrl([OAuth2Scope.IDENTIFY], state);
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
   * @param scopes - 요청할 권한 스코프 배열 (기본값: [OAuth2Scope.READ_USER])
   * @returns 인증 URL과 PKCE 코드 검증자를 포함한 객체
   * @throws {Error} Crypto API를 사용할 수 없는 환경에서 발생
   *
   * @example
   * ```typescript
   * const { authUrl, codeVerifier, state } = await client.createSecureAuthorizeUrl([OAuth2Scope.READ_USER, OAuth2Scope.EMAIL]);
   *
   * // 사용자를 인증 페이지로 리다이렉트
   * window.location.href = authUrl;
   *
   * // 콜백에서 토큰 교환 (codeVerifier와 state를 세션에 저장해두어야 함)
   * const tokens = await client.exchangeCode('auth-code', codeVerifier);
   * ```
   */
  async createSecureAuthorizeUrl(scopes: OAuth2Scope[] = [OAuth2Scope.IDENTIFY]): Promise<{ authUrl: string; codeVerifier: string; state: string }> {
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
}
