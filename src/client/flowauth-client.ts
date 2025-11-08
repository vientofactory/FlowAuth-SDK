import {
  OAuth2ClientConfig,
  OIDCDiscoveryDocument,
  PKCECodes,
  IdTokenPayload,
  TokenStorage,
  OAuth2CallbackParams,
} from "../types/oauth2";
import { TokenResponse, UserInfo, TokenData } from "../types/token";
import { OAuth2Error } from "../errors/oauth2";
import { EnvironmentUtils } from "../utils/environment";
import { getDefaultStorage } from "../utils/storage";
import { OIDCUtils } from "../utils/oidc";
import {
  OAuth2Scope,
  OAuth2ResponseType,
  OAUTH2_CONSTANTS,
} from "../constants/oauth2";

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
  private storage?: TokenStorage;
  /** 자동 토큰 리프래시 활성화 여부 */
  private autoRefresh: boolean;
  /** 저장된 토큰 데이터 */
  private tokenData?: TokenData;
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
    this.storage = config.storage || getDefaultStorage();
    this.autoRefresh = config.autoRefresh !== false;

    if (
      !this.clientId ||
      !this.clientSecret ||
      !this.redirectUri ||
      !this.server
    ) {
      throw new Error(
        "All parameters (server, clientId, clientSecret, redirectUri) are required.",
      );
    }

    // Load stored tokens
    this.loadStoredTokens();
  }

  /**
   * 인증 URL 생성 (기본 - Authorization Code Grant)
   *
   * 사용자를 FlowAuth 인증 페이지로 리다이렉트하기 위한 URL을 생성합니다.
   * 생성된 URL로 사용자를 이동시키면 OAuth2 인증 플로우가 시작됩니다.
   *
   * @param scopes - 요청할 권한 스코프 배열 (기본값: [OAuth2Scope.PROFILE])
   * @param state - CSRF 방지를 위한 상태값 (권장)
   * @param pkce - PKCE 코드 챌린지 (보안 강화용, 권장)
   * @param nonce - OIDC nonce 값 (openid 스코프 사용 시 필수)
   * @param responseType - OAuth2 응답 타입 (기본값: 'code', OIDC 스코프 포함 시 'code id_token')
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
   * // 명시적 response type 지정
   * const authUrl = client.createAuthorizeUrl([OAuth2Scope.PROFILE], 'state', undefined, undefined, 'token');
   *
   * // PKCE와 함께 사용
   * const pkce = await FlowAuthClient.generatePKCE();
   * const authUrl = client.createAuthorizeUrl([OAuth2Scope.PROFILE], 'state', pkce);
   * // pkce.codeVerifier를 안전하게 저장하여 토큰 교환 시 사용
   * ```
   */
  createAuthorizeUrl(
    scopes: OAuth2Scope[] = [OAuth2Scope.PROFILE],
    state?: string,
    pkce?: PKCECodes,
    nonce?: string,
    responseType?: OAuth2ResponseType,
  ): string {
    // responseType이 명시적으로 지정되지 않은 경우
    if (!responseType) {
      // OIDC를 사용하는 경우 response_type에 id_token 포함
      const hasOpenId = scopes.includes(OAuth2Scope.OPENID);
      responseType = hasOpenId
        ? OAUTH2_CONSTANTS.RESPONSE_TYPES.CODE_ID_TOKEN
        : OAUTH2_CONSTANTS.RESPONSE_TYPES.CODE;
    }

    return this.createAuthorizeUrlWithResponseType(
      responseType,
      scopes,
      state,
      pkce,
      nonce,
    );
  }

  /**
   * 특정 response_type으로 인증 URL 생성
   *
   * @param responseType - OAuth2 응답 타입
   * @param scopes - 요청할 권한 스코프 배열
   * @param state - CSRF 방지를 위한 상태값
   * @param pkce - PKCE 코드 챌린지
   * @param nonce - OIDC nonce 값
   * @returns 완성된 인증 URL
   *
   * @example
   * ```typescript
   * // Implicit Grant (Access Token만)
   * const authUrl = client.createAuthorizeUrlWithResponseType('token', [OAuth2Scope.PROFILE], 'state123');
   *
   * // Implicit Grant (ID Token만)
   * const authUrl = client.createAuthorizeUrlWithResponseType('id_token', [OAuth2Scope.OPENID], 'state123', undefined, 'nonce123');
   *
   * // Hybrid Flow
   * const authUrl = client.createAuthorizeUrlWithResponseType('code id_token', [OAuth2Scope.OPENID, OAuth2Scope.PROFILE], 'state123');
   * ```
   */
  createAuthorizeUrlWithResponseType(
    responseType: OAuth2ResponseType,
    scopes: OAuth2Scope[] = [OAuth2Scope.PROFILE],
    state?: string,
    pkce?: PKCECodes,
    nonce?: string,
  ): string {
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
  async exchangeCode(
    code: string,
    codeVerifier?: string,
  ): Promise<TokenResponse> {
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.clientId,
      code,
      redirect_uri: this.redirectUri,
    });

    if (codeVerifier) params.set("code_verifier", codeVerifier);

    const response = await EnvironmentUtils.getFetch()(
      `${this.server}/oauth2/token`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${EnvironmentUtils.btoa(`${this.clientId}:${this.clientSecret}`)}`,
        },
        body: params.toString(),
      },
    );

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new OAuth2Error(
        `Token exchange failed: ${response.status} ${response.statusText}`,
        response.status,
        errorData.error,
      );
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

    const response = await EnvironmentUtils.getFetch()(
      `${this.server}/oauth2/userinfo`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      },
    );

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new OAuth2Error(
        `User info request failed: ${response.status} ${response.statusText}`,
        response.status,
        errorData.error,
      );
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

    const response = await EnvironmentUtils.getFetch()(
      `${this.server}/oauth2/token`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${EnvironmentUtils.btoa(`${this.clientId}:${this.clientSecret}`)}`,
        },
        body: params.toString(),
      },
    );

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      this.clearStoredTokens();
      throw new OAuth2Error(
        `Token refresh failed: ${response.status} ${response.statusText}`,
        response.status,
        errorData.error,
      );
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
    } catch {
      // Silently handle storage errors during initialization
      // This prevents client creation from failing due to storage issues
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
      this.storage.setItem(
        `flowauth_tokens_${this.clientId}`,
        JSON.stringify(this.tokenData),
      );
    } catch {
      // Silently handle storage errors during token saving
      // This prevents token saving from failing due to storage issues
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
    return (
      !this.tokenData ||
      !this.tokenData.expires_at ||
      Date.now() >= this.tokenData.expires_at
    );
  }

  /**
   * 자동 토큰 리프래시
   */
  private async refreshTokenIfNeeded(): Promise<void> {
    if (
      !this.autoRefresh ||
      !this.tokenData?.refresh_token ||
      !this.isTokenExpired()
    ) {
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
      // Clear tokens on refresh failure and re-throw
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
      throw new Error(
        "Crypto API is not available. Please use a browser environment or Node.js 15+ with crypto support.",
      );
    }

    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const codeVerifier = EnvironmentUtils.btoa(
      String.fromCharCode(...array),
    ).replace(
      /[+/=]/g,
      (m: string) => ({ "+": "-", "/": "_", "=": "" })[m] || "",
    );
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const hash = await crypto.subtle.digest("SHA-256", data);
    const codeChallenge = EnvironmentUtils.btoa(
      String.fromCharCode(...new Uint8Array(hash)),
    ).replace(
      /[+/=]/g,
      (m: string) => ({ "+": "-", "/": "_", "=": "" })[m] || "",
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
      throw new Error(
        "Crypto API is not available. Please use a browser environment or Node.js 15+ with crypto support.",
      );
    }

    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const state = EnvironmentUtils.btoa(String.fromCharCode(...array)).replace(
      /[+/=]/g,
      (m: string) => ({ "+": "-", "/": "_", "=": "" })[m] || "",
    );
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
      throw new Error(
        "Crypto API is not available. Please use a browser environment or Node.js 15+ with crypto support.",
      );
    }

    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const nonce = EnvironmentUtils.btoa(String.fromCharCode(...array)).replace(
      /[+/=]/g,
      (m: string) => ({ "+": "-", "/": "_", "=": "" })[m] || "",
    );
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
  static async generateSecureAuthParams(): Promise<{
    pkce: PKCECodes;
    state: string;
  }> {
    const [pkce, state] = await Promise.all([
      this.generatePKCE(),
      this.generateState(),
    ]);

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
   * @param responseType - OAuth2 응답 타입 (기본값: 'code', OIDC 스코프 포함 시 'code id_token')
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
   * // 명시적 response type 지정
   * const { authUrl, codeVerifier, state } = await client.createSecureAuthorizeUrl([OAuth2Scope.PROFILE], 'token');
   *
   * // 콜백에서 토큰 교환 (codeVerifier와 state를 세션에 저장해두어야 함)
   * const tokens = await client.exchangeCode('auth-code', codeVerifier);
   * ```
   */
  async createSecureAuthorizeUrl(
    scopes: OAuth2Scope[] = [OAuth2Scope.PROFILE],
    responseType?: OAuth2ResponseType,
  ): Promise<{ authUrl: string; codeVerifier: string; state: string }> {
    const authParams = await FlowAuthClient.generateSecureAuthParams();

    const authUrl = this.createAuthorizeUrl(
      scopes,
      authParams.state,
      authParams.pkce,
      undefined,
      responseType,
    );

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
      const response = await EnvironmentUtils.getFetch()(
        `${this.server}/oauth2/userinfo`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        },
      );
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
  getTokenInfo(): TokenData | null {
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
    return this.discoveryDocument!;
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
  async validateIdToken(
    idToken?: string,
    expectedNonce?: string,
  ): Promise<IdTokenPayload> {
    const token = idToken || this.idToken;
    if (!token) {
      throw new Error("No ID token available");
    }

    const discovery = await this.getDiscoveryDocument();
    if (!discovery.jwks_uri) {
      throw new Error("JWKS URI not found in discovery document");
    }

    return await OIDCUtils.validateAndParseIdTokenWithRsa(
      token,
      discovery.jwks_uri,
      discovery.issuer,
      this.clientId,
      expectedNonce || this.nonce,
    );
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
   * Implicit Grant URL 생성 (Access Token only)
   *
   * Access Token만 받는 Implicit Grant 인증 URL을 생성합니다.
   * 클라이언트 시크릿을 안전하게 저장할 수 없는 환경에 적합합니다.
   *
   * @deprecated 대신 createAuthorizeUrl(scopes, state, undefined, undefined, 'token')을 사용하세요
   * @param scopes - 요청할 권한 스코프 배열
   * @param state - CSRF 방지를 위한 상태값
   * @returns 완성된 Implicit Grant 인증 URL
   *
   * @example
   * ```typescript
   * // Deprecated 방식
   * const authUrl = client.createImplicitGrantUrl([OAuth2Scope.PROFILE], 'random-state');
   *
   * // 권장 방식
   * const authUrl = client.createAuthorizeUrl([OAuth2Scope.PROFILE], 'random-state', undefined, undefined, 'token');
   * window.location.href = authUrl;
   * ```
   */
  createImplicitGrantUrl(
    scopes: OAuth2Scope[] = [OAuth2Scope.PROFILE],
    state?: string,
  ): string {
    return this.createAuthorizeUrl(
      scopes,
      state,
      undefined,
      undefined,
      OAuth2ResponseType.TOKEN,
    );
  }

  /**
   * OIDC Implicit Grant URL 생성 (ID Token only)
   *
   * ID Token만 받는 OIDC Implicit Grant 인증 URL을 생성합니다.
   * 인증 정보만 필요하고 리소스 접근이 불필요한 경우에 적합합니다.
   *
   * @deprecated 대신 createAuthorizeUrl 또는 createOIDCAuthorizeUrl에서 responseType을 'id_token'으로 지정하세요
   * @param scopes - 요청할 권한 스코프 배열 (openid 스코프 포함 권장)
   * @param state - CSRF 방지를 위한 상태값
   * @param nonce - Replay Attack 방지를 위한 nonce 값 (필수)
   * @returns 완성된 OIDC Implicit Grant 인증 URL
   *
   * @example
   * ```typescript
   * const nonce = await FlowAuthClient.generateNonce();
   *
   * // Deprecated 방식
   * const authUrl = client.createOIDCImplicitUrl([OAuth2Scope.OPENID], 'state', nonce);
   *
   * // 권장 방식
   * const authUrl = client.createOIDCAuthorizeUrl([OAuth2Scope.OPENID], 'state', nonce, undefined, 'id_token');
   * window.location.href = authUrl;
   * ```
   */
  createOIDCImplicitUrl(
    scopes: OAuth2Scope[] = [OAuth2Scope.OPENID],
    state?: string,
    nonce?: string,
  ): string {
    return this.createOIDCAuthorizeUrl(
      scopes,
      state,
      nonce,
      undefined,
      OAuth2ResponseType.ID_TOKEN,
    );
  }

  /**
   * OIDC Implicit Grant URL 생성 (Access Token + ID Token)
   *
   * Access Token과 ID Token을 동시에 받는 OIDC Implicit Grant 인증 URL을 생성합니다.
   * 리소스 접근과 인증 정보가 모두 필요한 SPA에 적합합니다.
   *
   * @deprecated 대신 createOIDCAuthorizeUrl에서 responseType을 'token id_token'으로 지정하세요
   * @param scopes - 요청할 권한 스코프 배열 (openid 스코프 포함 권장)
   * @param state - CSRF 방지를 위한 상태값
   * @param nonce - Replay Attack 방지를 위한 nonce 값 (필수)
   * @returns 완성된 OIDC Implicit Grant 인증 URL
   *
   * @example
   * ```typescript
   * const nonce = await FlowAuthClient.generateNonce();
   *
   * // Deprecated 방식
   * const authUrl = client.createOIDCImplicitTokenUrl([OAuth2Scope.OPENID, OAuth2Scope.PROFILE], 'state', nonce);
   *
   * // 권장 방식
   * const authUrl = client.createOIDCAuthorizeUrl(
   *   [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
   *   'state',
   *   nonce,
   *   undefined,
   *   'token id_token'
   * );
   * window.location.href = authUrl;
   * ```
   */
  createOIDCImplicitTokenUrl(
    scopes: OAuth2Scope[] = [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
    state?: string,
    nonce?: string,
  ): string {
    return this.createOIDCAuthorizeUrl(
      scopes,
      state,
      nonce,
      undefined,
      OAuth2ResponseType.TOKEN_ID_TOKEN,
    );
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
   * @param responseType - OAuth2 응답 타입 (기본값: 'code id_token')
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
   *
   * // 명시적 response type 지정
   * const authUrl = client.createOIDCAuthorizeUrl(
   *   [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
   *   'state',
   *   nonce,
   *   undefined,
   *   'id_token'
   * );
   * ```
   */
  createOIDCAuthorizeUrl(
    scopes: OAuth2Scope[] = [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
    state?: string,
    nonce?: string,
    pkce?: PKCECodes,
    responseType?: OAuth2ResponseType,
  ): string {
    // openid 스코프가 포함되어 있지 않으면 추가
    if (!scopes.includes(OAuth2Scope.OPENID)) {
      scopes = [OAuth2Scope.OPENID, ...scopes];
    }

    // responseType이 지정되지 않은 경우 OIDC 기본값 사용
    const finalResponseType =
      responseType || OAUTH2_CONSTANTS.RESPONSE_TYPES.CODE_ID_TOKEN;

    return this.createAuthorizeUrl(
      scopes,
      state,
      pkce,
      nonce,
      finalResponseType,
    );
  }

  /**
   * OIDC 보안 인증 URL 생성 (Hybrid Flow)
   *
   * PKCE, State, Nonce를 자동으로 생성하여 OIDC Hybrid Flow 인증 URL을 생성합니다.
   * Hybrid Flow는 Authorization Code와 ID Token을 동시에 받아서 보안성과 사용자 경험을 모두 제공합니다.
   *
   * @param scopes - 요청할 권한 스코프 배열 (openid 스코프 포함 권장)
   * @param responseType - OAuth2 응답 타입 (기본값: 'code id_token')
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
   * // 명시적 response type 지정
   * const { authUrl, codeVerifier, state, nonce } = await client.createSecureOIDCAuthorizeUrl(
   *   [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
   *   'id_token'
   * );
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
    scopes: OAuth2Scope[] = [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
    responseType?: OAuth2ResponseType,
  ): Promise<{
    authUrl: string;
    codeVerifier: string;
    state: string;
    nonce: string;
  }> {
    const [pkce, state] = await Promise.all([
      FlowAuthClient.generatePKCE(),
      FlowAuthClient.generateState(),
    ]);

    const nonce = await FlowAuthClient.generateNonce();

    const authUrl = this.createOIDCAuthorizeUrl(
      scopes,
      state,
      nonce,
      pkce,
      responseType,
    );

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
  parseCallbackUrl(callbackUrl: string): OAuth2CallbackParams {
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
  async handleHybridCallback(
    callbackUrl: string,
    expectedState?: string,
    expectedNonce?: string,
    codeVerifier?: string,
  ): Promise<TokenResponse> {
    const params = this.parseCallbackUrl(callbackUrl);

    // 에러 처리
    if (params.error) {
      throw new OAuth2Error(
        `OAuth2 callback error: ${params.error}${params.errorDescription ? ` - ${params.errorDescription}` : ""}`,
        undefined,
        params.error,
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
      } catch {
        // ID token 검증 실패해도 계속 진행 (선택적)
        // Silently handle ID token validation errors
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

    throw new OAuth2Error(
      "No authorization code or access token found in callback",
    );
  }
}
