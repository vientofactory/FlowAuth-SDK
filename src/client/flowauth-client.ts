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
import { OAuth2Scope, OAuth2ResponseType } from "../constants/oauth2";

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
   * 인증 URL 생성
   *
   * 사용자를 FlowAuth 인증 페이지로 리다이렉트하기 위한 URL을 생성합니다.
   * 스코프에 따라 자동으로 적절한 responseType을 결정하거나 명시적으로 지정할 수 있습니다.
   *
   * @param scopes - 요청할 권한 스코프 배열 (기본값: [OAuth2Scope.PROFILE])
   * @param options - 선택적 매개변수들
   * @param options.state - CSRF 방지를 위한 상태값 (권장)
   * @param options.pkce - PKCE 코드 챌린지 (보안 강화용, 권장)
   * @param options.nonce - OIDC nonce 값 (openid 스코프 사용 시 자동 생성 또는 직접 제공)
   * @param options.responseType - OAuth2 응답 타입 (미지정시 스코프에 따라 자동 결정)
   * @returns 완성된 인증 URL
   *
   * @example
   * ```typescript
   * // 기본 사용 (Authorization Code Grant)
   * const authUrl = client.createAuthorizeUrl([OAuth2Scope.PROFILE, OAuth2Scope.EMAIL], {
   *   state: 'random-state-123'
   * });
   *
   * // OIDC 사용 (자동으로 'code id_token' responseType 사용)
   * const authUrl = client.createAuthorizeUrl([OAuth2Scope.OPENID, OAuth2Scope.PROFILE], {
   *   state: 'state-123',
   *   nonce: await FlowAuthClient.generateNonce()
   * });
   *
   * // Implicit Grant (명시적 responseType 지정)
   * // 제거됨: 보안상의 이유로 Implicit Grant는 더 이상 지원되지 않습니다.
   * ```
   */
  createAuthorizeUrl(
    scopes: OAuth2Scope[] = [OAuth2Scope.PROFILE],
    options?: {
      state?: string;
      pkce?: PKCECodes;
      nonce?: string;
      responseType?: OAuth2ResponseType;
    },
  ): string {
    const { state, pkce, nonce, responseType } = options || {};

    return this.createAuthorizeUrlWithResponseType(
      responseType || OAuth2ResponseType.CODE,
      scopes,
      state,
      pkce,
      nonce,
    );
  }

  /**
   * 특정 responseType으로 인증 URL 생성
   * @internal 일반적으로 createAuthorizeUrl을 사용하는 것이 권장됩니다.
   */
  createAuthorizeUrlWithResponseType(
    responseType: string,
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
   * 보안 강화된 인증 URL 생성
   *
   * 자동으로 PKCE와 state를 생성하여 보안이 강화된 인증 URL을 생성합니다.
   *
   * @param scopes - 요청할 권한 스코프 배열
   * @param responseType - OAuth2 응답 타입 (기본값: code)
   * @returns 인증 URL과 보안 파라미터들
   */
  async createSecureAuthorizeUrl(
    scopes: OAuth2Scope[] = [OAuth2Scope.PROFILE],
    responseType: string = OAuth2ResponseType.CODE,
  ): Promise<{
    authUrl: string;
    codeVerifier: string;
    state: string;
  }> {
    const secureParams = await FlowAuthClient.generateSecureAuthParams();
    const authUrl = this.createAuthorizeUrlWithResponseType(
      responseType,
      scopes,
      secureParams.state,
      secureParams.pkce,
    );

    return {
      authUrl,
      codeVerifier: secureParams.pkce.codeVerifier,
      state: secureParams.state,
    };
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
   * 콜백 URL 파싱
   *
   * 인증 후 리다이렉트된 URL에서 파라미터를 추출합니다.
   *
   * @param callbackUrl - 콜백 URL
   * @returns 파싱된 콜백 파라미터들
   */
  parseCallbackUrl(callbackUrl: string): OAuth2CallbackParams {
    const url = new URL(callbackUrl);
    const params = new URLSearchParams(url.search);

    const code = params.get("code") || undefined;
    const state = params.get("state") || undefined;
    const error = params.get("error") || undefined;
    const errorDescription = params.get("error_description") || undefined;

    return {
      code,
      state,
      error,
      errorDescription,
    };
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
   * PKCE (Proof Key for Code Exchange) 코드 생성
   * @returns PKCE 코드 객체 (codeVerifier, codeChallenge, codeChallengeMethod)
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
   * OAuth2 State 파라미터 생성 (CSRF 방지용)
   * @returns 랜덤 state 문자열
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
   * OIDC Nonce 생성 (Replay Attack 방지용)
   * @returns 랜덤 nonce 문자열
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
   * @returns PKCE 코드와 State를 포함한 객체
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
   * Authorization Code Grant 콜백 처리
   *
   * Authorization Code Grant 콜백을 처리합니다.
   * URL에서 authorization code를 추출하여 토큰을 교환합니다.
   *
   * @param callbackUrl - 콜백 URL
   * @param expectedState - 예상 state 값 (CSRF 방지)
   * @param codeVerifier - PKCE 코드 검증자
   * @returns 토큰 응답 객체
   * @throws {OAuth2Error} 콜백 처리 실패 시
   *
   * @example
   * ```typescript
   * try {
   *   // 콜백 URL에서 파라미터 추출 및 검증
   *   const tokens = await client.handleCallback(
   *     window.location.href,
   *     sessionStorage.getItem('oauth_state'),
   *     sessionStorage.getItem('oauth_code_verifier')
   *   );
   *
   *   console.log('Access Token:', tokens.access_token);
   * } catch (error) {
   *   console.error('Callback failed:', error.message);
   * }
   * ```
   */
  async handleCallback(
    callbackUrl: string,
    expectedState?: string,
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

    // Authorization code가 있으면 토큰 교환
    if (params.code) {
      return await this.exchangeCode(params.code, codeVerifier);
    }

    throw new OAuth2Error("No authorization code found in callback");
  }
}
