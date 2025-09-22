/**
 * FlowAuth OAuth2 클라이언트 SDK
 * OAuth2 Authorization Code Grant 플로우를 위한 간단한 클라이언트 구현
 */

declare var crypto: any;

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in?: number;
  scope?: string;
}

interface UserInfo {
  sub: string;
  email?: string;
  username?: string;
  [key: string]: any;
}

class OAuth2Client {
  private clientId: string;
  private clientSecret: string;
  private redirectUri: string;
  private backendHost: string;

  /**
   * OAuth2Client 생성자
   * @param server - FlowAuth 백엔드 서버 URL
   * @param clientId - OAuth2 클라이언트 ID
   * @param clientSecret - OAuth2 클라이언트 시크릿
   * @param redirectUri - 인증 후 리다이렉트될 URI
   */
  constructor(server: string, clientId: string, clientSecret: string, redirectUri: string) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.redirectUri = redirectUri;
    this.backendHost = server;
  }

  /**
   * 인증 URL 생성
   * 사용자를 FlowAuth 인증 페이지로 리다이렉트하기 위한 URL을 생성합니다.
   * @param scopes - 요청할 권한 스코프 배열 (기본값: ["read:user"])
   * @param state - CSRF 방지를 위한 상태값
   * @returns 인증 URL
   */
  createAuthorizeUrl(scopes: string[] = ["read:user"], state?: string): string {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: scopes.join(" "),
    });

    if (state) params.set("state", state);

    return `${this.backendHost}/oauth2/authorize?${params.toString()}`;
  }

  /**
   * 토큰 교환
   * Authorization Code를 사용하여 Access Token과 Refresh Token을 교환합니다.
   * @param code - 인증 후 받은 authorization code
   * @param codeVerifier - PKCE 코드 검증자 (PKCE 사용 시)
   * @returns 토큰 응답 (access_token, refresh_token 등)
   * @throws Error if the token exchange fails
   */
  async exchangeCode(code: string, codeVerifier?: string): Promise<TokenResponse> {
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.clientId,
      code: code,
      redirect_uri: this.redirectUri,
    });

    if (codeVerifier) params.set("code_verifier", codeVerifier);

    const response = await fetch(`${this.backendHost}/oauth2/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${btoa(`${this.clientId}:${this.clientSecret}`)}`,
      },
      body: params.toString(),
    });

    if (!response.ok) {
      throw new Error(`Token exchange failed: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * 사용자 정보 조회
   * Access Token을 사용하여 사용자 정보를 조회합니다.
   * @param accessToken - 유효한 access token
   * @returns 사용자 정보 (sub, email, username 등)
   * @throws Error if the user info request fails
   */
  async getUserInfo(accessToken: string): Promise<UserInfo> {
    const response = await fetch(`${this.backendHost}/oauth2/userinfo`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error(`User info request failed: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * 토큰 리프래시
   * Refresh Token을 사용하여 새로운 Access Token을 발급받습니다.
   * @param refreshToken - 유효한 refresh token
   * @returns 새로운 토큰 응답
   * @throws Error if the token refresh fails
   */
  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    const params = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: this.clientId,
      refresh_token: refreshToken,
    });

    const response = await fetch(`${this.backendHost}/oauth2/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${btoa(`${this.clientId}:${this.clientSecret}`)}`,
      },
      body: params.toString(),
    });

    if (!response.ok) {
      throw new Error(`Token refresh failed: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * PKCE 코드 챌린지 생성
   * PKCE를 위한 코드 검증자와 챌린지를 생성합니다.
   * @returns {codeVerifier: string, codeChallenge: string}
   */
  static async generatePKCE(): Promise<{ codeVerifier: string; codeChallenge: string }> {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const codeVerifier = btoa(String.fromCharCode(...array)).replace(/[+/=]/g, (m) => ({ "+": "-", "/": "_", "=": "" }[m] || ""));
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const hash = await crypto.subtle.digest("SHA-256", data);
    const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/[+/=]/g, (m) => ({ "+": "-", "/": "_", "=": "" }[m] || ""));
    return { codeVerifier, codeChallenge };
  }
}

export default OAuth2Client;
