/**
 * FlowAuth OAuth2 클라이언트 SDK
 * OAuth2 Authorization Code Grant 플로우를 위한 간단한 클라이언트 구현
 */
class OAuth2Client {
  /**
   * OAuth2Client 생성자
   * @param {string} server - FlowAuth 백엔드 서버 URL
   * @param {string} clientId - OAuth2 클라이언트 ID
   * @param {string} clientSecret - OAuth2 클라이언트 시크릿
   * @param {string} redirectUri - 인증 후 리다이렉트될 URI
   */
  constructor(server, clientId, clientSecret, redirectUri) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.redirectUri = redirectUri;
    this.backendHost = server;
  }

  /**
   * 인증 URL 생성
   * 사용자를 FlowAuth 인증 페이지로 리다이렉트하기 위한 URL을 생성합니다.
   * @param {string[]} scopes - 요청할 권한 스코프 배열 (기본값: ["read:user"])
   * @param {string|null} state - CSRF 방지를 위한 상태값
   * @returns {string} 인증 URL
   */
  createAuthorizeUrl(scopes = ["read:user"], state = null) {
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
   * @param {string} code - 인증 후 받은 authorization code
   * @param {string|null} codeVerifier - PKCE 코드 검증자 (PKCE 사용 시)
   * @returns {Promise<Object>} 토큰 응답 (access_token, refresh_token 등)
   */
  async exchangeCode(code, codeVerifier = null) {
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

    return response.json();
  }

  /**
   * 사용자 정보 조회
   * Access Token을 사용하여 사용자 정보를 조회합니다.
   * @param {string} accessToken - 유효한 access token
   * @returns {Promise<Object>} 사용자 정보 (sub, email, username 등)
   */
  async getUserInfo(accessToken) {
    const response = await fetch(`${this.backendHost}/oauth2/userinfo`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    return response.json();
  }

  /**
   * 토큰 리프래시
   * Refresh Token을 사용하여 새로운 Access Token을 발급받습니다.
   * @param {string} refreshToken - 유효한 refresh token
   * @returns {Promise<Object>} 새로운 토큰 응답
   */
  async refreshToken(refreshToken) {
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

    return response.json();
  }
}

module.exports = OAuth2Client;
