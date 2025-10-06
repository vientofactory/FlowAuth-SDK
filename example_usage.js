import { FlowAuthClient, OAuth2Scope } from "./dist/index";
import { createInterface } from "readline";

// FlowAuth 서버 설정 (실제 사용 시 자신의 서버 URL로 변경)
const server = "https://authserver.viento.me";
const redirectUri = "https://auth.viento.me/callback";

// 클라이언트 자격 증명 (실제 사용 시 자신의 값으로 변경)
const clientId = "your-client-id";
const clientSecret = "your-client-secret";

/**
 * 보안 강화된 OIDC 인증 예제 (PKCE + Nonce 사용)
 * - PKCE: 코드 교환 공격 방지
 * - Nonce: ID 토큰 재생 공격 방지
 * - State: CSRF 공격 방지
 */
async function createSecureOIDCAuthorization() {
  // FlowAuth 클라이언트 초기화
  const client = new FlowAuthClient({
    server,
    clientId,
    clientSecret,
    redirectUri,
  });

  try {
    // 보안 강화된 OIDC 인증 URL 생성 (PKCE, Nonce, State 자동 포함)
    const { authUrl, codeVerifier, nonce } = await client.createSecureOIDCAuthorizeUrl([
      OAuth2Scope.OPENID, // OIDC 필수 스코프
      OAuth2Scope.PROFILE, // 프로필 정보 접근
      OAuth2Scope.EMAIL, // 이메일 정보 접근
    ]);
    console.log("인증 URL:", authUrl);
    console.log("브라우저에서 위 URL로 이동하여 인증을 완료한 후, 콜백 URL에서 코드를 복사하세요.");

    // Node.js 환경에서 사용자 입력 받기 (브라우저에서는 URL 파라미터에서 추출)
    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    rl.question("Authorization Code를 입력하세요: ", async (code) => {
      try {
        // 코드 교환 및 토큰 획득
        const token = await client.exchangeCode(code, codeVerifier);
        console.log("토큰 교환 성공:", {
          access_token: token.access_token ? "획득됨" : "없음",
          refresh_token: token.refresh_token ? "획득됨" : "없음",
          id_token: token.id_token ? "획득됨" : "없음",
        });

        // 사용자 프로필 정보 조회
        const profile = await client.getUserInfo(token.access_token);
        console.log("사용자 프로필:", profile);

        // ID 토큰 검증 (Nonce를 사용한 재생 공격 방지)
        const validateIdToken = await client.validateIdToken(token.id_token, nonce);
        console.log("ID 토큰 검증 결과:", validateIdToken ? "유효함" : "유효하지 않음");
      } catch (e) {
        console.error("인증 과정 중 오류:", e.message);
      }
      rl.close();
    });
  } catch (e) {
    console.error("초기화 오류:", e.message);
  }
}

/**
 * 기본 OIDC 인증 예제 (PKCE 미사용)
 * - 보안성이 낮으므로 프로덕션에서는 createSecureOIDCAuthorization 사용 권장
 */
function createOIDCAuthorization() {
  const client = new FlowAuthClient({
    server,
    clientId,
    clientSecret,
    redirectUri,
  });

  try {
    // OIDC 인증 URL 생성
    const authUrl = client.createOIDCAuthorizeUrl([OAuth2Scope.OPENID, OAuth2Scope.PROFILE, OAuth2Scope.EMAIL]);
    console.log("OIDC 인증 URL:", authUrl);

    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    rl.question("Authorization Code를 입력하세요: ", async (code) => {
      try {
        const token = await client.exchangeCode(code);
        console.log("토큰 교환 결과:", token);

        const profile = await client.getUserInfo(token.access_token);
        console.log("프로필 정보:", profile);

        const validateIdToken = await client.validateIdToken(token.id_token);
        console.log("ID 토큰 검증 결과:", validateIdToken);
      } catch (e) {
        console.error("오류:", e.message);
      }
      rl.close();
    });
  } catch (e) {
    console.error("초기화 오류:", e.message);
  }
}

/**
 * 기본 OAuth2 인증 예제 (OIDC 미사용)
 * - OpenID Connect를 지원하지 않는 OAuth2 서버용
 */
function createAuthorizeUrl() {
  const client = new FlowAuthClient({
    server,
    clientId,
    clientSecret,
    redirectUri,
  });

  try {
    const authUrl = client.createAuthorizeUrl([OAuth2Scope.OPENID, OAuth2Scope.PROFILE, OAuth2Scope.EMAIL]);
    console.log("OAuth2 인증 URL:", authUrl);

    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    rl.question("Authorization Code를 입력하세요: ", async (code) => {
      try {
        const token = await client.exchangeCode(code);
        console.log("토큰 교환 결과:", token);

        // OIDC가 아니므로 ID 토큰 검증 생략
        const profile = await client.getUserInfo(token.access_token);
        console.log("프로필 정보:", profile);
      } catch (e) {
        console.error("오류:", e.message);
      }
      rl.close();
    });
  } catch (e) {
    console.error("초기화 오류:", e.message);
  }
}

/**
 * PKCE를 사용한 보안 강화 OAuth2 인증 예제
 * - 코드 교환 공격 방지
 */
async function createSecureAuthorizeUrl() {
  const client = new FlowAuthClient({
    server,
    clientId,
    clientSecret,
    redirectUri,
  });

  try {
    // PKCE를 사용한 보안 강화 인증 URL 생성
    const { authUrl, codeVerifier } = await client.createSecureAuthorizeUrl([OAuth2Scope.OPENID, OAuth2Scope.PROFILE, OAuth2Scope.EMAIL]);
    console.log("보안 강화 인증 URL:", authUrl);

    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    rl.question("Authorization Code를 입력하세요: ", async (code) => {
      try {
        const token = await client.exchangeCode(code, codeVerifier);
        console.log("토큰 교환 결과:", token);

        const profile = await client.getUserInfo(token.access_token);
        console.log("프로필 정보:", profile);
      } catch (e) {
        console.error("오류:", e.message);
      }
      rl.close();
    });
  } catch (e) {
    console.error("초기화 오류:", e.message);
  }
}

/**
 * 브라우저 환경에서의 사용 예제 (참고용)
 * 실제 브라우저에서는 다음과 같이 사용할 수 있습니다:
 *
 * // 1. 인증 URL 생성 및 리다이렉트
 * const state = await FlowAuthClient.generateState();
 * const authUrl = client.createAuthorizeUrl([OAuth2Scope.OPENID], state);
 * window.location.href = authUrl;
 *
 * // 2. 콜백 페이지에서 코드 교환
 * const urlParams = new URLSearchParams(window.location.search);
 * const code = urlParams.get("code");
 * const receivedState = urlParams.get("state");
 *
 * if (receivedState === state) {
 *   const tokens = await client.exchangeCode(code);
 *   const userInfo = await client.getUserInfo();
 * }
 */

// 실행할 예제 선택 (주석 해제하여 테스트)
// createSecureOIDCAuthorization();  // 가장 보안적인 옵션 (권장)
createAuthorizeUrl(); // 기본 OAuth2 예제
