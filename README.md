# FlowAuth OAuth2/OIDC SDK

FlowAuth와의 OAuth2 및 OpenID Connect 통합을 위한 간단한 TypeScript/JavaScript SDK입니다.

## 특징

- OAuth2 Authorization Code Grant 플로우 지원
- **OpenID Connect 1.0 완전 지원** (ID 토큰, UserInfo 엔드포인트)
- PKCE (Proof Key for Code Exchange) 지원
- 자동 토큰 리프래시
- 토큰 저장 및 관리 (브라우저 sessionStorage/localStorage)
- **TypeScript OIDC 스코프 enum 제공** (타입 안전한 권한 관리)
- 브라우저 및 Node.js 환경 지원
- 강화된 에러 처리 (OAuth2Error 클래스)

## 환경 요구사항

### 브라우저 환경

- ES2018+ 지원 브라우저 (Chrome 64+, Firefox 58+, Safari 12+, Edge 79+)
- `crypto.subtle`, `fetch`, `sessionStorage`/`localStorage` 지원

### Node.js 환경

- Node.js 15+ (Web Crypto API 지원)
- Node.js 14 이하에서는 추가 설정 필요

## 설치

### npm을 사용하는 경우

```bash
npm install flowauth-oauth2-client
```

### 브라우저에서 직접 사용

```html
<script src="https://unpkg.com/flowauth-oauth2-client@latest/dist/index.js"></script>
```

## 사용법

### 기본 사용법

```javascript
const { FlowAuthClient } = require("flowauth-oauth2-client");

// 클라이언트 초기화 (자동 토큰 저장 활성화)
const client = new FlowAuthClient({
  server: "https://your-flowauth-server.com",
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirectUri: "https://your-app.com/callback",
  autoRefresh: true, // 자동 토큰 리프래시 활성화 (기본값: true)
});

// 1. State 생성 및 인증 URL 생성
const state = await FlowAuthClient.generateState();
const authUrl = client.createAuthorizeUrl([OAuth2Scope.OPENID, OAuth2Scope.PROFILE, OAuth2Scope.EMAIL], state);
console.log("인증 URL:", authUrl);
// 사용자를 authUrl로 리다이렉트

// 2. 콜백에서 코드 교환 (State 검증 및 토큰 자동 저장)
try {
  // 콜백 URL에서 파라미터 추출
  const urlParams = new URLSearchParams(window.location.search);
  const receivedState = urlParams.get("state");
  const receivedCode = urlParams.get("code");

  // State 검증 (CSRF 방지)
  if (receivedState !== state) {
    throw new Error("State mismatch - possible CSRF attack");
  }

  const tokens = await client.exchangeCode(receivedCode);
  console.log("Tokens:", tokens);
} catch (error) {
  console.error("Authentication failed:", error.message);
}

// 3. 저장된 토큰으로 사용자 정보 조회 (자동 리프래시)
const userInfo = await client.getUserInfo();
console.log("User Info:", userInfo);

// 4. 토큰 검증
const isValid = await client.validateToken();
console.log("Token is valid:", isValid);

// 5. 로그아웃 (저장된 토큰 제거)
client.logout();
```

### PKCE 및 State 사용 예제

```javascript
// 방법 1: 개별 생성 및 수동 관리
const pkce = await FlowAuthClient.generatePKCE();
const state = await FlowAuthClient.generateState();
const authUrl = client.createAuthorizeUrl([OAuth2Scope.OPENID], state, pkce);
const tokens = await client.exchangeCode("authorization-code", pkce.codeVerifier);

// 방법 2: PKCE와 State를 함께 생성 (편의 메소드)
const authParams = await FlowAuthClient.generateSecureAuthParams();
const authUrl = client.createAuthorizeUrl([OAuth2Scope.OPENID], authParams.state, authParams.pkce);
const tokens = await client.exchangeCode("authorization-code", authParams.pkce.codeVerifier);

// 방법 3: 완전 자동화된 보안 인증 URL 생성 (가장 간단)
const { authUrl, codeVerifier, state } = await client.createSecureAuthorizeUrl([OAuth2Scope.OPENID, OAuth2Scope.PROFILE, OAuth2Scope.EMAIL]);
// authUrl로 사용자를 리다이렉트하고, codeVerifier와 state를 세션에 저장
// 콜백에서:
const tokens = await client.exchangeCode("authorization-code", codeVerifier);
```

### OIDC Hybrid Flow 사용 예제

Hybrid Flow는 Authorization Code와 ID Token을 동시에 받아서 보안성과 사용자 경험을 모두 향상시킵니다:

```javascript
const { FlowAuthClient, OAuth2Scope } = require("flowauth-oauth2-client");

const client = new FlowAuthClient({
  server: "https://your-flowauth-server.com",
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirectUri: "https://your-app.com/callback",
});

// 방법 1: 수동 Hybrid Flow 구현
const pkce = await FlowAuthClient.generatePKCE();
const state = await FlowAuthClient.generateState();
const nonce = await FlowAuthClient.generateNonce();

const authUrl = client.createAuthorizeUrl([OAuth2Scope.OPENID, OAuth2Scope.PROFILE, OAuth2Scope.EMAIL], state, pkce, nonce);

// 세션에 파라미터 저장
sessionStorage.setItem("oauth_code_verifier", pkce.codeVerifier);
sessionStorage.setItem("oauth_state", state);
sessionStorage.setItem("oauth_nonce", nonce);

// 사용자를 authUrl로 리다이렉트
window.location.href = authUrl;

// 콜백에서 Hybrid Flow 처리
const callbackUrl = window.location.href;
const expectedState = sessionStorage.getItem("oauth_state");
const expectedNonce = sessionStorage.getItem("oauth_nonce");
const codeVerifier = sessionStorage.getItem("oauth_code_verifier");

try {
  const tokens = await client.handleHybridCallback(callbackUrl, expectedState, expectedNonce, codeVerifier);

  console.log("Access Token:", tokens.access_token);
  console.log("ID Token:", tokens.id_token);
  console.log("Refresh Token:", tokens.refresh_token);
} catch (error) {
  console.error("Hybrid callback failed:", error.message);
}

// 방법 2: 자동화된 Hybrid Flow (가장 간단)
const { authUrl, codeVerifier, state, nonce } = await client.createSecureOIDCAuthorizeUrl([
  OAuth2Scope.OPENID,
  OAuth2Scope.PROFILE,
  OAuth2Scope.EMAIL,
]);

// 세션에 파라미터 저장
sessionStorage.setItem("oauth_code_verifier", codeVerifier);
sessionStorage.setItem("oauth_state", state);
sessionStorage.setItem("oauth_nonce", nonce);

// 사용자를 authUrl로 리다이렉트
window.location.href = authUrl;

// 콜백에서 동일한 처리
const tokens = await client.handleHybridCallback(
  window.location.href,
  sessionStorage.getItem("oauth_state"),
  sessionStorage.getItem("oauth_nonce"),
  sessionStorage.getItem("oauth_code_verifier")
);
```

### 스코프 활용 예제

SDK는 TypeScript enum을 통해 타입 안전한 스코프 관리를 제공합니다:

```javascript
const { FlowAuthClient, OAuth2Scope, DEFAULT_SCOPES } = require("flowauth-oauth2-client");

const client = new FlowAuthClient({
  server: "https://your-flowauth-server.com",
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirectUri: "https://your-app.com/callback",
});

// 1. 기본 스코프 사용 (가장 일반적인 경우)
const authUrl = client.createAuthorizeUrl(DEFAULT_SCOPES);
console.log("기본 권한으로 인증:", authUrl);

// 2. 이메일 권한 추가 요청
const emailAuthUrl = client.createAuthorizeUrl([OAuth2Scope.OPENID, OAuth2Scope.PROFILE, OAuth2Scope.EMAIL]);
console.log("이메일 정보 접근 인증:", emailAuthUrl);
```

### 실전 활용 패턴

#### 사용자 프로필 애플리케이션

```javascript
const { FlowAuthClient, OAuth2Scope } = require("flowauth-oauth2-client");

class UserProfileApp {
  constructor() {
    this.client = new FlowAuthClient({
      server: "https://flowauth.example.com",
      clientId: "profile-app",
      clientSecret: "secret",
      redirectUri: "https://profile-app.com/callback",
    });
  }

  // 로그인 시작
  async startLogin() {
    const { authUrl, codeVerifier, state } = await this.client.createSecureAuthorizeUrl([OAuth2Scope.OPENID, OAuth2Scope.PROFILE, OAuth2Scope.EMAIL]);

    // 세션에 PKCE 정보 저장
    sessionStorage.setItem("oauth_code_verifier", codeVerifier);
    sessionStorage.setItem("oauth_state", state);

    // 사용자를 인증 페이지로 리다이렉트
    window.location.href = authUrl;
  }

  // 콜백 처리
  async handleCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get("code");
    const receivedState = urlParams.get("state");

    const savedState = sessionStorage.getItem("oauth_state");
    const codeVerifier = sessionStorage.getItem("oauth_code_verifier");

    if (receivedState !== savedState) {
      throw new Error("State 검증 실패");
    }

    // 토큰 교환 및 저장
    await this.client.exchangeCode(code, codeVerifier);

    // 세션 정리
    sessionStorage.removeItem("oauth_code_verifier");
    sessionStorage.removeItem("oauth_state");

    // 메인 페이지로 리다이렉트
    window.location.href = "/profile";
  }

  // 사용자 정보 표시
  async displayUserProfile() {
    try {
      const userInfo = await this.client.getUserInfo();
      console.log("사용자 정보:", userInfo);

      // 프로필 UI 업데이트
      this.updateProfileUI(userInfo);
    } catch (error) {
      console.error("프로필 로드 실패:", error);
      // 로그인 페이지로 리다이렉트
      this.startLogin();
    }
  }

  updateProfileUI(userInfo) {
    // 실제 애플리케이션에서는 DOM 업데이트
    console.log(`환영합니다, ${userInfo.username || userInfo.email}!`);
  }
}
```

#### 권한 기반 UI 렌더링

```javascript
const { FlowAuthClient, OAuth2Scope } = require("flowauth-oauth2-client");

class PermissionBasedUI {
  constructor(client) {
    this.client = client;
  }

  // 현재 사용자의 권한에 따른 UI 렌더링
  async renderUI() {
    const tokenInfo = this.client.getTokenInfo();
    if (!tokenInfo) {
      this.renderLoginButton();
      return;
    }

    const scopes = tokenInfo.scope ? tokenInfo.scope.split(" ") : [];

    // 이메일 정보 표시 UI
    if (scopes.includes(OAuth2Scope.EMAIL)) {
      this.renderEmailSection();
    }

    // 기본 사용자 정보 UI
    if (scopes.includes(OAuth2Scope.PROFILE)) {
      this.renderUserProfile();
    }
  }

  renderLoginButton() {
    console.log("로그인 버튼 표시");
    // 실제로는 DOM 조작
  }

  renderEmailSection() {
    console.log("이메일 정보 섹션 표시");
  }

  renderUserProfile() {
    console.log("사용자 프로필 섹션 표시");
  }

  // 추가 권한 요청 UI
  renderScopeRequest() {
    console.log("추가 권한 요청:");
    const additionalScopes = [OAuth2Scope.EMAIL];

    console.log("- 이메일 주소 접근 권한");

    // 추가 권한으로 재인증 링크 생성
    const authUrl = this.client.createAuthorizeUrl([OAuth2Scope.OPENID, OAuth2Scope.PROFILE, OAuth2Scope.EMAIL]);
    console.log("추가 권한 요청 URL:", authUrl);
  }
}

// 사용 예시
const client = new FlowAuthClient({
  /* 설정 */
});
const ui = new PermissionBasedUI(client);
ui.renderUI();
```

### 고급 사용법

```javascript
// 커스텀 스토리지 사용 (Node.js 환경 등)
const client = new FlowAuthClient({
  server: "https://your-server.com",
  clientId: "client-id",
  clientSecret: "client-secret",
  redirectUri: "https://your-app.com/callback",
  storage: customStorage, // 커스텀 Storage 구현
  autoRefresh: false, // 수동 리프래시
});

// 수동 토큰 관리
const tokens = await client.exchangeCode("code");
const userInfo = await client.getUserInfo(tokens.access_token);

// 수동 리프래시
const newTokens = await client.refreshToken(tokens.refresh_token);

// 토큰 정보 조회
const tokenInfo = client.getTokenInfo();
console.log("Current tokens:", tokenInfo);
```

## 배포

npm에 패키지를 배포하려면:

```bash
npm run build
npm publish
```

빌드 후 dist 폴더에 컴파일된 파일이 생성됩니다.

## 테스트

테스트를 실행하려면:

```bash
npm run test:run
```

또는 개발 중 감시 모드로:

```bash
npm test
```

## API 문서

### OAuth2/OIDC 스코프

SDK는 다음과 같은 OAuth2 및 OpenID Connect 스코프들을 enum으로 제공합니다:

```typescript
enum OAuth2Scope {
  OPENID = "openid", // OpenID Connect 인증을 위한 기본 스코프
  PROFILE = "profile", // 사용자 프로필 정보 (이름, 생년월일, 지역, 사진 등) 접근
  EMAIL = "email", // 사용자 이메일 주소 읽기
  IDENTIFY = "identify", // 계정의 기본 정보 읽기 (사용자 ID, 이름 등) - 레거시
}
```

**기본 스코프 (OIDC 권장):**

```typescript
const DEFAULT_SCOPES = [OAuth2Scope.OPENID, OAuth2Scope.PROFILE];
```

### FlowAuthClient 클래스

#### 생성자

```typescript
new FlowAuthClient(config: OAuth2ClientConfig)
```

**파라미터:**

- `server`: FlowAuth 서버 URL
- `clientId`: OAuth2 클라이언트 ID
- `clientSecret`: OAuth2 클라이언트 시크릿
- `redirectUri`: 인증 후 리다이렉트 URI
- `storage?`: 커스텀 스토리지 구현 (기본값: 브라우저 sessionStorage)
- `autoRefresh?`: 자동 토큰 리프래시 활성화 (기본값: true)

#### 메소드

- `createAuthorizeUrl(scopes: OAuth2Scope[] = [OAuth2Scope.OPENID], state?, pkce?)`: 인증 URL 생성 (PKCE 지원)
- `createSecureAuthorizeUrl(scopes: OAuth2Scope[] = [OAuth2Scope.OPENID, OAuth2Scope.PROFILE])`: PKCE와 State를 자동 생성하여 보안 인증 URL 생성
- `exchangeCode(code, codeVerifier?)`: Authorization Code를 토큰으로 교환
- `getUserInfo(accessToken?)`: 사용자 정보 조회 (저장된 토큰 자동 사용)
- `refreshToken(refreshToken?)`: 토큰 리프래시 (저장된 토큰 자동 사용)
- `validateToken(accessToken?)`: 토큰 유효성 검증
- `getStoredAccessToken()`: 저장된 액세스 토큰 조회
- `getTokenInfo()`: 현재 토큰 정보 조회
- `logout()`: 저장된 토큰 제거

#### 정적 메소드

- `FlowAuthClient.generatePKCE()`: PKCE 챌린지 생성
- `FlowAuthClient.generateState()`: OAuth2 State 파라미터 생성
- `FlowAuthClient.generateSecureAuthParams()`: PKCE와 State를 함께 생성

### 에러 처리

SDK는 `OAuth2Error` 클래스를 사용하여 OAuth2 관련 에러를 제공합니다:

```javascript
try {
  const tokens = await client.exchangeCode(code);
} catch (error) {
  if (error instanceof OAuth2Error) {
    console.log("OAuth2 Error:", error.status, error.code, error.message);
  }
}
```

자세한 API 문서와 OAuth2/OIDC 플로우 설명은 [가이드 문서](https://github.com/vientofactory/FlowAuth/blob/main/OAUTH2_GUIDE.md)를 참조하세요.

## 라이선스

이 SDK는 FlowAuth 프로젝트의 일부입니다. FlowAuth 프로젝트와 동일한 MIT 라이선스를 사용합니다.
