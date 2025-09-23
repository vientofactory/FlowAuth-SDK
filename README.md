# FlowAuth OAuth2 SDK

FlowAuth와의 OAuth2 통합을 위한 간단한 TypeScript/JavaScript SDK입니다.

## 특징

- OAuth2 Authorization Code Grant 플로우 지원
- PKCE (Proof Key for Code Exchange) 지원
- 자동 토큰 리프래시
- 토큰 저장 및 관리 (브라우저 sessionStorage/localStorage)
- **TypeScript 스코프 enum 제공** (타입 안전한 권한 관리)
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
const authUrl = client.createAuthorizeUrl(["read:user", "read:profile"], state);
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
const authUrl = client.createAuthorizeUrl(["read:user"], state, pkce);
const tokens = await client.exchangeCode("authorization-code", pkce.codeVerifier);

// 방법 2: PKCE와 State를 함께 생성 (편의 메소드)
const authParams = await FlowAuthClient.generateSecureAuthParams();
const authUrl = client.createAuthorizeUrl(["read:user"], authParams.state, authParams.pkce);
const tokens = await client.exchangeCode("authorization-code", authParams.pkce.codeVerifier);

// 방법 3: 완전 자동화된 보안 인증 URL 생성 (가장 간단)
const { authUrl, codeVerifier, state } = await client.createSecureAuthorizeUrl(["read:user", "read:profile"]);
// authUrl로 사용자를 리다이렉트하고, codeVerifier와 state를 세션에 저장
// 콜백에서:
const tokens = await client.exchangeCode("authorization-code", codeVerifier);
```

### 스코프 활용 예제

SDK는 TypeScript enum을 통해 타입 안전한 스코프 관리를 제공합니다:

```javascript
const { FlowAuthClient, OAuth2Scope, DEFAULT_SCOPES, SCOPE_DESCRIPTIONS } = require("flowauth-oauth2-client");

const client = new FlowAuthClient({
  server: "https://your-flowauth-server.com",
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirectUri: "https://your-app.com/callback",
});

// 1. 기본 스코프 사용 (가장 일반적인 경우)
const authUrl = client.createAuthorizeUrl(DEFAULT_SCOPES);
console.log("기본 권한으로 인증:", authUrl);

// 2. 특정 스코프만 요청
const profileAuthUrl = client.createAuthorizeUrl([OAuth2Scope.READ_USER, OAuth2Scope.READ_PROFILE, OAuth2Scope.EMAIL]);
console.log("프로필 정보 접근 인증:", profileAuthUrl);

// 3. 파일 관리 권한 요청
const fileAuthUrl = client.createAuthorizeUrl([OAuth2Scope.READ_USER, OAuth2Scope.UPLOAD_FILE, OAuth2Scope.READ_FILE, OAuth2Scope.DELETE_FILE]);
console.log("파일 관리 인증:", fileAuthUrl);

// 4. 관리자 권한 요청
const adminAuthUrl = client.createAuthorizeUrl([OAuth2Scope.READ_CLIENT, OAuth2Scope.WRITE_CLIENT, OAuth2Scope.DELETE_CLIENT]);
console.log("클라이언트 관리 인증:", adminAuthUrl);

// 5. 스코프 설명 표시 (UI에서 사용자에게 권한 설명)
console.log("요청할 권한들:");
const requestedScopes = [OAuth2Scope.READ_USER, OAuth2Scope.EMAIL, OAuth2Scope.UPLOAD_FILE];
requestedScopes.forEach((scope) => {
  console.log(`- ${scope}: ${SCOPE_DESCRIPTIONS[scope]}`);
});
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
    const { authUrl, codeVerifier, state } = await this.client.createSecureAuthorizeUrl([
      OAuth2Scope.READ_USER,
      OAuth2Scope.READ_PROFILE,
      OAuth2Scope.EMAIL,
    ]);

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

#### 파일 관리 애플리케이션

```javascript
const { FlowAuthClient, OAuth2Scope } = require("flowauth-oauth2-client");

class FileManagerApp {
  constructor() {
    this.client = new FlowAuthClient({
      server: "https://flowauth.example.com",
      clientId: "file-manager",
      clientSecret: "secret",
      redirectUri: "https://filemanager.com/callback",
    });
  }

  // 파일 권한으로 로그인
  async loginForFileAccess() {
    const { authUrl, codeVerifier, state } = await this.client.createSecureAuthorizeUrl([
      OAuth2Scope.READ_USER,
      OAuth2Scope.UPLOAD_FILE,
      OAuth2Scope.READ_FILE,
      OAuth2Scope.DELETE_FILE,
    ]);

    sessionStorage.setItem("oauth_code_verifier", codeVerifier);
    sessionStorage.setItem("oauth_state", state);
    window.location.href = authUrl;
  }

  // 파일 업로드
  async uploadFile(file) {
    const accessToken = this.client.getStoredAccessToken();
    if (!accessToken) {
      throw new Error("인증 필요");
    }

    const formData = new FormData();
    formData.append("file", file);

    const response = await fetch(`${this.client.server}/api/files/upload`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
      body: formData,
    });

    if (!response.ok) {
      throw new Error("파일 업로드 실패");
    }

    return response.json();
  }

  // 파일 목록 조회
  async listFiles() {
    const accessToken = this.client.getStoredAccessToken();
    if (!accessToken) {
      throw new Error("인증 필요");
    }

    const response = await fetch(`${this.client.server}/api/files`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error("파일 목록 조회 실패");
    }

    return response.json();
  }
}
```

#### 권한 기반 UI 렌더링

```javascript
const { FlowAuthClient, OAuth2Scope, SCOPE_DESCRIPTIONS } = require("flowauth-oauth2-client");

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

    // 파일 관리 UI
    if (scopes.includes(OAuth2Scope.UPLOAD_FILE)) {
      this.renderFileUpload();
    }

    // 사용자 관리 UI (관리자만)
    if (scopes.includes(OAuth2Scope.WRITE_CLIENT)) {
      this.renderAdminPanel();
    }

    // 프로필 편집 UI
    if (scopes.includes(OAuth2Scope.READ_PROFILE)) {
      this.renderProfileEditor();
    }
  }

  renderLoginButton() {
    console.log("로그인 버튼 표시");
    // 실제로는 DOM 조작
  }

  renderFileUpload() {
    console.log("파일 업로드 UI 표시");
  }

  renderAdminPanel() {
    console.log("관리자 패널 표시");
  }

  renderProfileEditor() {
    console.log("프로필 편집 UI 표시");
  }

  // 권한 요청 UI
  renderScopeRequest() {
    console.log("추가 권한 요청:");
    const additionalScopes = [OAuth2Scope.UPLOAD_FILE, OAuth2Scope.DELETE_FILE];

    additionalScopes.forEach((scope) => {
      console.log(`- ${SCOPE_DESCRIPTIONS[scope]}`);
    });

    // 추가 권한으로 재인증 링크 생성
    const authUrl = this.client.createAuthorizeUrl(additionalScopes);
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

### OAuth2 스코프

SDK는 다음과 같은 OAuth2 스코프들을 enum으로 제공합니다:

```typescript
enum OAuth2Scope {
  READ_USER = "read:user", // 사용자 기본 정보 읽기
  READ_PROFILE = "read:profile", // 사용자 프로필 읽기
  UPLOAD_FILE = "upload:file", // 파일 업로드
  READ_FILE = "read:file", // 파일 읽기
  DELETE_FILE = "delete:file", // 파일 삭제
  READ_CLIENT = "read:client", // 클라이언트 정보 읽기
  WRITE_CLIENT = "write:client", // 클라이언트 정보 수정
  DELETE_CLIENT = "delete:client", // 클라이언트 삭제
  BASIC = "basic", // 기본 접근 권한
  EMAIL = "email", // 사용자 이메일 주소 읽기
}
```

**기본 스코프:**

```typescript
const DEFAULT_SCOPES = [OAuth2Scope.BASIC, OAuth2Scope.READ_USER, OAuth2Scope.READ_PROFILE];
```

**스코프 설명:**

```typescript
const SCOPE_DESCRIPTIONS = {
  [OAuth2Scope.READ_USER]: "사용자 기본 정보 읽기",
  [OAuth2Scope.READ_PROFILE]: "사용자 프로필 읽기",
  // ... 기타 설명들
};
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

- `createAuthorizeUrl(scopes: OAuth2Scope[], state?, pkce?)`: 인증 URL 생성 (PKCE 지원)
- `createSecureAuthorizeUrl(scopes?: OAuth2Scope[])`: PKCE와 State를 자동 생성하여 보안 인증 URL 생성
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

자세한 API 문서와 OAuth2 플로우 설명은 [OAUTH2_GUIDE.md](../OAUTH2_GUIDE.md)를 참조하세요.

## 라이선스

이 SDK는 FlowAuth 프로젝트의 일부입니다. 라이선스 정보는 [LICENSE](../LICENSE)를 참조하세요.
