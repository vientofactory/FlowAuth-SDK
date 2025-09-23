# FlowAuth OAuth2 SDK

FlowAuth와의 OAuth2 통합을 위한 간단한 TypeScript/JavaScript SDK입니다.

## 특징

- OAuth2 Authorization Code Grant 플로우 지원
- PKCE (Proof Key for Code Exchange) 지원
- 자동 토큰 리프래시
- 토큰 저장 및 관리 (브라우저 sessionStorage/localStorage)
- TypeScript 타입 정의 제공
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
const authUrl = client.createAuthorizeUrl(["read:user", "email"], state);
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
const { authUrl, codeVerifier, state } = await client.createSecureAuthorizeUrl(["read:user", "email"]);
// authUrl로 사용자를 리다이렉트하고, codeVerifier와 state를 세션에 저장
// 콜백에서:
const tokens = await client.exchangeCode("authorization-code", codeVerifier);
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

- `createAuthorizeUrl(scopes, state?, pkce?)`: 인증 URL 생성 (PKCE 지원)
- `createSecureAuthorizeUrl(scopes?)`: PKCE와 State를 자동 생성하여 보안 인증 URL 생성
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
