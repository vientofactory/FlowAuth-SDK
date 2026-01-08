# FlowAuth OAuth2 SDK

FlowAuth와의 OAuth2 Authorization Code Grant 통합을 위한 간단한 TypeScript/JavaScript SDK입니다.

## 특징

- OAuth2 Authorization Code Grant 플로우 지원
- PKCE (Proof Key for Code Exchange) 지원
- **향상된 암호화 지원**: RSA (RS256) 및 ECDSA (ES256) 알고리즘 지원
- **강화된 ID 토큰 검증**: JWKS 기반 서명 검증 (RSA/ECDSA)
- 자동 토큰 리프래시
- 토큰 저장 및 관리 (브라우저 sessionStorage/localStorage)
- TypeScript OAuth2 스코프 enum 제공 (타입 안전한 권한 관리)
- 브라우저 및 Node.js 환경 지원
- 강화된 에러 처리 (OAuth2Error 클래스)

## 환경 요구사항

### 브라우저 환경

- ES2018+ 지원 브라우저 (Chrome 64+, Firefox 58+, Safari 12+, Edge 79+)
- `crypto.subtle`, `fetch`, `sessionStorage`/`localStorage` 지원

### Node.js 환경

- Node.js 15+ (Web Crypto API 지원)
- Node.js 18+에서는 `fetch`가 기본 제공되어 추가 설정 불필요
- Node.js 14-17에서는 `node-fetch` 설치 권장:
  ```bash
  npm install node-fetch
  ```
- **토큰 저장**: Node.js 환경에서도 토큰 저장이 완전히 지원됩니다
  - 기본값: `MemoryStorage` (애플리케이션 실행 중 유지)
  - 영구 저장: `FileStorage` 사용 가능
  - 커스텀 스토리지: `TokenStorage` 인터페이스 구현

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

### TypeScript 환경

```typescript
import {
  FlowAuthClient,
  OAuth2Scope,
  OAuth2ResponseType,
  OAuth2GrantType,
  OAuth2TokenType
} from "flowauth-oauth2-client";

// 클라이언트 초기화 (자동 토큰 저장 활성화)
const client = new FlowAuthClient({
  server: "https://your-flowauth-server.com",
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirectUri: "https://your-app.com/callback",
  autoRefresh: true, // 자동 토큰 리프래시 활성화 (기본값: true)
});

// 1. State 생성 및 인증 URL 생성 (타입 안전한 enum 사용)
const state = await FlowAuthClient.generateState();

// Authorization Code Flow (권장)
const authUrl = client.createAuthorizeUrl(
  [OAuth2Scope.OPENID, OAuth2Scope.PROFILE, OAuth2Scope.EMAIL],
  state,
  undefined,
  undefined,
  OAuth2ResponseType.CODE
);

console.log("인증 URL:", authUrl);
// 사용자를 authUrl로 리다이렉트

// 2. 콜백에서 코드 교환 (State 검증 및 토큰 자동 저장)
try {
  // 콜백 URL에서 파라미터 추출
  const urlParams = new URLSearchParams(window.location.search);
  const receivedState = urlParams.get("state");
  const receivedCode = urlParams.get("code");

  // State 검증 (CSRF 방지)
```

### 순수 JavaScript 환경

SDK는 순수 JavaScript 환경에서도 완전히 지원됩니다. 런타임 상수 객체들을 제공하여 타입 정의 없이도 안전하게 사용할 수 있습니다.

```javascript
const {
  FlowAuthClient,
  OAuth2ResponseTypes,
  OAuth2GrantTypes,
  OAuth2TokenTypes,
  OAuth2Scope,
  OAUTH2_CONSTANTS,
} = require("flowauth-oauth2-client");

// 클라이언트 초기화
const client = new FlowAuthClient({
  server: "https://your-flowauth-server.com",
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirectUri: "https://your-app.com/callback",
});

// 런타임 상수 사용
console.log("지원되는 응답 타입들:", OAuth2ResponseTypes);
// 출력: { CODE: "code" }

console.log("지원되는 Grant 타입들:", OAuth2GrantTypes);
// 출력: { AUTHORIZATION_CODE: "authorization_code", REFRESH_TOKEN: "refresh_token", ... }

// Authorization Code Flow
const authUrl = client.createAuthorizeUrl(
  [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
  state,
  pkce,
);

// 콜백 처리
function handleCallback(callbackParams) {
  // Authorization Code 처리
  if (callbackParams.code) {
    client
      .exchangeCode(callbackParams.code)
      .then(tokens => console.log("토큰 받음:", tokens))
      .catch(error => console.error("토큰 교환 실패:", error));
  }

  // 에러 처리
  if (callbackParams.error) {
    console.error("OAuth2 에러:", callbackParams.error);
  }
}

// 응답 타입 검증
function isValidResponseType(responseType) {
  return OAUTH2_CONSTANTS.SUPPORTED_RESPONSE_TYPES.includes(responseType);
}

console.log(isValidResponseType(OAuth2ResponseTypes.CODE)); // true
console.log(isValidResponseType("invalid_type")); // false
```

### 기본 사용법

```javascript
// 클라이언트 초기화
const client = new FlowAuthClient({
  server: "https://your-flowauth-server.com",
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirectUri: "https://your-app.com/callback",
});

// 1. State 생성 및 인증 URL 생성
const state = await FlowAuthClient.generateState();
// 권장 스코프 사용
const authUrl = client.createAuthorizeUrl(
  [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
  state,
);

// 사용자를 authUrl로 리다이렉트
window.location.href = authUrl;

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
const authUrl = client.createAuthorizeUrl(
  [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
  state,
  pkce,
);
const tokens = await client.exchangeCode(
  "authorization-code",
  pkce.codeVerifier,
);

// 방법 2: PKCE와 State를 함께 생성 (편의 메소드)
const authParams = await FlowAuthClient.generateSecureAuthParams();
const authUrl = client.createAuthorizeUrl(
  [OAuth2Scope.OPENID, OAuth2Scope.PROFILE],
  authParams.state,
  authParams.pkce,
);
const tokens = await client.exchangeCode(
  "authorization-code",
  authParams.pkce.codeVerifier,
);

// 방법 3: 완전 자동화된 보안 인증 URL 생성 (가장 간단)
const { authUrl, codeVerifier, state } = await client.createSecureAuthorizeUrl([
  OAuth2Scope.OPENID,
  OAuth2Scope.PROFILE,
  OAuth2Scope.EMAIL,
]);
// authUrl로 사용자를 리다이렉트하고, codeVerifier와 state를 세션에 저장
// 콜백에서:
const tokens = await client.exchangeCode("authorization-code", codeVerifier);
```

### 스코프 활용 예제

SDK는 TypeScript enum을 통해 타입 안전한 스코프 관리를 제공합니다:

```javascript
const {
  FlowAuthClient,
  OAuth2Scope,
  DEFAULT_SCOPES,
} = require("flowauth-oauth2-client");

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
const emailAuthUrl = client.createAuthorizeUrl([
  OAuth2Scope.OPENID,
  OAuth2Scope.PROFILE,
  OAuth2Scope.EMAIL,
]);
console.log("이메일 정보 접근 인증:", emailAuthUrl);
```

### Node.js 스토리지 사용 예제

```javascript
const {
  FlowAuthClient,
  MemoryStorage,
  FileStorage,
  OAuth2Scope,
} = require("flowauth-oauth2-client");

// 1. 메모리 스토리지 사용 (기본값, 애플리케이션 실행 중에만 유지)
const client = new FlowAuthClient({
  server: "https://your-flowauth-server.com",
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirectUri: "https://your-app.com/callback",
  // storage: new MemoryStorage() // 기본값이므로 생략 가능
});

// 2. 파일 기반 스토리지 사용 (영구 저장)
const fileStorage = new FileStorage("./tokens.json");
const clientWithFileStorage = new FlowAuthClient({
  server: "https://your-flowauth-server.com",
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirectUri: "https://your-app.com/callback",
  storage: fileStorage,
});

// 3. 커스텀 스토리지 구현
class RedisStorage {
  constructor(redisClient) {
    this.redis = redisClient;
  }

  async getItem(key) {
    return await this.redis.get(key);
  }

  async setItem(key, value) {
    await this.redis.set(key, value);
  }

  async removeItem(key) {
    await this.redis.del(key);
  }

  async clear() {
    // Redis에서 모든 키 삭제 로직
  }
}

const redisStorage = new RedisStorage(redisClient);
const clientWithRedis = new FlowAuthClient({
  server: "https://your-flowauth-server.com",
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  redirectUri: "https://your-app.com/callback",
  storage: redisStorage,
});
```

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
    const { authUrl, codeVerifier, state } =
      await this.client.createSecureAuthorizeUrl([
        OAuth2Scope.OPENID,
        OAuth2Scope.PROFILE,
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
    const authUrl = this.client.createAuthorizeUrl([
      OAuth2Scope.OPENID,
      OAuth2Scope.PROFILE,
      OAuth2Scope.EMAIL,
    ]);
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

### 암호화 서명 검증 (RSA/ECDSA)

SDK는 ID 토큰의 암호화 서명 검증을 완전히 지원합니다. FlowAuth 서버가 RSA (RS256) 또는 ECDSA (ES256) 알고리즘을 사용하는지에 관계없이 자동으로 적절한 검증을 수행합니다.

```javascript
// ID 토큰 자동 검증 (RSA/ECDSA 모두 지원)
try {
  const idTokenPayload = await client.validateIdToken();
  console.log("검증된 ID 토큰 정보:", {
    userId: idTokenPayload.sub,
    email: idTokenPayload.email,
    name: idTokenPayload.name,
    issuer: idTokenPayload.iss,
    audience: idTokenPayload.aud,
    issuedAt: new Date(idTokenPayload.iat * 1000),
    expiration: new Date(idTokenPayload.exp * 1000),
  });
} catch (error) {
  console.error("ID 토큰 검증 실패:", error.message);
  // 가능한 원인:
  // - 서명이 유효하지 않음
  // - 토큰이 만료됨
  // - issuer 또는 audience가 일치하지 않음
  // - JWKS를 가져올 수 없음
}

// 수동 ID 토큰 검증 (더 세밀한 제어)
try {
  const customIdToken = "eyJ..."; // 외부에서 받은 ID 토큰
  const expectedNonce = "custom-nonce-value";

  const payload = await client.validateIdToken(customIdToken, expectedNonce);
  console.log("검증 성공:", payload);
} catch (error) {
  console.error("검증 실패:", error.message);
}

// OIDC 유틸리티 직접 사용 (고급 사용법)
import { OIDCUtils } from "flowauth-oauth2-client";

try {
  // RSA 키로 검증
  const rsaPayload = await OIDCUtils.validateAndParseIdTokenWithCrypto(
    idToken,
    "https://your-server.com/.well-known/jwks.json",
    "https://your-server.com", // expected issuer
    "your-client-id", // expected audience
    nonce, // expected nonce (선택사항)
  );

  // 또는 특정 공개키 가져오기 (RSA/ECDSA 자동 감지)
  const publicKey = await OIDCUtils.getPublicKey(
    "https://your-server.com/.well-known/jwks.json",
    "rsa-key-env", // 또는 "ec-key-env"
    "RS256", // 또는 "ES256"
  );
} catch (error) {
  console.error("암호화 검증 실패:", error.message);
}
```

#### 지원되는 암호화 알고리즘

- **RSA (RS256)**: 2048비트 RSA 키와 SHA-256 해시 함수 사용
- **ECDSA (ES256)**: P-256 곡선과 SHA-256 해시 함수 사용

#### 보안 고려사항

- ID 토큰은 항상 HTTPS를 통해 전송되어야 합니다
- nonce 값은 각 인증 요청마다 고유해야 합니다 (CSRF 방지)
- 토큰 검증은 백엔드에서도 수행하는 것을 권장합니다
- JWKS URI는 HTTPS를 사용해야 합니다

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
  OPENID = "openid", // OpenID Connect 인증을 위한 기본 스코프
  PROFILE = "profile", // 사용자 프로필 정보 (이름, 생년월일, 지역, 사진 등) 접근
  EMAIL = "email", // 사용자 이메일 주소 읽기
}
```

**기본 스코프:**

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
- `storage?`: 커스텀 스토리지 구현 (기본값: 브라우저 sessionStorage 또는 Node.js MemoryStorage)
- `autoRefresh?`: 자동 토큰 리프래시 활성화 (기본값: true)

#### 메소드

- `createAuthorizeUrl(scopes?, state?, pkce?, nonce?, responseType?)`: 인증 URL 생성 (기본값: `[OAuth2Scope.PROFILE]`)
- `createSecureAuthorizeUrl(scopes?, responseType?)`: PKCE와 State를 자동 생성하여 보안 인증 URL 생성 (기본값: `[OAuth2Scope.PROFILE]`)
- `exchangeCode(code, codeVerifier?)`: Authorization Code를 토큰으로 교환
- `refreshToken(refreshToken?)`: 토큰 리프래시 (저장된 토큰 자동 사용)
- `validateToken(accessToken?)`: 토큰 유효성 검증
- `getStoredAccessToken()`: 저장된 액세스 토큰 조회
- `getTokenInfo()`: 현재 토큰 정보 조회
- `logout()`: 저장된 토큰 제거

#### 정적 메소드

- `FlowAuthClient.generatePKCE()`: PKCE 챌린지 생성
- `FlowAuthClient.generateState()`: OAuth2 State 파라미터 생성
- `FlowAuthClient.generateSecureAuthParams()`: PKCE와 State를 함께 생성

### 스토리지 클래스

#### MemoryStorage

메모리 기반 스토리지로 애플리케이션 실행 중에만 데이터를 유지합니다.

```typescript
class MemoryStorage implements TokenStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  clear(): void;
}
```

#### FileStorage

JSON 파일에 데이터를 영구 저장하는 스토리지입니다.

```typescript
class FileStorage implements TokenStorage {
  constructor(filePath?: string);
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  clear(): void;
}
```

**파라미터:**

- `filePath`: 토큰을 저장할 파일 경로 (기본값: "./.flowauth-tokens.json")

#### TokenStorage 인터페이스

커스텀 스토리지를 구현하기 위한 인터페이스입니다.

```typescript
interface TokenStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  clear?(): void;
}
```

### 에러 처리

SDK는 `OAuth2Error` 클래스를 사용하여 OAuth2 관련 에러를 제공합니다:

```javascript
import { OAuth2Error } from "flowauth-oauth2-client";
// 또는 CommonJS: const { OAuth2Error } = require("flowauth-oauth2-client");

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
