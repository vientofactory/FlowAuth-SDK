# FlowAuth OAuth2 SDK

FlowAuth와의 OAuth2 통합을 위한 간단한 TypeScript/JavaScript SDK입니다.

## 특징

- OAuth2 Authorization Code Grant 플로우 지원
- PKCE (Proof Key for Code Exchange) 지원
- TypeScript 타입 정의 제공
- 에러 처리 강화
- 간단한 최소 구현

## 설치

### npm을 사용하는 경우

```bash
npm install flowauth-oauth2-sdk
```

## 사용법

```javascript
const FlowAuthClient = require("flowauth-oauth2-sdk");

// 또는 TypeScript에서
// import FlowAuthClient from "flowauth-oauth2-sdk";

// 클라이언트 초기화
const client = new FlowAuthClient({
  server: "https://example.com",
  clientId: "client-id",
  clientSecret: "client-secret",
  redirectUri: "https://example.com/callback",
});

// 1. 인증 URL 생성
const authUrl = client.createAuthorizeUrl(["read:user", "email"]);
console.log("인증 URL:", authUrl);

// 사용자를 authUrl로 리다이렉트

// 2. 콜백에서 코드 교환
try {
  const tokens = await client.exchangeCode("authorization-code-from-callback");
  console.log("Tokens:", tokens);
} catch (error) {
  console.error("Token exchange failed:", error);
}

// 3. 사용자 정보 조회
const userInfo = await client.getUserInfo(tokens.access_token);

// 4. 토큰 리프래시 (필요시)
const newTokens = await client.refreshToken(tokens.refresh_token);

// 5. PKCE 사용 예제
const pkce = await FlowAuthClient.generatePKCE();
const authUrlWithPKCE = client.createAuthorizeUrl(["read:user"], null, pkce.codeChallenge);
// ... 이후 exchangeCode에 codeVerifier 전달
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

자세한 API 문서와 OAuth2 플로우 설명은 [OAUTH2_GUIDE.md](../OAUTH2_GUIDE.md)를 참조하세요.

## 라이선스

이 SDK는 FlowAuth 프로젝트의 일부입니다. 라이선스 정보는 [LICENSE](../LICENSE)를 참조하세요.
