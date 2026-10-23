# FlowAuth OAuth2 SDK

FlowAuth Authorization Code + PKCE 연동을 위한 TypeScript/JavaScript 패키지 `flowauth-oauth2-client`입니다. 인증 URL 생성, 코드 교환, UserInfo 조회, 토큰 갱신과 JWKS 기반 ID 토큰 검증을 제공합니다.

## 설치와 실행 환경

```bash
npm install flowauth-oauth2-client
```

산출물은 CommonJS(`dist/index.js`)와 TypeScript 선언입니다. TypeScript/bundler에서는 아래 `import` 예제를 사용하고, CommonJS에서는 `require("flowauth-oauth2-client")`로 가져옵니다. 브라우저에서 사용하려면 번들러가 필요하며, `dist/index.js`를 일반 `<script>` 태그로 로드하는 전역 번들은 제공하지 않습니다.

실행 환경에는 `fetch`, Web Crypto(`crypto.subtle`, `getRandomValues`), `TextEncoder`와 URL API가 필요합니다. 저장소 개발·예제 검증 기준은 통합 루트가 지정하는 Node.js 24.14.1입니다. 구형 Node·브라우저에 대한 지원 범위를 추정하지 말고 배포 대상에서 필요한 API를 확인하세요.

현재 생성자는 `clientSecret`을 필수로 요구하고 토큰 요청에 HTTP Basic 인증을 사용합니다. 아래 예제는 서버 애플리케이션을 기준으로 합니다. 시크릿을 브라우저 번들·공개 환경 변수에 넣지 마세요. 브라우저 런타임 유틸리티가 존재하더라도 현재 클라이언트 API가 시크릿 없는 SPA 연동을 제공하는 것은 아닙니다.

## 서버 연동 순서

1. FlowAuth에 클라이언트를 등록하고 서버 콜백 URI를 정확히 일치시킵니다.
2. `server`, `clientId`, `clientSecret`, `redirectUri`로 설정합니다. 시크릿은 서버 환경 변수/시크릿 저장소에서 읽습니다.
3. 로그인 시작 시 PKCE·state·nonce를 생성하고, 이 값을 짧은 유효기간의 사용자별 서버 세션에 보관합니다.
4. 브라우저를 인증 URL로 리다이렉트합니다.
5. 콜백에서 같은 세션의 값을 한 번만 소비하고 코드 교환·ID 토큰 검증을 수행합니다.

### PKCE와 OIDC 예제

아래 함수는 HTTP 프레임워크와 독립적인 연동 부분입니다. 라우트에서 `beginLogin`의 `pending`을 서버 세션에 저장한 뒤 `authUrl`로 이동시키고, 콜백 라우트에서는 저장값을 꺼내 즉시 제거한 뒤 `finishLogin`에 전달하세요. 세션 쿠키·로그인 결과 처리와 토큰의 안전한 보관은 애플리케이션에서 구현합니다.

```typescript
import {
  FlowAuthClient,
  MemoryStorage,
  OAuth2Scope,
  type OAuth2ClientConfig,
} from "flowauth-oauth2-client";

interface PendingLogin {
  state: string;
  codeVerifier: string;
  nonce: string;
  expiresAt: number;
}

function createClient(config: OAuth2ClientConfig): FlowAuthClient {
  // Isolate token storage for each authentication transaction.
  return new FlowAuthClient({
    ...config,
    storage: new MemoryStorage(),
    autoRefresh: false,
  });
}

export async function beginLogin(config: OAuth2ClientConfig) {
  const client = createClient(config);
  const { pkce, state } = await FlowAuthClient.generateSecureAuthParams();
  const nonce = await FlowAuthClient.generateNonce();
  const authUrl = client.createAuthorizeUrl(
    [OAuth2Scope.OPENID, OAuth2Scope.PROFILE, OAuth2Scope.EMAIL],
    { state, pkce, nonce },
  );

  const pending: PendingLogin = {
    state,
    codeVerifier: pkce.codeVerifier,
    nonce,
    expiresAt: Date.now() + 10 * 60 * 1000,
  };
  return { authUrl, pending };
}

export async function finishLogin(
  config: OAuth2ClientConfig,
  callbackUrl: string,
  pending: PendingLogin | undefined,
) {
  if (
    !pending?.state ||
    !pending.codeVerifier ||
    !pending.nonce ||
    !Number.isFinite(pending.expiresAt) ||
    Date.now() >= pending.expiresAt
  ) {
    throw new Error("Missing or expired login session");
  }

  const client = createClient(config);
  const tokens = await client.handleCallback(
    callbackUrl,
    pending.state,
    pending.codeVerifier,
  );
  if (!tokens.id_token) {
    throw new Error("Missing ID token");
  }

  const identity = await client.validateIdToken(tokens.id_token, pending.nonce);
  const userInfo = await client.getUserInfo();
  if (userInfo.sub !== identity.sub) {
    client.logout();
    throw new Error("UserInfo subject mismatch");
  }
  return { identity, userInfo, tokens };
}
```

`4.3.4`부터 ID 토큰 검증은 `RS256`/`ES256`만 허용하며 서명과 필수 클레임을 함께 검사합니다. `HS256`, 지원하지 않는 알고리즘, 유효하지 않거나 현재 시각에 도달한 만료 시간은 거부합니다. Discovery의 issuer도 설정한 `server`와 정확히 일치해야 합니다. `OIDCUtils.validateAndParseIdToken`은 서명을 검사하지 않는 호환용 클레임 파서이므로 인증 판단에는 사용하지 마세요.

SDK는 state·PKCE·nonce를 콜백 사이에 자동 영속화하지 않습니다. `handleCallback`의 `expectedState`가 비어 있으면 state 검사를 생략하므로, 세션이 없는 콜백을 호출 전에 거부해야 합니다. `exchangeCode`는 ID 토큰을 자동 검증하지 않으며, OIDC에서는 위와 같이 검증 단계를 명시합니다. 예제의 10분은 애플리케이션이 정한 로그인 시도 유효기간입니다.

## 주요 API

정확한 타입은 [`src/types/oauth2.ts`](src/types/oauth2.ts), [`src/types/token.ts`](src/types/token.ts), 구현은 [`src/client/flowauth-client.ts`](src/client/flowauth-client.ts)를 참고하세요.

### 설정

- 필수: `server`, `clientId`, `clientSecret`, `redirectUri`
- `storage?`: 동기식 `TokenStorage` 구현. Node 기본값은 인스턴스별 `MemoryStorage`, 브라우저는 접근 가능한 `sessionStorage` 우선
- `autoRefresh?`: 기본 `true`. 저장된 토큰의 만료를 확인하는 `getUserInfo` 호출 과정에서 갱신하며 백그라운드 타이머는 제공하지 않음

서버에서 하나의 클라이언트/스토리지를 여러 사용자에게 공유하면 토큰이 섞일 수 있습니다. 사용자별로 격리하세요. 기본 메모리 저장소는 프로세스 종료·인스턴스 교체 시 유지되지 않습니다.

### 인가와 콜백

- `createAuthorizeUrl(scopes?, options?)`: `options`는 `{ state?, pkce?, nonce?, responseType? }` 객체. 기본 스코프는 `[OAuth2Scope.PROFILE]`, 기본 응답 타입은 `code`
- `createSecureAuthorizeUrl(scopes?, responseType?)`: `{ authUrl, codeVerifier, state }` 반환. nonce는 생성하지 않으므로 OIDC nonce가 필요하면 위 예제처럼 구성
- `parseCallbackUrl(callbackUrl)`: 코드·state·OAuth 오류를 파싱하며 검증이나 토큰 교환은 수행하지 않음
- `handleCallback(callbackUrl, expectedState?, codeVerifier?)`: OAuth 오류 확인, 전달된 state 비교, 코드 교환
- `exchangeCode(code, codeVerifier?)`: 토큰 교환과 저장
- 정적 메서드: `generatePKCE()`, `generateState()`, `generateNonce()`, `generateSecureAuthParams()`

`OAuth2Scope`는 `OPENID`, `PROFILE`, `EMAIL`, `OFFLINE_ACCESS`를 제공합니다. `DEFAULT_SCOPES`는 openid·profile이지만 메서드의 기본 인자와는 다릅니다. OIDC에서는 `OPENID`를 명시하고, refresh token이 필요하면 `OFFLINE_ACCESS`를 요청한 뒤 실제 서버 응답을 확인하세요.

### 토큰과 사용자 정보

- `getUserInfo(accessToken?)`: UserInfo 조회; 저장된 refresh token과 만료 상태에 따라 자동 갱신 시도
- `refreshToken(refreshToken?, scope?)`: 명시적 갱신. `scope`는 공백 구분 문자열이며 기존 스코프의 부분 집합으로 요청
- `validateToken(accessToken?)`: UserInfo 엔드포인트의 성공 여부를 반환; JWT 서명 검증 메서드가 아님
- `validateIdToken(idToken?, expectedNonce?)`: Discovery/JWKS를 사용해 RSA/ECDSA 서명과 클레임 검증. 콜백 요청 간에는 예상 nonce를 명시적으로 전달
- `getDiscoveryDocument()`: 인스턴스 내에 Discovery 문서를 캐시
- `getStoredAccessToken()`: 만료되지 않은 로컬 access token만 반환; 만료·누락 시 `null`
- `getStoredIdToken()`, `getTokenInfo()`: 로컬 ID 토큰과 토큰 메타데이터 복사본 조회. 반환 자체가 서명 검증이나 갱신을 의미하지 않음
- `logout()`: 저장된 토큰 데이터를 제거. 서버 토큰 폐기·SSO 세션 종료 요청은 수행하지 않음

만료된 access token에 refresh token이 있으면 재생성한 인스턴스에서도 갱신할 수 있도록 보존합니다. 저장된 ID 토큰도 복원하지만, 사용 전에는 `validateIdToken`으로 검증해야 합니다. 유효하지 않은 저장 데이터와 갱신할 수 없는 만료 세션은 제거합니다.

같은 클라이언트 인스턴스에서 동일 세션·refresh token·scope의 동시 갱신은 하나의 요청을 공유합니다. 여러 인스턴스·프로세스가 하나의 토큰 저장소를 공유하는 경우의 동기화는 애플리케이션에서 처리합니다. 진행 중인 요청과 다른 scope의 갱신은 거부합니다. 갱신 응답에서 refresh token이나 ID 토큰이 생략되면 같은 세션의 기존 값을 유지하고, scope가 생략되면 요청한 scope 또는 기존 scope를 유지합니다. 새 코드 교환이나 다른 refresh token으로 시작한 세션에는 이전 ID 토큰·nonce·scope를 넘기지 않습니다. refresh token이 회전되면 새 값을 저장합니다.

`expires_in`은 유한한 0 이상의 초 단위 숫자여야 합니다. `0`은 즉시 만료이며, 생략된 경우 기존 호환 기본값인 3600초를 사용합니다. `getTokenInfo().expires_at`은 밀리초 단위 시각입니다.

`logout()`은 메모리의 토큰·nonce와 진행 중인 요청의 저장 권한을 먼저 제거합니다. 로그아웃 전이나 이전 세션에서 시작한 응답이 나중에 도착해도 세션을 복원하거나 새 세션을 지우지 않습니다. 저장소 삭제가 실패하면 호출부에 오류를 전달하며, 메모리는 이미 비워진 상태입니다. 호출부는 해당 저장소의 영속 데이터 제거 실패를 처리해야 합니다. 저장소 읽기·쓰기가 차단된 환경에서는 인스턴스 메모리만 사용할 수 있으며 새 인스턴스로의 영속화는 보장하지 않습니다.

### 저장소

[`TokenStorage`](src/types/oauth2.ts)는 **동기식** `getItem(key): string | null`, `setItem(key, value): void`, `removeItem(key): void`, 선택적 `clear(): void` 계약입니다. 비동기 Redis 메서드를 그대로 전달할 수 없습니다.

- `MemoryStorage`: 인스턴스 수명 동안 유지
- `FileStorage(path?)`: Node용 JSON 파일 저장소, 기본 경로 `./.flowauth-tokens.json`
- 브라우저 저장소 또는 동기식 사용자 정의 구현

`FileStorage`는 암호화나 다중 프로세스 잠금을 제공하지 않고 파일 오류를 내부에서 처리합니다. 영속화 성공을 보장한다고 가정하지 마세요. 토큰 파일을 Git에 넣지 말고 파일 접근 권한을 제한합니다. 여러 사용자의 서버 세션 저장소로 하나의 기본 파일을 공유하지 않습니다.

### 오류 처리

토큰 교환·UserInfo 등 OAuth 요청 오류는 `OAuth2Error`의 `status`, `code`, `message`로 분기할 수 있습니다. 검증·환경 오류는 일반 `Error`일 수도 있으므로 호출부에서 함께 처리합니다. 로그에 토큰·시크릿·전체 콜백 URL을 기록하지 않습니다.

## 코드 구조

- [`src/index.ts`](src/index.ts): 공개 export
- [`src/client/`](src/client/): OAuth2 클라이언트
- [`src/types/`](src/types/), [`src/constants/`](src/constants/): 타입·스코프·프로토콜 상수
- [`src/utils/`](src/utils/): 실행 환경, OIDC, 저장소
- [`src/errors/`](src/errors/): OAuth 오류
- [`test/`](test/): Vitest 테스트
- `dist/`: `npm run build`로 생성되는 배포 산출물

## 개발과 검증

소스 체크아웃에서는 통합 루트의 Node 버전을 선택한 뒤 실행합니다.

```bash
npm ci
npm run type-check
npm run lint
npm run format:check
npm run test:run
npm run build
```

`npm test`는 감시 모드입니다. `lint:fix`와 `format`은 소스를 수정합니다. 전체 검증 단계는 `prepublishOnly`에도 정의되어 있습니다.

## 릴리즈와 라이선스

통합 저장소의 `AGENTS.md`와 릴리즈 절차를 따릅니다. GitHub 작업은 `gh` CLI를 사용하고 dev → 피처 브랜치 → dev → main → 최신 dev 순서로 전달합니다. 버전 범프 후 `npm i`·`npm ci`와 검증을 마치고, SDK 커밋을 먼저 공개한 뒤 루트 포인터를 갱신합니다.

배포 요청에 따른 GitHub Release 생성과 npm 레지스트리 게시는 별도 작업입니다. `publish:patch`, `publish:minor`, `publish:major`는 버전 변경과 실제 npm 게시를 실행하므로 검증 명령으로 사용하지 않습니다.

라이선스는 [`package.json`](package.json)에 명시된 MIT입니다.
