/**
 * 범용 스토리지 인터페이스
 * 브라우저와 Node.js 환경 모두에서 사용할 수 있는 스토리지 인터페이스
 */
export interface TokenStorage {
  /** 키에 해당하는 값 가져오기 */
  getItem(key: string): string | null;
  /** 키-값 쌍 저장 */
  setItem(key: string, value: string): void;
  /** 키에 해당하는 값 제거 */
  removeItem(key: string): void;
  /** 모든 데이터 제거 */
  clear?(): void;
}

/**
 * OAuth2 클라이언트 설정 인터페이스
 */
export interface OAuth2ClientConfig {
  /** FlowAuth 백엔드 서버 URL */
  server: string;
  /** OAuth2 클라이언트 ID */
  clientId: string;
  /** OAuth2 클라이언트 시크릿 */
  clientSecret: string;
  /** 인증 후 리다이렉트될 URI */
  redirectUri: string;
  /** 토큰 저장을 위한 스토리지 (기본값: 브라우저 sessionStorage 또는 Node.js MemoryStorage) */
  storage?: TokenStorage;
  /** 자동 토큰 리프래시 활성화 여부 (기본값: true) */
  autoRefresh?: boolean;
}

/**
 * PKCE (Proof Key for Code Exchange) 코드 객체 인터페이스
 */
export interface PKCECodes {
  /** PKCE 코드 검증자 */
  codeVerifier: string;
  /** PKCE 코드 챌린지 */
  codeChallenge: string;
  /** 코드 챌린지 메소드 (기본값: "S256") */
  codeChallengeMethod?: string;
}

/**
 * OIDC ID 토큰 페이로드 인터페이스
 */
export interface IdTokenPayload {
  /** 발급자 (Issuer) */
  iss: string;
  /** 대상자 (Audience) */
  aud: string;
  /** 만료 시간 (Expiration Time) */
  exp: number;
  /** 발급 시간 (Issued At) */
  iat: number;
  /** 주체 (Subject) - 사용자 ID */
  sub: string;
  /** 인증 시간 (Authentication Time) */
  auth_time?: number;
  /** Nonce 값 (Replay Attack 방지) */
  nonce?: string;
  /** 인증 컨텍스트 클래스 참조 */
  acr?: string;
  /** 허용된 인증 방법 */
  amr?: string[];
  /** 권한 부여자 */
  azp?: string;
  /** 추가 클레임들 */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

/**
 * JWKS (JSON Web Key Set) 키 인터페이스
 */
export interface JWKSKey {
  /** 키 타입 (RSA, EC) */
  kty: string;
  /** 키 ID */
  kid: string;
  /** 키 사용 목적 (sig, enc) */
  use?: string;
  /** 알고리즘 */
  alg: string;

  // RSA 키 매개변수
  /** RSA 모듈러스 (Base64URL) */
  n?: string;
  /** RSA 공개 지수 (Base64URL) */
  e?: string;

  // ECDSA 키 매개변수
  /** 타원 곡선 (P-256, P-384, P-521) */
  crv?: string;
  /** X 좌표 (Base64URL) */
  x?: string;
  /** Y 좌표 (Base64URL) */
  y?: string;
}

/**
 * JWKS 응답 인터페이스
 */
export interface JWKSResponse {
  keys: JWKSKey[];
}

/**
 * OAuth2 콜백 파라미터 인터페이스
 */
export interface OAuth2CallbackParams {
  /** Authorization Code (Authorization Code Grant) */
  code?: string;
  /** State 파라미터 (CSRF 방지) */
  state?: string;
  /** 에러 코드 */
  error?: string;
  /** 에러 설명 */
  errorDescription?: string;
}

/**
 * OIDC Discovery 문서 인터페이스
 */
export interface OIDCDiscoveryDocument {
  /** 발급자 */
  issuer: string;
  /** 인증 엔드포인트 */
  authorization_endpoint: string;
  /** 토큰 엔드포인트 */
  token_endpoint: string;
  /** UserInfo 엔드포인트 */
  userinfo_endpoint: string;
  /** JWKS URI */
  jwks_uri: string;
  /** 지원하는 스코프들 */
  scopes_supported: string[];
  /** 지원하는 응답 타입들 */
  response_types_supported: string[];
  /** 지원하는 토큰 엔드포인트 인증 방법들 */
  token_endpoint_auth_methods_supported: string[];
  /** 지원하는 ID 토큰 서명 알고리즘들 */
  id_token_signing_alg_values_supported: string[];
  /** 지원하는 클레임들 */
  claims_supported: string[];
}
