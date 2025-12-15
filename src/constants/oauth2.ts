/**
 * OAuth2 스코프 열거형 (OpenID Connect 표준)
 * FlowAuth에서 지원하는 권한 스코프들을 정의합니다.
 */
export enum OAuth2Scope {
  /** OpenID Connect 인증을 위한 기본 스코프 */
  OPENID = "openid",
  /** 사용자 프로필 정보 (이름, 생년월일, 지역, 사진 등) 접근 */
  PROFILE = "profile",
  /** 사용자 이메일 주소 읽기 */
  EMAIL = "email",
}

/**
 * OAuth2 응답 타입 열거형
 */
export enum OAuth2ResponseType {
  /** Authorization Code */
  CODE = "code",
}

/**
 * OAuth2 Grant 타입 열거형
 */
export enum OAuth2GrantType {
  /** Authorization Code Grant */
  AUTHORIZATION_CODE = "authorization_code",
  /** Refresh Token Grant */
  REFRESH_TOKEN = "refresh_token",
  /** Client Credentials Grant */
  CLIENT_CREDENTIALS = "client_credentials",
}

/**
 * OAuth2 토큰 타입 열거형
 */
export enum OAuth2TokenType {
  /** Bearer Token */
  BEARER = "Bearer",
}

/**
 * 기본 스코프 목록
 * 새로운 클라이언트에 기본적으로 부여되는 스코프들입니다.
 */
export const DEFAULT_SCOPES: OAuth2Scope[] = [
  OAuth2Scope.OPENID,
  OAuth2Scope.PROFILE,
];

/**
 * OAuth2 관련 상수들
 */
export const OAUTH2_CONSTANTS = {
  /** 응답 타입들 */
  RESPONSE_TYPES: {
    CODE: OAuth2ResponseType.CODE,
  } as const,
  /** 지원되는 응답 타입들 */
  SUPPORTED_RESPONSE_TYPES: [OAuth2ResponseType.CODE] as const,
  /** 지원되는 Grant 타입들 */
  SUPPORTED_GRANT_TYPES: [
    OAuth2GrantType.AUTHORIZATION_CODE,
    OAuth2GrantType.REFRESH_TOKEN,
    OAuth2GrantType.CLIENT_CREDENTIALS,
  ] as const,

  /** 기본 토큰 만료 시간 (1시간) */
  DEFAULT_TOKEN_EXPIRY_SECONDS: 3600,
  /** Bearer 토큰 타입 (하위 호환성) */
  TOKEN_TYPE_BEARER: OAuth2TokenType.BEARER,
} as const;
