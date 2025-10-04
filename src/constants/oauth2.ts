/**
 * OAuth2 스코프 열거형
 * FlowAuth에서 지원하는 권한 스코프들을 정의합니다.
 */
export enum OAuth2Scope {
  /** OpenID Connect 인증을 위한 기본 스코프 */
  OPENID = "openid",
  /** 사용자 프로필 정보 (이름, 생년월일, 지역, 사진 등) 접근 */
  PROFILE = "profile",
  /** 사용자 이메일 주소 읽기 */
  EMAIL = "email",
  /** 계정의 기본 정보 읽기 (사용자 ID, 이름 등) - 레거시 */
  IDENTIFY = "identify",
}

/**
 * 기본 스코프 목록
 * 새로운 클라이언트에 기본적으로 부여되는 스코프들입니다.
 */
export const DEFAULT_SCOPES: OAuth2Scope[] = [OAuth2Scope.OPENID, OAuth2Scope.PROFILE];

/**
 * OAuth2 관련 상수들
 */
export const OAUTH2_CONSTANTS = {
  /** 기본 토큰 만료 시간 (1시간) */
  DEFAULT_TOKEN_EXPIRY_SECONDS: 3600,
  /** Bearer 토큰 타입 */
  TOKEN_TYPE_BEARER: "Bearer",
} as const;
