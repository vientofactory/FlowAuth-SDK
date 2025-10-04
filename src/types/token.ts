/**
 * OAuth2 토큰 응답 인터페이스
 */
export interface TokenResponse {
  /** 액세스 토큰 */
  access_token: string;
  /** 리프래시 토큰 (선택적) */
  refresh_token?: string;
  /** ID 토큰 (OIDC 사용 시) */
  id_token?: string;
  /** 토큰 타입 (일반적으로 "Bearer") */
  token_type: string;
  /** 토큰 만료까지 남은 시간(초) */
  expires_in?: number;
  /** 토큰에 부여된 스코프 */
  scope?: string;
  /** 토큰 만료 시각 (Unix timestamp, 내부 사용) */
  expires_at?: number;
}

/**
 * 사용자 정보 인터페이스
 */
export interface UserInfo {
  /** 사용자 고유 식별자 */
  sub: string;
  /** 사용자 이메일 (선택적) */
  email?: string;
  /** 사용자 이름 (선택적) */
  username?: string;
  /** 추가 사용자 정보 (확장 가능) */
  [key: string]: any;
}

/**
 * 토큰 저장소 인터페이스
 */
export interface TokenStorage {
  /** 액세스 토큰 */
  access_token: string;
  /** 리프래시 토큰 (선택적) */
  refresh_token?: string;
  /** ID 토큰 (OIDC 사용 시) */
  id_token?: string;
  /** 토큰 타입 */
  token_type: string;
  /** 토큰 만료 시각 (Unix timestamp) */
  expires_at: number;
  /** 토큰 스코프 */
  scope?: string;
}
