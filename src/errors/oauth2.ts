/**
 * OAuth2 관련 에러 클래스
 */
export class OAuth2Error extends Error {
  /**
   * OAuth2Error 생성자
   * @param message - 에러 메시지
   * @param status - HTTP 상태 코드 (선택적)
   * @param code - OAuth2 에러 코드 (선택적)
   */
  constructor(message: string, public status?: number, public code?: string) {
    super(message);
    this.name = "OAuth2Error";
  }
}
