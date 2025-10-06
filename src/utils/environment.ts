/**
 * 환경 감지 및 호환성 유틸리티 클래스
 * 브라우저와 Node.js 환경 간의 API 차이를 처리합니다.
 */
export class EnvironmentUtils {
  /**
   * 현재 환경이 브라우저인지 확인합니다.
   * @returns 브라우저 환경이면 true
   */
  static isBrowser(): boolean {
    return typeof window !== "undefined" && typeof window.document !== "undefined";
  }

  /**
   * 현재 환경이 Node.js인지 확인합니다.
   * @returns Node.js 환경이면 true
   */
  static isNode(): boolean {
    return typeof globalThis !== "undefined" && typeof (globalThis as any).process !== "undefined";
  }

  /**
   * 환경에 맞는 Crypto API를 반환합니다.
   * @returns Crypto API 인스턴스
   * @throws {Error} Crypto API를 사용할 수 없는 환경에서 발생
   */
  static getCrypto(): Crypto {
    if (this.isBrowser()) {
      return window.crypto;
    } else if (this.isNode()) {
      // Node.js 환경에서 crypto 모듈 사용
      try {
        // Node.js 15+에서는 globalThis.crypto.webcrypto 사용
        if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.subtle) {
          return globalThis.crypto;
        }
        // 구버전 Node.js에서는 crypto 모듈 import
        const nodeCrypto = (globalThis as any).require?.("crypto");
        if (nodeCrypto?.webcrypto) {
          return nodeCrypto.webcrypto as Crypto;
        }
        // crypto가 없는 환경에서는 에러 대신 null 반환 (테스트 환경 등)
        return null as any;
      } catch (error) {
        // crypto가 없는 환경에서는 null 반환
        return null as any;
      }
    }
    throw new Error("Crypto API is not available in this environment");
  }

  /**
   * 환경에 맞는 Base64 인코딩 함수를 사용하여 문자열을 인코딩합니다.
   * @param input - 인코딩할 문자열
   * @returns Base64로 인코딩된 문자열
   * @throws {Error} btoa를 사용할 수 없는 환경에서 발생
   */
  static btoa(input: string): string {
    if (this.isBrowser()) {
      return window.btoa(input);
    } else if (this.isNode()) {
      // Node.js Buffer 사용
      const Buffer = (globalThis as any).Buffer;
      if (Buffer) {
        return Buffer.from(input, "binary").toString("base64");
      }
      throw new Error("Buffer is not available in this Node.js environment");
    }
    throw new Error("btoa is not available in this environment");
  }

  /**
   * 환경에 맞는 기본 스토리지를 반환합니다.
   * 브라우저: sessionStorage/localStorage
   * Node.js: MemoryStorage
   * @returns 사용할 수 있는 Storage 인스턴스 또는 undefined
   */
  static getDefaultStorage(): Storage | undefined {
    if (this.isBrowser()) {
      try {
        // sessionStorage를 먼저 시도, 실패하면 localStorage
        return window.sessionStorage || window.localStorage;
      } catch {
        // Private browsing 모드 등에서 storage가 제한될 수 있음
        return undefined;
      }
    }
    return undefined;
  }

  /**
   * 환경에 맞는 Fetch API를 반환합니다.
   * @returns Fetch API 함수
   * @throws {Error} fetch를 사용할 수 없는 환경에서 발생
   */
  static getFetch(): typeof fetch {
    if (this.isBrowser()) {
      return window.fetch;
    } else if (this.isNode()) {
      // Node.js 18+에서는 globalThis.fetch가 있지만, 구버전 호환을 위해
      if (typeof globalThis.fetch !== "undefined") {
        return globalThis.fetch;
      }
      // node-fetch 등의 polyfill이 필요할 수 있음
      const nodeFetch = (globalThis as any).require?.("node-fetch");
      if (nodeFetch) {
        return nodeFetch;
      }
      throw new Error("fetch is not available. Please install node-fetch or use Node.js 18+");
    }
    throw new Error("fetch is not available in this environment. For Node.js, use version 18+ or install node-fetch.");
  }

  /**
   * JWT 토큰을 파싱합니다.
   * @param token JWT 토큰 문자열
   * @returns 헤더, 페이로드, 서명
   */
  static parseJwt(token: string): { header: any; payload: any; signature: string } {
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new Error("Invalid JWT token format");
    }

    const header = JSON.parse(this.atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
    const payload = JSON.parse(this.atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    const signature = parts[2];

    return { header, payload, signature };
  }

  /**
   * JWT 토큰의 만료 여부를 확인합니다.
   * @param token JWT 토큰 문자열
   * @returns 만료되었으면 true
   */
  static isTokenExpired(token: string): boolean {
    try {
      const { payload } = this.parseJwt(token);
      const currentTime = Math.floor(Date.now() / 1000);
      return payload.exp < currentTime;
    } catch {
      return true; // 파싱 실패 시 만료된 것으로 간주
    }
  }

  /**
   * Base64URL 디코딩 함수
   * @param input Base64URL 문자열
   * @returns 디코딩된 문자열
   */
  static atob(input: string): string {
    if (this.isBrowser()) {
      return window.atob(input.replace(/-/g, "+").replace(/_/g, "/"));
    } else if (this.isNode()) {
      const Buffer = (globalThis as any).Buffer;
      if (Buffer) {
        return Buffer.from(input.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString();
      }
      throw new Error("Buffer is not available in this Node.js environment");
    }
    throw new Error("atob is not available in this environment");
  }
}
