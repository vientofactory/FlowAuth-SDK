/**
 * Node.js 환경용 스토리지 구현체들
 * 브라우저와 Node.js 환경 모두에서 사용할 수 있는 토큰 저장소
 */
import { TokenStorage } from "../types/oauth2";
import { EnvironmentUtils } from "./environment";

/**
 * 메모리 기반 스토리지
 * 애플리케이션 실행 중에만 유지되는 임시 저장소
 */
export class MemoryStorage implements TokenStorage {
  private data: Map<string, string> = new Map();

  getItem(key: string): string | null {
    return this.data.get(key) || null;
  }

  setItem(key: string, value: string): void {
    this.data.set(key, value);
  }

  removeItem(key: string): void {
    this.data.delete(key);
  }

  clear(): void {
    this.data.clear();
  }
}

/**
 * 파일 기반 스토리지
 * JSON 파일에 데이터를 영구 저장
 */
export class FileStorage implements TokenStorage {
  private filePath: string;
  private data: Map<string, string> = new Map();
  private fs: any = null;

  constructor(filePath: string = "./.flowauth-tokens.json") {
    this.filePath = filePath;
    this.initializeFs();
    this.loadFromFile();
  }

  private initializeFs(): void {
    if (EnvironmentUtils.isNode()) {
      try {
        this.fs = require("fs");
      } catch (error) {
        // fs 모듈을 사용할 수 없는 환경
        console.warn("FileStorage: fs module not available, falling back to memory storage");
      }
    }
  }

  private loadFromFile(): void {
    if (!this.fs) return;

    try {
      if (this.fs.existsSync(this.filePath)) {
        const content = this.fs.readFileSync(this.filePath, "utf8");
        const parsed = JSON.parse(content);
        this.data = new Map(Object.entries(parsed));
      }
    } catch (error) {
      console.warn("Failed to load tokens from file:", error);
    }
  }

  private saveToFile(): void {
    if (!this.fs) return;

    try {
      const obj = Object.fromEntries(this.data);
      this.fs.writeFileSync(this.filePath, JSON.stringify(obj, null, 2));
    } catch (error) {
      console.warn("Failed to save tokens to file:", error);
    }
  }

  getItem(key: string): string | null {
    return this.data.get(key) || null;
  }

  setItem(key: string, value: string): void {
    this.data.set(key, value);
    this.saveToFile();
  }

  removeItem(key: string): void {
    this.data.delete(key);
    this.saveToFile();
  }

  clear(): void {
    this.data.clear();
    this.saveToFile();
  }
}

/**
 * 환경에 맞는 기본 스토리지를 반환
 * 브라우저: sessionStorage
 * Node.js: MemoryStorage
 */
export function getDefaultStorage(): TokenStorage | undefined {
  if (EnvironmentUtils.isBrowser()) {
    try {
      return window.sessionStorage || window.localStorage;
    } catch {
      return undefined;
    }
  } else if (EnvironmentUtils.isNode()) {
    return new MemoryStorage();
  }
  return undefined;
}
