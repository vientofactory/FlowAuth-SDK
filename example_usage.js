import { FlowAuthClient, OAuth2Scope } from "./dist/index.js";
import { createInterface } from "readline";

const server = "http://localhost:3000";
const redirectUri = "http://localhost:5173/callback";
const clientId = "495216108970708992";
const clientSecret =
  "4e6ce281d945ebba2c5fdd38a07d4c3b76179dd83ec547d86da0422566b8b857";

async function createSecureOIDCAuthorization() {
  const client = new FlowAuthClient({
    server,
    clientId,
    clientSecret,
    redirectUri,
  });

  try {
    const { authUrl, codeVerifier, nonce } =
      await client.createSecureOIDCAuthorizeUrl([
        OAuth2Scope.OPENID,
        OAuth2Scope.PROFILE,
        OAuth2Scope.EMAIL,
      ]);
    console.log("인증 URL:", authUrl);

    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    rl.question("Authorization Code를 입력하세요: ", async code => {
      try {
        const token = await client.exchangeCode(code, codeVerifier);
        console.log("토큰 교환 결과: ", token);
        const profile = await client.getUserInfo(token.access_token);
        console.log("프로필 가져오기 결과: ", profile);
        const validateIdToken = await client.validateIdToken(
          token.id_token,
          nonce,
        );
        console.log("ID 토큰 검증 결과:", validateIdToken);
      } catch (e) {
        console.error("오류: ", e);
      }
      rl.close();
    });
  } catch (e) {
    console.error("초기화 오류:", e);
  }
}

function createOIDCAuthorization() {
  const client = new FlowAuthClient({
    server,
    clientId,
    clientSecret,
    redirectUri,
  });

  try {
    const authUrl = client.createOIDCAuthorizeUrl([
      OAuth2Scope.OPENID,
      OAuth2Scope.PROFILE,
      OAuth2Scope.EMAIL,
    ]);
    console.log("인증 URL:", authUrl);

    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    rl.question("Authorization Code를 입력하세요: ", async code => {
      try {
        const token = await client.exchangeCode(code);
        console.log("토큰 교환 결과: ", token);
        const profile = await client.getUserInfo(token.access_token);
        console.log("프로필 가져오기 결과: ", profile);
        const validateIdToken = await client.validateIdToken(token.id_token);
        console.log("ID 토큰 검증 결과:", validateIdToken);
      } catch (e) {
        console.error("오류: ", e);
      }
      rl.close();
    });
  } catch (e) {
    console.error("초기화 오류:", e);
  }
}

function createAuthorizeUrl() {
  const client = new FlowAuthClient({
    server,
    clientId,
    clientSecret,
    redirectUri,
  });

  try {
    const authUrl = client.createAuthorizeUrl([
      OAuth2Scope.OPENID,
      OAuth2Scope.PROFILE,
      OAuth2Scope.EMAIL,
    ]);
    console.log("인증 URL:", authUrl);

    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    rl.question("Authorization Code를 입력하세요: ", async code => {
      try {
        const token = await client.exchangeCode(code);
        console.log("토큰 교환 결과: ", token);
        const profile = await client.getUserInfo(token.access_token);
        console.log("프로필 가져오기 결과: ", profile);
      } catch (e) {
        console.error("오류: ", e);
      }
      rl.close();
    });
  } catch (e) {
    console.error("초기화 오류:", e);
  }
}

async function createSecureAuthorizeUrl() {
  const client = new FlowAuthClient({
    server,
    clientId,
    clientSecret,
    redirectUri,
  });

  try {
    const { authUrl, codeVerifier } = await client.createSecureAuthorizeUrl([
      OAuth2Scope.OPENID,
      OAuth2Scope.PROFILE,
      OAuth2Scope.EMAIL,
    ]);
    console.log("인증 URL:", authUrl);

    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    rl.question("Authorization Code를 입력하세요: ", async code => {
      try {
        const token = await client.exchangeCode(code, codeVerifier);
        console.log("토큰 교환 결과: ", token);
        const profile = await client.getUserInfo(token.access_token);
        console.log("프로필 가져오기 결과: ", profile);
      } catch (e) {
        console.error("오류: ", e);
      }
      rl.close();
    });
  } catch (e) {
    console.error("초기화 오류:", e);
  }
}

createSecureOIDCAuthorization();
