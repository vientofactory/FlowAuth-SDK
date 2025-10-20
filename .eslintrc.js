module.exports = {
  root: true,
  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: "module",
  },
  plugins: ["@typescript-eslint", "prettier"],
  extends: ["eslint:recommended", "prettier"],
  env: {
    browser: true,
    node: true,
    es2022: true,
  },
  globals: {
    globalThis: "readonly",
  },
  rules: {
    // Prettier 관련
    "prettier/prettier": "error",

    // TypeScript 관련 (플러그인 규칙을 수동으로 활성화)
    "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
    "@typescript-eslint/no-explicit-any": "warn",

    // 일반 규칙
    "no-console": "warn",
    "prefer-const": "error",
    "no-var": "error",
    "object-shorthand": "error",
    "prefer-arrow-callback": "error",
    "arrow-spacing": "error",
    "no-multiple-empty-lines": ["error", { max: 2, maxEOF: 1 }],
    "eol-last": "error",
    "comma-dangle": ["error", "always-multiline"],
    semi: ["error", "always"],
    quotes: ["error", "double", { avoidEscape: true }],
  },
  overrides: [
    {
      files: ["test/**/*.ts"],
      rules: {
        "@typescript-eslint/no-explicit-any": "off",
        "no-console": "off",
      },
    },
  ],
  ignorePatterns: ["dist/", "node_modules/", "*.js", "!.eslintrc.js"],
};
