const js = require("@eslint/js");
const tsParser = require("@typescript-eslint/parser");
const tsPlugin = require("@typescript-eslint/eslint-plugin");
const prettierPlugin = require("eslint-plugin-prettier");
const prettierConfig = require("eslint-config-prettier");
const globals = require("globals");

const sharedRules = {
  // Prettier
  "prettier/prettier": "error",

  // TypeScript (the base rule cannot understand type-only usage)
  "no-unused-vars": "off",
  "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
  "@typescript-eslint/no-explicit-any": "warn",

  // General
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
};

module.exports = [
  {
    ignores: [
      "dist/",
      "build/",
      "coverage/",
      "node_modules/",
      "logs/",
      "*.log",
      "*.tsbuildinfo",
      ".vitest/",
    ],
  },
  js.configs.recommended,
  prettierConfig,
  {
    files: ["src/**/*.ts", "test/**/*.ts"],
    languageOptions: {
      parser: tsParser,
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        ...globals.browser,
        ...globals.node,
        globalThis: "readonly",
      },
    },
    plugins: {
      "@typescript-eslint": tsPlugin,
      prettier: prettierPlugin,
    },
    rules: sharedRules,
  },
  {
    files: ["test/**/*.ts"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "no-console": "off",
    },
  },
];
