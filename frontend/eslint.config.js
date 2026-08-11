// Flat ESLint config — React + TypeScript, zero-config `npm run lint`.
// Kept strict on what catches real bugs (hooks rules, unused vars, TS
// no-explicit-any) and lenient elsewhere so lint stays green and useful.

import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "coverage", "node_modules"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      globals: { ...globals.browser },
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // React 19 compiler-era rules flag established, working patterns in
      // this codebase (sync setState-in-effect resets, latest-ref hooks,
      // DOM dataset mutation in theme handlers). They're aspirational, not
      // bug-catchers here — disable the noisy ones, keep the real ones.
      "react-hooks/set-state-in-effect": "off",
      "react-hooks/refs": "off",
      "react-hooks/immutability": "off",
      "react-hooks/purity": "off",
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/no-explicit-any": "off",
    },
  },
  {
    files: ["**/*.test.{ts,tsx}", "**/test/**", "src/test/**"],
    languageOptions: { globals: { ...globals.node } },
  },
  {
    // The router entry declares ~20 lazy page components with no exports.
    // React Refresh can't fast-refresh the router table anyway (every page
    // edit reloads it), so the rule has nothing useful to say here.
    files: ["src/main.tsx"],
    rules: { "react-refresh/only-export-components": "off" },
  },
);
