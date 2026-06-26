import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{js,jsx}'],
    extends: [
      js.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      globals: globals.browser,
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
  },
  {
    // Build/config files run in Node — allow node globals (process, fs, etc.).
    files: ['vite.config.js'],
    languageOptions: { globals: globals.node },
  },
  {
    // Vendored shadcn/ui primitives — keep generator output verbatim.
    // They import the `React` namespace by convention and co-export `cva`
    // variant constants alongside components; both are intentional here.
    files: ['src/components/ui/**/*.{js,jsx}'],
    rules: {
      'no-unused-vars': ['error', { varsIgnorePattern: '^React$' }],
      'react-refresh/only-export-components': 'off',
    },
  },
])
