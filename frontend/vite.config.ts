import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,          // 0.0.0.0 바인딩 (외부 접속용)
    port: 5173,
    strictPort: true,
    proxy: {
      '/analyze': 'http://localhost:8080',
      '/jobs': 'http://localhost:8080',
    },
  },
})