import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],

  server: {
    port: 5173,

    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5055',
        changeOrigin: true,
      },

      '/jobs': {
        target: 'http://127.0.0.1:5055',
        changeOrigin: true,
      },

      '/analyze': {
        target: 'http://127.0.0.1:5055',
        changeOrigin: true,
      },
    },
  },
})