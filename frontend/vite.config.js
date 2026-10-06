import fs from 'node:fs'
import path from 'node:path'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Dev server runs over HTTPS with the same local cert as the backend (SR-16)
// and proxies /api to Flask, so the browser only ever talks to one origin.
// The cert is only needed for `npm run dev`, not for `npm run build`.
const certDir = path.resolve(__dirname, '../backend/instance/certs')

export default defineConfig(({ command }) => ({
  plugins: [react()],
  server: command !== 'serve' ? undefined : {
    port: 5173,
    strictPort: true,
    https: {
      cert: fs.readFileSync(path.join(certDir, 'cert.pem')),
      key: fs.readFileSync(path.join(certDir, 'key.pem')),
    },
    proxy: {
      '/api': {
        target: 'https://127.0.0.1:5000',
        secure: false, // self-signed dev cert only
      },
    },
  },
}))
