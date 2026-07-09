import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  // Electron loads the built index.html via file://, not http://, so
  // asset URLs must be relative ('./assets/...') rather than absolute
  // ('/assets/...') or the script/stylesheet tags silently fail to
  // resolve and the window renders blank.
  base: './',
  plugins: [react()],
})
