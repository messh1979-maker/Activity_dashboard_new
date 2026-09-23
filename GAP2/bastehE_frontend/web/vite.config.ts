import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from 'tailwindcss'
import autoprefixer from 'autoprefixer'
import { fileURLToPath } from 'url'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: '/',
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    rollupOptions: {
      output: {
        assetFileNames: (assetInfo) => {
          const extType = assetInfo.name.split('.').at(1) || 'file'
          let typeCategory = 'assets'
          if (['png', 'jpg', 'jpeg', 'svg', 'gif', 'tiff', 'bmp', 'ico'].includes(extType)) {
            typeCategory = 'assets/images'
          } else if (extType === 'css') {
            typeCategory = 'assets/css'
          } else if (/\.js$/.test(assetInfo.name)) {
            typeCategory = 'assets/js'
          }
          return `${typeCategory}/[name]-[hash][extname]`
        },
      },
    },
    css: {
      postcss: {
        plugins: [tailwindcss(), autoprefixer()],
      },
    },
  },
  server: {
    port: 3000,
    host: '127.0.0.1',
  },
  preview: {
    port: 4000,
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
})