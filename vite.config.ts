import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';
import {defineConfig} from 'vite';

const CESIUM_STATIC_DIRS = ['Workers', 'ThirdParty', 'Assets', 'Widgets'];

export default defineConfig(() => {
  return {
    plugins: [
      react(),
      tailwindcss(),
      {
        name: 'cesium-static-assets',
        configureServer(server) {
          const cesiumRoot = path.resolve(__dirname, 'node_modules/cesium/Build/Cesium');
          server.middlewares.use('/cesium', (req, res, next) => {
            const rawUrl = (req.url || '/').split('?')[0];
            const safeRelative = rawUrl.replace(/^\/+/, '');
            const resolved = path.resolve(cesiumRoot, safeRelative);
            if (!resolved.startsWith(cesiumRoot + path.sep) || !fs.existsSync(resolved) || fs.statSync(resolved).isDirectory()) {
              next();
              return;
            }
            const ext = path.extname(resolved).toLowerCase();
            const mimeMap: Record<string, string> = {
              '.js': 'application/javascript',
              '.mjs': 'application/javascript',
              '.css': 'text/css',
              '.json': 'application/json',
              '.png': 'image/png',
              '.jpg': 'image/jpeg',
              '.jpeg': 'image/jpeg',
              '.svg': 'image/svg+xml',
              '.wasm': 'application/wasm',
              '.xml': 'application/xml',
              '.glsl': 'text/plain',
            };
            res.setHeader('Content-Type', mimeMap[ext] || 'application/octet-stream');
            fs.createReadStream(resolved).pipe(res);
          });
        },
        closeBundle(error?: Error): void {
          if (error) return;
          const distDir = path.resolve(__dirname, 'dist');
          const cesiumSrc = path.resolve(__dirname, 'node_modules/cesium/Build/Cesium');
          const cesiumDest = path.resolve(distDir, 'cesium');
          if (fs.existsSync(distDir) && fs.existsSync(cesiumSrc)) {
            fs.mkdirSync(cesiumDest, {recursive: true});
            for (const dir of CESIUM_STATIC_DIRS) {
              const src = path.join(cesiumSrc, dir);
              const dest = path.join(cesiumDest, dir);
              if (fs.existsSync(src)) {
                fs.cpSync(src, dest, {recursive: true, force: true});
              }
            }
          }
        },
      },
      {
        name: 'copy-unbundled-src-assets',
        apply: 'build',
        closeBundle(error?: Error): void {
          if (error) {
            return;
          }
          const distDir = path.resolve(__dirname, 'dist');
          const srcAssets = path.resolve(__dirname, 'src/assets');
          const distAssets = path.resolve(distDir, 'src/assets');
          if (fs.existsSync(distDir) && fs.existsSync(srcAssets)) {
            fs.cpSync(srcAssets, distAssets, {recursive: true, force: true});
          }
        },
      },
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    build: {
      chunkSizeWarningLimit: 4000,
    },
    server: {
      hmr: process.env.DISABLE_HMR !== 'true',
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
