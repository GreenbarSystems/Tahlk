import { defineConfig } from 'vite';

export default defineConfig(({ mode }) => {
  const isSolo = mode === 'solo';
  return {
    // Keep Rust/cargo logs visible in the tauri dev terminal.
    clearScreen: false,
    server: {
      // tauri.conf.json devUrl pins port 5173 — fail loudly if it's taken
      // rather than silently shifting and breaking the window's load URL.
      port: 5173,
      strictPort: true,
      // Never watch the Rust build tree: target/ churns DLLs the linker holds
      // open, and watching them throws EBUSY and kills the dev server.
      watch: {
        ignored: ['**/src-tauri/**'],
      },
    },
    build: {
      outDir: isSolo ? 'dist-solo' : 'dist-group',
      emptyOutDir: true,
      rollupOptions: {
        input: isSolo ? 'solo.html' : 'group.html',
      },
    },
  };
});
