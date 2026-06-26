import { defineConfig } from 'vite';

export default defineConfig(({ mode }) => {
  const isSolo = mode === 'solo';
  return {
    build: {
      outDir: isSolo ? 'dist-solo' : 'dist-group',
      emptyOutDir: true,
      rollupOptions: {
        input: isSolo ? 'solo.html' : 'group.html',
      },
    },
  };
});
