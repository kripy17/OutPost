/// <reference types="vitest/config" />
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

/**
 * Preload the Overview route chunk into index.html at build time.
 *
 * The Overview is the initial route, but its chunk is loaded via a dynamic
 * import — the browser fetches it only AFTER the main chunk executes and the
 * router resolves, queueing it behind fonts/streams on the 6-connection
 * HTTP/1.1 pool (measured: the chunk fetch pushed the shell's session-count
 * commit past ~300ms). modulepreload moves the fetch to HTML-parse time so
 * the chunk is cached before the router asks for it — the fetch leaves the
 * critical path entirely.
 */
function preloadOverviewChunk(): Plugin {
  return {
    name: "preload-overview-chunk",
    apply: "build",
    transformIndexHtml(html, ctx) {
      // ctx.bundle (build only) holds the generated chunks — find the
      // Overview's hashed file and preload it from HTML-parse time.
      const bundle = (ctx as { bundle?: Record<string, { type?: string }> }).bundle;
      if (!bundle) return html;
      console.error("preload plugin: bundleKeys=", JSON.stringify(Object.keys(bundle).slice(0, 10)));
      const entry = Object.keys(bundle).find(
        (n) => n.endsWith(".js") && n.includes("/overview-"),
      );
      if (!entry) return html;
      return html.replace(
        "<head>",
        `<head>\n    <link rel="modulepreload" href="/${entry}" />`,
      );
    },
  };
}

export default defineConfig({
  plugins: [react(), tailwindcss(), preloadOverviewChunk()],
  server: {
    port: 5173,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
