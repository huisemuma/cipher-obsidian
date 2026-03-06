import esbuild from "esbuild";
import { existsSync } from "fs";

const watch = process.argv.includes("--watch");

const ctx = await esbuild.context({
  entryPoints: ["main.ts"],
  bundle: true,
  external: ["obsidian", "electron", "@codemirror/*"],
  format: "cjs",
  target: "es2020",
  outfile: "main.js",
  sourcemap: false,
  logLevel: "info",
});

if (watch) {
  await ctx.watch();
  console.log("Watching...");
} else {
  await ctx.rebuild();
  await ctx.dispose();
}
