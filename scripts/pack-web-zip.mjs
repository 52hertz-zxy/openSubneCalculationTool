/**
 * 打包「纯网页离线版」ZIP（不含 Electron），体积通常在数 MB 以内。
 * 用法：npm run dist:web
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const distDir = path.join(root, "dist");
const staging = path.join(distDir, "_web-staging");
const zipPath = path.join(distDir, "SubneCalculationTool-web.zip");

const FILES = [
  "index.html",
  "styles.css",
  "app.js",
  "netcalc.js",
  "ip_geo_db.js",
  "README.md",
  "assets/app-logo.svg",
];

function main() {
  if (!fs.existsSync(distDir)) fs.mkdirSync(distDir, { recursive: true });
  fs.rmSync(staging, { recursive: true, force: true });
  fs.mkdirSync(staging, { recursive: true });

  for (const name of FILES) {
    const src = path.join(root, name);
    if (!fs.existsSync(src)) {
      console.error("缺少文件:", src);
      process.exit(1);
    }
    const dest = path.join(staging, name);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(src, dest);
  }

  if (fs.existsSync(zipPath)) fs.unlinkSync(zipPath);

  try {
    execFileSync("tar", ["-a", "-c", "-f", zipPath, "-C", staging, "."], {
      stdio: "inherit",
      cwd: root,
    });
  } catch {
    const ps = [
      "Compress-Archive",
      "-Path",
      `${staging}\\*`,
      "-DestinationPath",
      zipPath,
      "-Force",
    ].join(" ");
    execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ps], {
      stdio: "inherit",
    });
  }

  fs.rmSync(staging, { recursive: true, force: true });
  const bytes = fs.statSync(zipPath).size;
  console.log(`已生成: ${zipPath}`);
  console.log(`大小: ${(bytes / (1024 * 1024)).toFixed(2)} MB`);
}

main();
