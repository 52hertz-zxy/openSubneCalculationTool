/**
 * 从 assets/app-logo.svg 生成 Windows 用 build/icon.ico（供 electron-builder 与窗口图标）。
 * 在 npm run dist 前自动执行；更换左上角 logo 时只需替换 SVG 后重新打包。
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import sharp from "sharp";
import toIco from "to-ico";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const svgPath = path.join(root, "assets", "app-logo.svg");
const outDir = path.join(root, "build");
const outIco = path.join(outDir, "icon.ico");

async function main() {
  if (!fs.existsSync(svgPath)) {
    console.error("缺少图标源文件:", svgPath);
    process.exit(1);
  }
  const svg = fs.readFileSync(svgPath);
  const sizes = [16, 24, 32, 48, 64, 128, 256];
  const buffers = await Promise.all(
    sizes.map((s) =>
      sharp(svg, { density: 300 })
        .resize(s, s, { fit: "contain", background: { r: 0, g: 0, b: 0, alpha: 0 } })
        .png()
        .toBuffer(),
    ),
  );
  const ico = await toIco(buffers);
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(outIco, ico);
  console.log("已生成:", path.relative(root, outIco));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
