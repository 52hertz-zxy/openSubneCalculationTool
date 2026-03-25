# 子网计算工具（IPv4/IPv6）绿色版（离线）

完整功能列表与模块说明见：**[功能说明.md](./功能说明.md)**。

## 运行方式

### 1）浏览器（体积最小，约数 MB 以内）

1. 执行 `npm run dist:web`，在 `dist/` 下生成 `SubneCalculationTool-web.zip`（或直接使用仓库内 `index.html` 等静态文件）。
2. 解压后双击 `index.html`，用 Edge / Chrome 等现代浏览器打开即可。

> 说明：**群 Ping 检测**依赖系统 `ping`，**端口扫描**依赖 Electron 主进程 TCP 探测，二者仅在 **Electron 桌面版** 中可用；纯网页版无法使用这两项。

### 2）Electron 桌面版（单文件 exe）

1. 在项目根目录执行：`npm run dist`（会先根据 `assets/app-logo.svg` 生成 `build/icon.ico`，再打包）
2. 产物：`dist/SubneCalculationTool 1.0.0.exe`（便携版）

**桌面 / 任务栏图标**：与主界面左上角 logo 同源，均为 `assets/app-logo.svg`。更换 logo 时替换该 SVG 后重新执行 `npm run dist` 即可；仅本地调试时可单独执行 `npm run build:icon` 以更新窗口图标。

#### Windows 提示「智能应用控制已阻止可能不安全的应用」

双击 exe 时若出现类似提示（例如：**无法确认其编写人**、**不是熟悉的应用**），多为 **未做商业代码签名** 所致，**不是程序损坏**。

1. **解除锁定**：右键 exe → **属性** → 底部 **安全** 勾选 **解除锁定** → 确定后再运行；若来自压缩包，可先对 **zip** 解除锁定再解压。  
2. **仍被拦**：**设置** → **隐私和安全性** → **Windows 安全中心** → **应用和浏览器控制** → **智能应用控制**（或基于信誉的保护）按需调整。*会降低对未知应用的防护，请自行权衡。*  
3. **不改系统策略**：使用 **`npm run dist:web`** 生成的网页包，用浏览器打开 `index.html`（无 exe，一般无此拦截；群 Ping / 端口扫描仅 Electron 版可用）。  
4. **长期**：购买 **Authenticode** 证书并对 exe 签名，可明显减少误拦。

打包完成后，`dist` 目录会生成 **`若无法运行-请先阅读.txt`**，可与 exe 一起发给他人。首次在本机成功启动 Windows 版时，会 **一次性** 弹出简要说明（被拦截时程序尚未运行，无法由程序自身弹出，请先按上文或该 txt 操作）。

#### 关于 exe 体积（为何难以做到约 10MB）

Electron 会打包 **Chromium 内核**，单文件便携 exe 通常在 **约 70～100MB** 量级。  
本项目已尽量缩小体积：

- `compression: maximum`（打包压缩）
- `electronLanguages: ["en-US"]`（去掉多余 Chromium 语言包；界面中文在页面内，不受影响）

若必须 **约 10MB** 分发，请选择 **网页 ZIP**（`dist:web`），或需改用 **Tauri / WebView2** 等方案（需较大改造）。

## 开发调试

```bash
npm install
npm start
```
