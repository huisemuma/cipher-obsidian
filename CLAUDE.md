# Cipher Obsidian Plugin

Obsidian 插件，在笔记中加密/解密密码。密码仅存内存，不写入文件，不被同步。

## 构建

```bash
npm install
npm run build
```

产物：`main.js`（连同 `manifest.json`、`styles.css` 复制到 vault 的 `.obsidian/plugins/cipher-decode/`）

## 算法

与 `/cipher/index.html` 完全一致：
- PBKDF2-SHA256, 迭代 100000, 盐值 `"cipher-v1"`
- BASE=33, RANGE=94, FIXED_LEN=18
- 结构: `[1位长度编码 | 明文 | 随机填充]` → 逐字符模运算加密
- 加密: `enc = ((c - 33 + key) % 94 + 94) % 94 + 33`
- 解密: `dec = ((c - 33 - key) % 94 + 94) % 94 + 33`

## 笔记中的格式

- 新格式: `` `🔐<24位base64url>` `` — 密文经 base64url 编码，避免反引号冲突
- 旧格式: `` `cipher:<18位ASCII>` `` — 仍兼容识别

## 插件功能

- **Markdown Post Processor**: 识别 `<code>` 中的密文，替换为遮罩 + 按钮
- **按钮**: 📋 复制（不显示明文）/ 👁 查看切换 / 🔄 重新输入密码
- **命令** `Lock password` (Cmd+P 搜 "Lock"): 在编辑器光标处加密插入密文
- **设置**: 密码超时 0-60 分钟（0=不过期，关闭 Obsidian 才清除）

## 安全设计

- 主密码仅存插件实例变量（JS 堆内存），不存 data.json
- data.json 只存 `{ timeout: number }`
- 解密只改 DOM，不修改 .md 文件

## 文件结构

- `main.ts` — 全部逻辑（加解密、Modal、PostProcessor、设置页）
- `styles.css` — .cipher-container / .cipher-masked / .cipher-revealed / .cipher-eye
- `manifest.json` — 插件元数据 (id: cipher-decode)
- `esbuild.config.mjs` — 构建配置

## 修改注意

- 加解密算法不能改，否则与已有密文和 HTML 工具不兼容
- base64url 编解码函数 `cipherToBase64url` / `base64urlToCipher` 是格式层，不影响加密核心
- 改完后 `npm run build` 然后复制 main.js 到 vault 插件目录
