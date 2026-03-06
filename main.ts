import { Plugin, Modal, App, Editor, PluginSettingTab, Setting, MarkdownPostProcessorContext, MarkdownRenderChild } from "obsidian";

// --- Cipher constants (must match the HTML tool) ---
const BASE = 33;
const RANGE = 94;
const FIXED_LEN = 18;
const MAX_INPUT = FIXED_LEN - 1;

// New format: 🔐 + 24 base64url chars
// Old format (compat): cipher: + 18 raw ASCII chars
const PREFIX = "\uD83D\uDD10";
const NEW_RE = /^\uD83D\uDD10([A-Za-z0-9_-]{24})$/;
const OLD_RE = /^\s*cipher:(.{18})\s*$/;

// --- Base64url encoding for ciphertext ---
function cipherToBase64url(raw: string): string {
	const bytes = new Uint8Array(raw.length);
	for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
	let b64 = btoa(String.fromCharCode(...bytes));
	return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64urlToCipher(encoded: string): string {
	let b64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
	while (b64.length % 4) b64 += "=";
	return atob(b64);
}

// --- PBKDF2 key derivation (same as HTML tool) ---
async function deriveKeyBytes(password: string, length: number): Promise<Uint8Array> {
	const enc = new TextEncoder();
	const keyMaterial = await crypto.subtle.importKey(
		"raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]
	);
	const numBits = Math.ceil(length / 32) * 256;
	const bits = await crypto.subtle.deriveBits(
		{ name: "PBKDF2", salt: enc.encode("cipher-v1"), iterations: 100000, hash: "SHA-256" },
		keyMaterial,
		numBits
	);
	return new Uint8Array(bits).slice(0, length);
}

// --- Decrypt (same algorithm as HTML tool) ---
async function decrypt(ciphertext: string, password: string): Promise<string> {
	const keyBytes = await deriveKeyBytes(password, FIXED_LEN);
	let decrypted = "";
	for (let i = 0; i < FIXED_LEN; i++) {
		const c = ciphertext.charCodeAt(i);
		const k = keyBytes[i] % RANGE;
		decrypted += String.fromCharCode(((c - BASE - k) % RANGE + RANGE) % RANGE + BASE);
	}
	let len = decrypted.charCodeAt(0) - BASE;
	if (len < 0 || len > MAX_INPUT) len = MAX_INPUT;
	return decrypted.slice(1, 1 + len);
}

// --- Encrypt (same algorithm as HTML tool) ---
async function encrypt(plaintext: string, password: string): Promise<string> {
	for (let i = 0; i < plaintext.length; i++) {
		const c = plaintext.charCodeAt(i);
		if (c < BASE || c > BASE + RANGE - 1) {
			throw new Error(`Unsupported character: ${plaintext[i]}`);
		}
	}
	if (plaintext.length > MAX_INPUT) throw new Error(`Max length is ${MAX_INPUT}`);

	const lenChar = String.fromCharCode(plaintext.length + BASE);
	let padded = lenChar + plaintext;
	while (padded.length < FIXED_LEN) {
		padded += String.fromCharCode(Math.floor(Math.random() * RANGE) + BASE);
	}

	const keyBytes = await deriveKeyBytes(password, FIXED_LEN);
	let result = "";
	for (let i = 0; i < FIXED_LEN; i++) {
		const c = padded.charCodeAt(i);
		const k = keyBytes[i] % RANGE;
		result += String.fromCharCode(((c - BASE + k) % RANGE + RANGE) % RANGE + BASE);
	}
	return result;
}

// --- Settings ---
interface CipherSettings {
	timeout: number; // minutes
}

const DEFAULT_SETTINGS: CipherSettings = {
	timeout: 5,
};

// --- Password Modal ---
class PasswordModal extends Modal {
	private resolve: (value: string | null) => void;

	constructor(app: App, resolve: (value: string | null) => void) {
		super(app);
		this.resolve = resolve;
	}

	onOpen() {
		const { contentEl } = this;
		contentEl.createEl("h3", { text: "Enter master password" });

		const input = contentEl.createEl("input", {
			type: "password",
			placeholder: "Master password",
		});
		input.style.width = "100%";
		input.style.padding = "8px";
		input.style.marginTop = "8px";
		input.style.marginBottom = "12px";

		input.addEventListener("keydown", (e) => {
			if (e.key === "Enter") {
				e.preventDefault();
				this.submit(input.value);
			}
		});

		const btnRow = contentEl.createDiv({ cls: "modal-button-container" });
		const confirmBtn = btnRow.createEl("button", { text: "Confirm", cls: "mod-cta" });
		const cancelBtn = btnRow.createEl("button", { text: "Cancel" });

		confirmBtn.addEventListener("click", () => this.submit(input.value));
		cancelBtn.addEventListener("click", () => this.submit(null));

		setTimeout(() => input.focus(), 50);
	}

	private submit(value: string | null) {
		this.resolve(value && value.length > 0 ? value : null);
		this.close();
	}

	onClose() {
		this.contentEl.empty();
	}
}

// --- Encrypt Modal ---
class EncryptModal extends Modal {
	private plugin: CipherPlugin;
	private resolve: (value: string | null) => void;

	constructor(app: App, plugin: CipherPlugin, resolve: (value: string | null) => void) {
		super(app);
		this.plugin = plugin;
		this.resolve = resolve;
	}

	onOpen() {
		const { contentEl } = this;
		contentEl.createEl("h3", { text: "Encrypt a password" });

		const plaintextInput = contentEl.createEl("input", {
			type: "password",
			placeholder: `Password to encrypt (max ${MAX_INPUT} chars)`,
		});
		plaintextInput.style.width = "100%";
		plaintextInput.style.padding = "8px";
		plaintextInput.style.marginTop = "8px";
		plaintextInput.maxLength = MAX_INPUT;

		let masterInput: HTMLInputElement | null = null;
		const cachedPw = this.plugin.getPassword();
		if (!cachedPw) {
			contentEl.createEl("div", {
				text: "Master password",
				cls: "setting-item-name",
			}).style.marginTop = "12px";
			masterInput = contentEl.createEl("input", {
				type: "password",
				placeholder: "Master password",
			});
			masterInput.style.width = "100%";
			masterInput.style.padding = "8px";
			masterInput.style.marginTop = "4px";
		}

		const msgEl = contentEl.createEl("div");
		msgEl.style.cssText = "margin-top:8px;font-size:12px;color:var(--text-error);min-height:1.4em;";

		const submit = async () => {
			const plain = plaintextInput.value;
			if (!plain) { msgEl.textContent = "Please enter a password to encrypt"; return; }

			const masterPw = cachedPw || masterInput?.value;
			if (!masterPw) { msgEl.textContent = "Please enter the master password"; return; }

			try {
				const ciphertext = await encrypt(plain, masterPw);
				if (!cachedPw) this.plugin.setPassword(masterPw);
				this.resolve(ciphertext);
				this.close();
			} catch (e: any) {
				msgEl.textContent = e.message || "Encrypt failed";
			}
		};

		const lastInput = masterInput || plaintextInput;
		lastInput.addEventListener("keydown", (e) => {
			if (e.key === "Enter") { e.preventDefault(); submit(); }
		});

		const btnRow = contentEl.createDiv({ cls: "modal-button-container" });
		btnRow.style.marginTop = "12px";
		const confirmBtn = btnRow.createEl("button", { text: "Encrypt", cls: "mod-cta" });
		const cancelBtn = btnRow.createEl("button", { text: "Cancel" });
		confirmBtn.addEventListener("click", submit);
		cancelBtn.addEventListener("click", () => { this.resolve(null); this.close(); });

		setTimeout(() => plaintextInput.focus(), 50);
	}

	onClose() {
		this.contentEl.empty();
	}
}

// --- Cipher Render Child ---
class CipherRenderChild extends MarkdownRenderChild {
	private plugin: CipherPlugin;
	private ciphertext: string;
	private revealed = false;

	constructor(el: HTMLElement, plugin: CipherPlugin, ciphertext: string) {
		super(el);
		this.plugin = plugin;
		this.ciphertext = ciphertext;
	}

	onload() {
		this.render();
	}

	private render() {
		const container = this.containerEl;
		container.empty();
		container.addClass("cipher-container");

		const textSpan = container.createSpan({
			cls: "cipher-masked",
			text: "\u25CF\u25CF\u25CF\u25CF\u25CF\u25CF\u25CF\u25CF",
		});

		const copyBtn = container.createEl("button", {
			cls: "cipher-eye",
			text: "\uD83D\uDCCB",
			attr: { "aria-label": "Copy decrypted password" },
		});

		const eyeBtn = container.createEl("button", {
			cls: "cipher-eye",
			text: "\uD83D\uDC41",
			attr: { "aria-label": "Toggle cipher visibility" },
		});

		const retryBtn = container.createEl("button", {
			cls: "cipher-eye cipher-retry",
			text: "\uD83D\uDD04",
			attr: { "aria-label": "Re-enter password" },
		});
		retryBtn.style.display = "none";

		const getDecrypted = async (forceAsk: boolean): Promise<string | null> => {
			let pw = forceAsk ? null : this.plugin.getPassword();
			if (!pw) {
				pw = await new Promise<string | null>((resolve) => {
					new PasswordModal(this.plugin.app, resolve).open();
				});
				if (!pw) return null;
				this.plugin.setPassword(pw);
			}
			return decrypt(this.ciphertext, pw);
		};

		const mask = () => {
			textSpan.setText("\u25CF\u25CF\u25CF\u25CF\u25CF\u25CF\u25CF\u25CF");
			textSpan.removeClass("cipher-revealed");
			textSpan.addClass("cipher-masked");
			retryBtn.style.display = "none";
			this.revealed = false;
		};

		copyBtn.addEventListener("click", async () => {
			try {
				const plaintext = await getDecrypted(false);
				if (!plaintext) return;
				await navigator.clipboard.writeText(plaintext);
				const orig = copyBtn.textContent;
				copyBtn.setText("\u2705");
				setTimeout(() => copyBtn.setText(orig!), 1500);
			} catch {
				copyBtn.setText("\u274C");
				setTimeout(() => copyBtn.setText("\uD83D\uDCCB"), 1500);
			}
		});

		eyeBtn.addEventListener("click", async () => {
			if (this.revealed) {
				mask();
				return;
			}
			try {
				const plaintext = await getDecrypted(false);
				if (!plaintext) return;
				textSpan.setText(plaintext);
				textSpan.removeClass("cipher-masked");
				textSpan.addClass("cipher-revealed");
				retryBtn.style.display = "";
				this.revealed = true;
			} catch {
				textSpan.setText("Decrypt error");
				textSpan.addClass("cipher-revealed");
				retryBtn.style.display = "";
				this.revealed = true;
			}
		});

		retryBtn.addEventListener("click", async () => {
			this.plugin.clearPassword();
			mask();
			try {
				const plaintext = await getDecrypted(true);
				if (!plaintext) return;
				textSpan.setText(plaintext);
				textSpan.removeClass("cipher-masked");
				textSpan.addClass("cipher-revealed");
				retryBtn.style.display = "";
				this.revealed = true;
			} catch {
				textSpan.setText("Decrypt error");
				textSpan.addClass("cipher-revealed");
				retryBtn.style.display = "";
				this.revealed = true;
			}
		});
	}
}

// --- Settings Tab ---
class CipherSettingTab extends PluginSettingTab {
	plugin: CipherPlugin;

	constructor(app: App, plugin: CipherPlugin) {
		super(app, plugin);
		this.plugin = plugin;
	}

	display() {
		const { containerEl } = this;
		containerEl.empty();
		containerEl.createEl("h2", { text: "Cipher Decode Settings" });

		new Setting(containerEl)
			.setName("Password timeout")
			.setDesc(
				this.plugin.settings.timeout === 0
					? "Master password will be kept until Obsidian is closed"
					: `Master password will be cleared after ${this.plugin.settings.timeout} minute(s)`
			)
			.addSlider((slider) =>
				slider
					.setLimits(0, 60, 1)
					.setValue(this.plugin.settings.timeout)
					.setDynamicTooltip()
					.onChange(async (value) => {
						this.plugin.settings.timeout = value;
						await this.plugin.saveSettings();
						this.display();
					})
			);
	}
}

// --- Main Plugin ---
export default class CipherPlugin extends Plugin {
	settings: CipherSettings = DEFAULT_SETTINGS;
	private masterPassword: string | null = null;
	private passwordExpireTime = 0;

	async onload() {
		await this.loadSettings();

		this.registerMarkdownPostProcessor((el: HTMLElement, ctx: MarkdownPostProcessorContext) => {
			const codeEls = el.querySelectorAll("code");
			codeEls.forEach((code) => {
				const text = code.textContent || "";

				// Try new format first: 🔐 + base64url
				let cipherRaw: string | null = null;
				const newMatch = text.match(NEW_RE);
				if (newMatch) {
					cipherRaw = base64urlToCipher(newMatch[1]);
				} else {
					// Fallback: old cipher: format
					const oldMatch = text.match(OLD_RE);
					if (oldMatch) cipherRaw = oldMatch[1];
				}

				if (!cipherRaw) return;
				const wrapper = code.parentElement;
				if (!wrapper) return;

				const span = createSpan();
				code.replaceWith(span);
				const child = new CipherRenderChild(span, this, cipherRaw);
				ctx.addChild(child);
			});
		});

		this.addCommand({
			id: "insert-cipher",
			name: "Lock password",
			editorCallback: async (editor: Editor) => {
				const ciphertext = await new Promise<string | null>((resolve) => {
					new EncryptModal(this.app, this, resolve).open();
				});
				if (!ciphertext) return;
				const encoded = cipherToBase64url(ciphertext);
				editor.replaceSelection(`\`${PREFIX}${encoded}\``);
			},
		});

		this.addSettingTab(new CipherSettingTab(this.app, this));
	}

	getPassword(): string | null {
		if (this.masterPassword && (this.settings.timeout === 0 || Date.now() < this.passwordExpireTime)) {
			return this.masterPassword;
		}
		this.masterPassword = null;
		return null;
	}

	setPassword(pw: string) {
		this.masterPassword = pw;
		this.passwordExpireTime = this.settings.timeout === 0
			? Infinity
			: Date.now() + this.settings.timeout * 60 * 1000;
	}

	clearPassword() {
		this.masterPassword = null;
		this.passwordExpireTime = 0;
	}

	async loadSettings() {
		this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
	}

	async saveSettings() {
		await this.saveData(this.settings);
	}
}
