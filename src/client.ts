import type { ApiResponse, EpicAuthAppData, EpicAuthOptions, EpicAuthUserData, ResolvedEpicAuthOptions } from "./types/types"
import { EpicAuthError } from "./errors"
import crypto from "crypto"
import * as ed from "@noble/ed25519";
import fs from "fs";
import { execSync, exec } from "child_process";
import type { BanResponse, ChangeUsernameResponse, ChatGetResponse, ChatSendResponse, CheckBlacklistResponse, CheckResponse, Disable2faResponse, DownloadResponse, Enable2faResponse, fetchOnlineResponse, fetchOnlineResponse2, fetchStatsResponse, FileResponse, GetvarResponse, InitResponse, LicenseResponse, LoginResponse, LogoutResponse, RegisterResponse, SetvarResponse, UpgradeResponse, VarResponse, WebhookResponse } from "./types/responses";
import os from "os";
import { createInterface } from "readline";
import path from "node:path";
import type { LicenseOptions, LoginOptions, RegisterOptions, UpgradeOptions, WebhookOptions } from "./types/inputs";
import { sha512 } from "@noble/hashes/sha2.js";
import * as QRCode from "qrcode";
ed.hashes.sha512 = (...msgs) => sha512(ed.etc.concatBytes(...msgs));
const readline = createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
})

export default class EpicAuth {
    private name: string;
    private ownerid: string;
    private version: string;
    private hash_to_check?: string;
    private url: string = "https://epicauth.cc/api/1.3/";
    private path?: string;
    private exitOnError?: boolean = true;

    private sessionid?: string;
    private initialized: boolean = false;

    private public_key: string = "95b38710f40927b16528a073b87d942e03bd4578d49963a19ebae177945f89ac";
    private loggingEnabled: boolean = true;

    public user_data: EpicAuthUserData | null = null;
    public app_data: EpicAuthAppData | null = null;

    constructor(options: EpicAuthOptions) {
        this.name = options.name;
        this.ownerid = options.ownerid;
        this.version = options.version;
        this.hash_to_check = options.hash_to_check;
        this.url = options.url ?? "https://epicauth.cc/api/1.3/";
        this.path = options.path;
        this.loggingEnabled = options.loggingEnabled ?? true;
        this.exitOnError = options.exitOnError ?? true

        if (!this.name || !this.ownerid || !this.version) {
            throw new Error("Name, ownerid, and version are required");
        }
    }
    /**
        * Initialize EpicAuth authentication service.
        *
        * This method sets up the authentication client, loads configuration,
        * and prepares the necessary tokens and listeners.
        *
        * **Important**: Must be called **exactly once** during app startup,
        * preferably in the main entry point or root module.
        *
        * @returns {Promise<void>} Resolves when initialization is complete.
        * @throws {EpicAuthError} If configuration is invalid or network error occurs.
        */
    async init() {
        if (!this.sessionid && this.initialized) {
            return this.fail("Application already initialized", 0)
        }
        let token: string = "";
        if (this.path) {
            try {
                token = fs.readFileSync(this.path, "utf-8").trim();
            } catch (error) {
                return this.fail(`Failed to read file at path ${this.path}: ${error}`, 0);
            }
        }

        const body = {
            "type": "init",
            "ownerid": this.ownerid,
            "version": this.version,
            "name": this.name,
            "hash": this.hash_to_check,
            ...this.path && {
                "token": token,
                "thash": crypto.createHash("sha256").update(token).digest("hex"),
            }
        }
        const response = await this.request<InitResponse | DownloadResponse | "EpicAuth_Invalid">(body);
        if (response === "EpicAuth_Invalid") {
            return this.fail("This application does not exist");
        }

        if (response["message"] === "invalidver") {
            if ("download" in response) {
                console.log("Your application is outdated.");
                exec(`start ${response["download"]}`, (error) => {
                    if (error) {
                        return this.fail(`Failed to open the download link:${error}`);
                    }
                });
                return this.fail('use latest update');
            } else {
                return this.fail("Your application is outdated and no download link was provided, contact the owner for the latest app version.");
            }
        }

        if (response['success'] === false) {
            return this.fail(response['message']);
        }
        if ("sessionid" in response) {
            this.sessionid = response.sessionid;
            this.initialized = true;
        }
    }
    /**
   * Login to EpicAuth using a username and password.
   *
   * @param username User's username.
   * @param password User's password.
   * @param code Optional 2FA code if exist.
   * @param hwid Optional custom HWID.
   *
   */
    async login({ username, password, code, hwid }: LoginOptions) {
        this.checkinit();
        if (!hwid) hwid = this.getHWID();
        const body = {
            "type": "login",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
            "username": username,
            "pass": password,
            "hwid": hwid,
            ...code && { "code": code },
        };
        const response = await this.request<LoginResponse>(body);
        if (response["success"] === true) {
            console.log(response["message"]);
            this.load_user_data(response["info"]);
        } else {
            console.log(response["message"]);
            return this.fail(response['message'])
        }

    }
    /**
     * Login to EpicAuth Using a license key.
     * 
     * @param license License key
     * @param code Optional 2FA code if exist.
     * @param hwid Optional custom HWID.
     */
    async license({ license, code, hwid }: LicenseOptions) {
        this.checkinit();
        if (!hwid) hwid = this.getHWID();
        const body = {
            "type": "license",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
            "key": license,
            "hwid": hwid,

            ...code && { "code": code },
        };
        const response = await this.request<LicenseResponse>(body);
        if (response["success"] === true) {
            console.log(response["message"]);
            this.load_user_data(response["info"]);
        } else {
            console.log(response["message"]);
            return this.fail(response['message'])
        }
    }
    /**
     * Register to EpicAuth using a username and password.
     * 
     * @param username User's username.
     * @param password User's password.
     * @param license User's license.
     * @param hwid Optional custom HWID.
     */
    async register({ username, password, license, hwid }: RegisterOptions) {
        this.checkinit();
        if (!hwid) hwid = this.getHWID();
        const body = {
            "type": "register",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
            "username": username,
            "pass": password,
            "key": license,
            "hwid": hwid,
        };
        const response = await this.request<RegisterResponse>(body);
        if (response["success"] === true) {
            console.log(response["message"]);
            this.load_user_data(response["info"]);
        } else {
            console.log(response["message"]);
            return this.fail(response['message'])
        }
    }
    /**
     * Upgrade your user by license
     * 
     * @param username User's username
     * @param license the license to upgrade user expiry
     * @description license should be not used
     */
    async upgrade({ username, license }: UpgradeOptions) {
        this.checkinit();

        const body = {
            "type": "upgrade",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
            "username": username,
            "key": license,
        };
        const response = await this.request<RegisterResponse>(body);
        if (response["success"] === true) {
            console.log(response["message"]);
            return this.fail("Restart the application to apply the changes.");
        } else {
            console.log(response["message"]);
            return this.fail(response['message'])
        }
    }
    /**
     * Get global Var
     * 
     * @param name var name
     */
    async var({ name }: { name: string }) {
        this.checkinit();
        const body = {
            "type": "var",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
            "varid": name
        };
        const response = await this.request<VarResponse>(body);
        if (response["success"] === true) {
            console.log(response["message"]);
        } else {
            this.fail(response["message"] ?? "var error");
        }
    }
    /**
     * get user variable
     * 
     * @param name User's variable name
     */
    async getvar({ name }: { name: string }) {
        this.checkinit();
        const body = {
            "type": "getvar",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
            "var": name
        };
        const response = await this.request<GetvarResponse>(body);
        if (response["success"] === true) {
            console.log(response["message"]);
        } else {
            this.fail(response["message"] ?? "getvar error");
        }
    }
    /**
     * edit user variable
     * 
     * @param name User's variable name
     * @param value User's variable value
     */
    async setvar({ name, value }: { name: string, value: string }) {
        this.checkinit();
        const body = {
            "type": "setvar",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
            "varid": name,
            "data": value,
        };
        const response = await this.request<SetvarResponse>(body);
        if (response["success"] === true) {
            return true
        } else {
            this.fail(response["message"] ?? "setvar error");
        }
    }
    /**
     * Ban function 
     * 
     * @description Ban current user
     */
    async ban() {
        this.checkinit();
        const body = {
            "type": "ban",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
        };
        const response = await this.request<BanResponse>(body);
        if (response["success"] === true) {
            return true
        } else {
            this.fail(response["message"]);
        }
    }
    /**
     * EpicAuth file system
     * 
     * @param id file id, Avilable in dashboard
     * @description Download files by it's id
     */
    async file({ id }: { id: string }) {
        this.checkinit();
        const body = {
            "type": "file",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
            "fileid": id
        };
        const response = await this.request<FileResponse>(body);
        if (response["success"] === true) {
            return Buffer.from(response['contents']);
        } else {
            this.fail(response["message"]);
        }
    }
    /**
     * EpicAuth's Webhook function
     * 
     * @param id file id 
     */
    async webhook({ id, param, body, conttype }: WebhookOptions) {
        this.checkinit();
        const data = {
            "type": "webhook",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
            "webid": id,
            "params": param,
            "body": body,
            "conttype": conttype,
        };
        const response = await this.request<WebhookResponse>(data);
        if (response["success"] === true) {
            return response['message'];
        } else {
            this.fail(response["message"]);
        }
    }
    /**
     * Check auth function
     * 
     * @description check auth fo current session
     */
    async check() {
        this.checkinit();
        const body = {
            "type": "check",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
        }
        const response = await this.request<CheckResponse>(body);
        if (response["success"] === true) {
            return true;
        } else {
            this.fail(response["message"]);
        }
    }
    /**
     * Check Blacklist
     * 
     * @description Check if user in blacklisted or not 
     */
    async checkblacklist() {
        this.checkinit();
        const hwid = this.getHWID();
        const body = {
            "type": "checkblacklist",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
            "hwid": hwid,
        };
        const response = await this.request<CheckBlacklistResponse>(body);
        if (response["success"] === true) {
            return true;
        } else {
            this.fail(response["message"]);
        }
    }
    /**
     * Log function
     * 
     * @description send log to EpicAuth or webhook if exist.
     */
    async log({ message }: { message: string }) {
        this.checkinit();
        const body = {
            "type": "log",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
            "message": message,
            "pcuser": os.userInfo().username,
        };
        await this.request(body);
    }
    /**
     * FetchOnline function
     * 
     * @description Get number of online users
     */
    async fetchOnline() {
        this.checkinit();
        const body = {
            "type": "fetchOnline",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
        }
        const response = await this.request<fetchOnlineResponse | fetchOnlineResponse2>(body);
        if (response["success"] === true) {
            if ("users" in response) {
                return Number(response['users'])
            } else {
                return null
            }
        } else {
            return false
        }
    }
    /**
     * FetchStats function
     * 
     * @description Get application status
     */
    async fetchStats() {
        this.checkinit();
        const body = {
            "type": "fetchStats",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
        };
        const response = await this.request<fetchStatsResponse>(body);
        if (response["success"] === true) {
            return this.load_app_data(response['appinfo'])
        }
    }
    /**
     * Chat Get function
     * @param channel Channel name
     * @description retrive messages
     * @returns  return { author: string; message: string; timestamp: number; } [] | null
     */
    async chatGet({ channel }: { channel: string }) {
        this.checkinit();
        const body = {
            "type": "chatget",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
            "channel": channel,
        };
        const response = await this.request<ChatGetResponse>(body);
        if (response["success"] === true) {
            return response["messages"];
        } else {
            return false;
        }
    }
    /**
     * Chat Send function
     * @param channel Channel name
     * @param message message to send
     * @description Send message to channel
     * @returns  return true | false
     */
    async chatSend({ message, channel }: { message: string, channel: string }) {
        this.checkinit();
        const body = {
            "type": "chatsend",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
            "channel": channel,
            "message": message,
        };
        const response = await this.request<ChatSendResponse>(body);
        if (response["success"] === true) {
            return true;
        } else {
            return false;
        }
    }
    /**
     * Change username function
     * 
     * @param username users' username
     * @description change user's username
     */
    async changeUsername({ username }: { username: string }) {
        this.checkinit();
        const body = {
            "type": "changeUsername",
            "newUsername": username,
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
        };
        const response = await this.request<ChangeUsernameResponse>(body);
        if (response["success"] === true) {
            console.log("Username changed successfully");
        } else {
            return false;
        }
    }
    /**
     * Logout function
     * @description logout & close session
     */
    async logout() {
        this.checkinit();
        const body = {
            "type": "logout",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
        };
        const response = await this.request<LogoutResponse>(body);
        if (response["success"] === true) {
            this.fail("Logged out successfully");
        } else {
            this.fail(response["message"]);
        }
    }
    /**
     * Enable 2FA
     * @param code 2fa code in second time
     * @description Enable 2FA
     */
    async enable2fa({ code }: { code?: string }) {
        this.checkinit();
        const post_data = {
            "type": "2faenable",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
            ...code && { "code": code },
        };

        const response = await this.request<Enable2faResponse>(post_data);

        if (response["success"] === true) {
            if (!code) {
                console.log(response);
                console.log("Your 2fa secret code is: " + response["2fa"]["secret_code"]);

                this.displayQrCode(response["2fa"]["QRCode"]);
                console.log("Please enter the code you received in your authenticator app.");

                const userCode = await new Promise<string>((resolve) => {
                    readline.question("Enter the code: ", (input: string) => {
                        resolve(input);
                    });
                });

                await this.enable2fa({ code: userCode });
            } else {
                console.log("2FA enabled successfully");
            }
        } else {
            console.log(response["message"]);
            this.sleep(5000);
            process.exit(0);
        }

    }
    /**
     * Disable 2FA
     * @description Disable 2FA
     */
    async disable2fa() {
        this.checkinit();
        const code = await new Promise<string>((resolve) => {
            readline.question("Enter the code: ", (input: string) => {
                resolve(input);
            });
        });
        const post_data = {
            "type": "2fadisable",
            "name": this.name,
            "ownerid": this.ownerid,
            "sessionid": this.sessionid,
            "code": code,
        };
        const response = await this.request<Disable2faResponse>(post_data);
        console.log(response["message"]);
        await this.sleep(5000);
    }
    async checkinit() {
        if (!this.sessionid && !this.initialized) {
            return this.fail("You need to run the EpicAuthApp.init(); function before any other EpicAuth functions")
        }
    }
    getHWID(): string {
        const platform = os.platform();
        try {
            switch (platform) {
                case "linux":
                    // Linux: (machine-id)
                    try {
                        const machineId = fs.readFileSync("/etc/machine-id", "utf-8").trim();
                        if (machineId && machineId.length > 10) {
                            return machineId;
                        }
                    } catch {
                        // Fallback
                        try {
                            const dbus = fs.readFileSync("/var/lib/dbus/machine-id", "utf-8").trim();
                            if (dbus) return dbus;
                        } catch { }
                    }
                    break;

                case "win32":
                    // Windows: Machine GUID 
                    try {
                        const guid = execSync(
                            'reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid',
                            { stdio: "pipe" }
                        ).toString();

                        const match = guid.match(/MachineGuid\s+REG_SZ\s+([a-zA-Z0-9-]+)/);
                        if (match && match[1]) {
                            return match[1];
                        }
                    } catch { }
                    // Fallback to SID
                    try {
                        const user = os.userInfo().username;
                        const sidOutput = execSync(
                            `wmic useraccount where name='${user}' get sid`,
                            { stdio: "pipe" }
                        ).toString();

                        const sid = sidOutput.split("\n")[1]?.trim();
                        if (sid && sid.length > 10) return sid;
                    } catch { }
                    break;

                case "darwin":
                    // macOS: Serial Number
                    try {
                        const serial = execSync("ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformSerialNumber")
                            .toString()
                            .split("=")[1]
                            ?.trim()
                            .replace(/"/g, "");

                        if (serial) return serial;
                    } catch { }
                    break;
            }
        } catch (error) {
            console.warn("⚠️ Primary HWID method failed, using fallback");
        }
        const fallback = [
            os.hostname(),
            os.userInfo().username,
            os.arch(),
            os.cpus()[0]?.model || "",
            crypto.randomUUIDv7()
        ].join("|");

        return crypto
            .createHash("sha256")
            .update(fallback)
            .digest("hex")
            .substring(0, 32);
    }
    async displayQrCode(qrCodeUrl: string): Promise<void> {
        try {
            const qrCode = await QRCode.toDataURL(qrCodeUrl);

            const base64Data = qrCode.split(",")[1];
            if (!base64Data) {
                throw new Error("Invalid QR code data");
            }
            const img = Buffer.from(base64Data, "base64");

            const outputPath = this.path ?? "qrcode.png";
            fs.writeFileSync(outputPath, img);

            const platform = os.platform();
            let openCommand: string;

            if (platform === "win32") {
                openCommand = `start ${outputPath}`;
            } else if (platform === "darwin") {
                openCommand = `open ${outputPath}`;
            } else if (platform === "linux") {
                openCommand = `xdg-open ${outputPath}`;
            } else {
                console.error("Unsupported platform for opening the QR code image");
                return;
            }

            exec(openCommand, (error) => {
                if (error) {
                    console.error("Failed to display the QR code image:", error);
                }
            });
        } catch (error) {
            console.error("Failed to generate QR code:", error);
        }
    }
    private async fail(message: string, ms: number = 5000): Promise<never> {
        if (this.exitOnError) {
            console.error(message);
            await this.sleep(ms);
            process.exit(1);
        }
        throw new EpicAuthError(message);
    }
    private async sleep(ms: number) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }
    private async request<T>(
        body: Record<string, unknown>
    ): Promise<T> {
        try {
            const params = new URLSearchParams();

            for (const [key, value] of Object.entries(body)) {
                if (value !== undefined) {
                    params.append(key, String(value));
                }
            }
            const response = await fetch(this.url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body: params.toString(),
            });

            if (!response.ok) {
                return this.fail(`HTTP ${response.status}`)
            }

            const rawBody = await response.text();
            if (rawBody === "EpicAuth_Invalid") { return rawBody as T; }
            const data = JSON.parse(rawBody);
            const excludedfuncs = ["file", "log", "2faenable", "2fadisable"];
            if (excludedfuncs.includes(body.type as string)) {
                return data;
            }
            const signature = response.headers.get("x-signature-ed25519");
            const timestamp = response.headers.get("x-signature-timestamp");

            if (!signature || !timestamp) {
                return this.fail("Missing signature or timestamp in response headers");
            }

            const server_time = new Date(Number(timestamp) * 1000).toUTCString();
            const current_time = new Date().toUTCString();

            const buffer_seconds = 5; // Allowable time difference in seconds
            const time_difference = Math.abs(new Date(server_time).getTime() - new Date(current_time).getTime()) / 1000;

            if (time_difference > buffer_seconds + 20) {
                return this.fail(
                    `Time difference is too large: ${time_difference} seconds, try syncing your date and time settings.`
                );
            }
            const message = new TextEncoder().encode(timestamp + rawBody);
            const signatureBytes = ed.etc.hexToBytes(signature);
            const publicKeyBytes = ed.etc.hexToBytes(this.public_key);
            const valid = await ed.verify(signatureBytes, message, publicKeyBytes);
            if (!valid) {
                return this.fail("Signature checksum failed. Request was tampered with or session ended most likely.", 3000);
            }
            this.logEvent(JSON.stringify(data) + "\n");
            return data;
        } catch (error) {
            return this.fail(`Unexpected error: ${error}`);
        }
    }
    private logEvent(message: string) {
        console.log(message)
        if (!this.loggingEnabled) return;
        const executable = process.argv[1] ?? "unknown";
        const exeName = executable.split("\\").pop() ?? executable.split("/").pop() ?? "unknown";
        const logDirectory = path.join(
            os.homedir(),
            ".epicauth",
            "logs",
            exeName
        );
        try {
            if (!fs.existsSync(logDirectory)) {
                fs.mkdirSync(logDirectory, { recursive: true });
            }

            const logFileName = `${new Date().toLocaleDateString("en-US", { month: "short", day: "2-digit", year: "numeric" }).replace(/ /g, "_")}_logs.txt`;
            const logFilePath = `${logDirectory}/${logFileName}`;

            // Redact sensitive fields
            message = this.redactField(message, "sessionid");
            message = this.redactField(message, "ownerid");
            message = this.redactField(message, "app");
            message = this.redactField(message, "version");
            message = this.redactField(message, "fileid");
            message = this.redactField(message, "webhooks");
            message = this.redactField(message, "nonce");

            const logMessage = `[${new Date().toISOString()}] [${exeName}] ${message}\n`;
            fs.appendFileSync(logFilePath, logMessage, "utf-8");
        } catch (error) {
            if (error instanceof Error) {
                console.error(`Error logging data: ${error.message}`);
            } else {
                console.error("Error logging data: Unknown error");
            }
        }
    }
    private redactField(content: string, field: string): string {
        const regex = new RegExp(`"${field}":\\s*".*?"`, "g");
        return content.replace(regex, `"${field}": "[REDACTED]"`);
    }
    private load_app_data(data: fetchStatsResponse['appinfo']) {
        this.app_data = {
            numUsers: Number(data["numUsers"]),
            numKeys: Number(data["numKeys"]),
            app_ver: data["version"],
            customer_panel: data["customerPanelLink"],
            onlineUsers: Number(data["numOnlineUsers"]),
        }
    }
    private load_user_data(data: LoginResponse["info"]) {
        const subscription = data.subscriptions[0];
        if (!subscription) {
            return this.fail("User has no subscriptions.");
        }
        this.user_data = {
            username: data.username,
            ip: data.ip,
            hwid: data.hwid ?? "N/A",
            expires: Number(subscription.expiry),
            createdate: Number(data.createdate),
            lastlogin: Number(data.lastlogin),
            subscription: subscription.subscription,
            subscriptions: data.subscriptions,
        };
    }
}
