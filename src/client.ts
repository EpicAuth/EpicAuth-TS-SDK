import type { ApiResponse, EpicAuthAppData, EpicAuthOptions, EpicAuthUserData, ResolvedEpicAuthOptions } from "./types/types"
import { EpicAuthError } from "./errors"
import crypto from "crypto"
import * as ed from "@noble/ed25519";
import fs from "fs";
import { execSync, exec } from "child_process";
import type { DownloadResponse, InitResponse, LicenseResponse, LoginResponse } from "./types/responses";
import os from "os";
import { createInterface } from "readline";
import path from "node:path";
import type { LicenseOptions, LoginOptions } from "./types/inputs";
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

    private public_key: string = "5586b4bc69c7a4b487e4563a4cd96afd39140f919bd31cea7d1c6a1e8439422b";
    private loggingEnabled: boolean = true;

    public user_data: EpicAuthUserData | null = null;
    public app_data: EpicAuthAppData | null = null;

    constructor(options: EpicAuthOptions) {
        this.name = options.name;
        this.ownerid = options.ownerid;
        this.version = options.version;
        this.loggingEnabled = options.loggingEnabled ?? true;
        this.hash_to_check = options.hash_to_check;
        this.url = options.url ?? "https://epicauth.cc/api/1.3/";
        this.path = options.path;
        this.exitOnError = options.exitOnError ?? true
    }

    async Init() {
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
            const response = await fetch(this.url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body: JSON.stringify(body)
            });

            if (!response.ok) {
                return this.fail(`HTTP ${response.status}`)
            }

            const data = await response.json() as T;
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
            const message = new TextEncoder().encode(JSON.stringify(data));
            const signatureBytes = ed.etc.hexToBytes(signature);
            const publicKeyBytes = ed.etc.hexToBytes(this.public_key);
            const valid = await ed.verify(signatureBytes, message, publicKeyBytes);
            if (!valid) {
                return this.fail("Signature checksum failed. Request was tampered with or session ended most likely.", 3000);
            }
            this.logEvent(JSON.stringify(data) + "\n");
            return data;
        } catch (error) {
            return this.fail(`Unexpected error: error`);
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
