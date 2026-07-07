export interface LoginOptions {
    username: string;
    password: string;
    code?: string;
    hwid?: string;
}
export interface LicenseOptions {
    license: string;
    code?: string;
    hwid?: string;
}
export interface RegisterOptions {
    username: string;
    password: string;
    license: string;
    hwid?: string;
}
export interface UpgradeOptions {
    username: string;
    license: string;
}
export interface WebhookOptions {
    id: string,
    param: string,
    body?: string,
    conttype?: string
}