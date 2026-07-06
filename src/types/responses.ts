export interface DownloadResponse {
    success: boolean;
    code: number;
    message: string;
    download: string;
    nonce: string;
    ownerid: string;
}
export interface InitResponse {
    success: boolean;
    code: number;
    message: string;
    sessionid: string;
    appinfo: { numUsers: string; numOnlineUsers: string; numKeys: string; version: string; customerPanelLink: string; };
    newSession: boolean; nonce: string; ownerid: string;
}
export interface LoginResponse {
    success: boolean;
    code: number;
    message: string;
    info: {
        username: string;
        subscriptions: {
            subscription: string;
            key: string;
            expiry: string;
            timeleft: number;
            level: string;
        }[];
        ip: string;
        hwid: string | undefined;
        createdate: string | number;
        lastlogin: string;
    },
    nonce: string,
    ownerid: string
}
export interface LicenseResponse {
    success: boolean;
    code: number;
    message: string;
    info: {
        username: string;
        subscriptions: {
            subscription: string;
            key: string;
            expiry: string;
            timeleft: number;
            level: string;
        }[];
        ip: string;
        hwid: string | undefined;
        createdate: string | number;
        lastlogin: string;
    },
    nonce: string,
    ownerid: string
}