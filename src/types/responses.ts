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
export interface RegisterResponse {
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
export interface UpgradeResponse {
    success: boolean;
    code: number;
    message: string | null;
    nonce: string;
    ownerid: string;
}
export interface VarResponse {
    success: boolean;
    code: number;
    message: string;
    nonce: string;
    ownerid: string;
}
export interface GetvarResponse {
    success: boolean;
    code: number;
    message: string;
    response: string;
    nonce: string;
    ownerid: string;
}
export interface SetvarResponse {
    success: boolean; code: number; message: string; nonce: string; ownerid: string;
}
export interface BanResponse {
    success: boolean; code: number; message: string; nonce: string; ownerid: string;
}
export interface FileResponse {
    success: boolean; code: number; message: string; contents: string; nonce: string; ownerid: string;
}
export interface WebhookResponse {
    success: boolean; code: number; message: string; response: string; ownerid: string; nonce: string;
}
export interface CheckResponse {
    success: boolean; code: number; message: string; nonce: string; ownerid: string;
}
export interface CheckBlacklistResponse {
    success: boolean; code: number; message: string; nonce: string; ownerid: string;
}
export interface fetchOnlineResponse {
    success: boolean; code: number; message: string; nonce: string; ownerid: string;
}
export interface fetchOnlineResponse2 {
    success: boolean; code: number; message: string; users: string[]; nonce: string; ownerid: string;
}
export interface fetchStatsResponse {
    success: boolean;
    code: number;
    message: string;
    appinfo: { numUsers: string; numOnlineUsers: string; numKeys: string; version: string; customerPanelLink: string; };
    nonce: string;
    ownerid: string;
}

export interface ChatGetResponse {
    success: boolean; code: number; message: string;
    messages: { author: string; message: string; timestamp: number; }[] | null;
    nonce: string; ownerid: string;
}

export interface ChatSendResponse {
    success: boolean; code: number; message: string; nonce: string; ownerid: string;
}
export interface ChangeUsernameResponse {
    success: boolean; code: number; message: string; nonce: string; ownerid: string;
}
export interface LogoutResponse {
    success: boolean; code: number; message: string; nonce: string; ownerid: string;
}
export interface Enable2faResponse {
    success: boolean; message: string; code: number; "2fa": { secret_code: string; QRCode: string; }; nonce: string; ownerid: string;
}
export interface Disable2faResponse {
    success: boolean; message: string; code: number; "2fa": { secret_code: string; QRCode: string; }; nonce: string; ownerid: string;
}