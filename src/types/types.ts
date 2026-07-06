export interface EpicAuthOptions {
    name: string;
    ownerid: string;
    version: string;
    hash_to_check?: string;
    url?: string;
    path?: string;
    exitOnError?: boolean
    loggingEnabled?: boolean
}
export interface ResolvedEpicAuthOptions extends EpicAuthOptions {
    exitOnError: boolean
    loggingEnabled: boolean
    url: string
    public_key: string
}

export interface ApiResponse<T = unknown> {
    success: boolean
    message: string
    data: T
}
export interface EpicAuthUserData {
    username: string;
    ip: string;
    hwid: string;
    expires: number;
    createdate: number;
    lastlogin: number;
    subscription: string;
    subscriptions: EpicAuthSubscription[];
}
export interface EpicAuthSubscription {
    subscription: string;
    key: string;
    expiry: string;
    timeleft: number;
    level: string;
}
export interface EpicAuthAppData {
    numUsers: number;
    numKeys: number;
    app_ver: string;
    customer_panel: string;
    onlineUsers: number;
}
