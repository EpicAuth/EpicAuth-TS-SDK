# epicauth-ts-example

To install dependencies:

## **`Bun`**
```bash
bun add @epicauth/sdk
```
## **`npm`**
```bash
npm install @epicauth/sdk
```

This project was created using `bun init` in bun v1.3.13. [Bun](https://bun.com) is a fast all-in-one JavaScript runtime.


## **`EpicAuthApp` instance definition**

Visit https://epicauth.cc/app/ and select your application, then click on the **Javascript** tab.

It'll provide you with the code which you should replace in the `epicauth.ts` file.

```typescript
const EpicAuthApp = new EpicAuth({
  name: "", // App name (Manage Applications --> Application name)
  ownerid: "", // Owner ID (Account-Settings --> OwnerID)
  version: "",
});
```

## **Initialize application**

```typescript
await EpicAuthApp.init();
```

## **Display application information**

```typescript
await EpicAuthApp.fetchStats();
console.log(`
    App data:
    Number of users: ${EpicAuthApp.app_data?.numUsers}
    Number of online users: ${EpicAuthApp.app_data?.onlineUsers}
    Number of keys: ${EpicAuthApp.app_data?.numKeys}
    Application Version: ${EpicAuthApp.app_data?.app_ver}
    Customer panel link: ${EpicAuthApp.app_data?.customer_panel}
`);
```

