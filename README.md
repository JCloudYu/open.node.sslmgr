# sslmgr

集中管理 Let's Encrypt 憑證的小工具。伺服器端負責透過 ACME（DNS-01，Cloudflare）申請與續期憑證，並提供 API 讓各台主機拉取；客戶端則定期檢查本地憑證，快到期時自動向伺服器取回新的 crt 與 bundle。

```
┌──────────────────────────────┐         ┌──────────────────────────┐
│ Server (boot.server.ts)      │  HTTPS  │ Client                   │
│  - API: /ssl/:host/*         │ ◀────── │  (boot.auto-refresh.ts)  │
│  - 每日 00:00 執行續期 cron    │         │  - 每小時檢查本地憑證       │
└──────────────────────────────┘         └──────────────────────────┘
```

## 需求

- Node.js 22 以上
- pnpm、tsx（`npm install -g pnpm tsx`）

## 憑證目錄結構

伺服器端的 `STORAGE_DIR` 底下，每個子資料夾代表一組憑證，**資料夾名稱即為 host key**（同時也是客戶端的 `CERT_HOST_KEY`）。

```
storage/
└── example.com/
    ├── meta.json     # 憑證設定（需手動建立）
    ├── client.key    # ACME 帳號金鑰（自動產生）
    ├── ssl.key       # 憑證私鑰（自動產生，也作為客戶端驗證用）
    ├── ssl.csr
    ├── ssl.crt
    └── bundle.pem    # ssl.crt + ssl.key
```



### meta.json

```json
{
	"expiredDate": "permanently",
	"auth": {
		"type": "cloudflare",
		"zone_id": "<Cloudflare Zone ID>",
		"token": "<Cloudflare API Token>"
	},
	"domains": [
		"example.com",
		"*.example.com"
	]
}
```


| 欄位            | 說明                                                                                       |
| ------------- | ---------------------------------------------------------------------------------------- |
| `expiredDate` | 這組憑證的服務期限。`"permanently"`、`null` 或不填代表無期限；填入日期（例如 `"2026-06-01T00:00:00+08:00"`）則超過後不再續期 |
| `auth`        | DNS-01 驗證所需的 Cloudflare 資訊，token 需要 DNS 編輯權限                                             |
| `domains`     | 憑證涵蓋的網域，第一個會作為 CN                                                                        |


> `meta.json` 含有 Cloudflare token，`ssl.key`、`bundle.pem` 含有私鑰，請勿提交到版本控制。



## 環境變數

所有程式都會依序載入 `.env` → `.env.prod` → `.env.local`，後載入的會覆蓋前面的設定。

### 伺服器端


| 變數            | 說明                    |
| ------------- | --------------------- |
| `BIND_HOST`   | 監聽位址，例如 `0.0.0.0`     |
| `BIND_PORT`   | 監聽 port，例如 `63039`    |
| `STORAGE_DIR` | 憑證目錄（必填），相對路徑以專案目錄為基準 |




### 客戶端


| 變數                | 說明                                        |
| ----------------- | ----------------------------------------- |
| `CERT_DIR`        | 本地憑證目錄，需事先放好 `ssl.key`                    |
| `CERT_FETCH_HOST` | 伺服器位址（必填），例如 `https://sslmgr.example.com` |
| `CERT_HOST_KEY`   | 要拉取的 host key（必填），即伺服器端的資料夾名稱             |




## 伺服器端



### 啟動

```bash
pnpm install
pnpm start
```

啟動後會在每天 00:00:00（依執行環境時區）自動執行一次 `cron.refresh-certificate.ts`，結果輸出到 `/var/log/sslmgr/refresh-YYYY-MM-DD.log`，資料夾不存在會自動建立。

### 申請與續期憑證

```bash
pnpm refresh
```

會掃描 `STORAGE_DIR` 底下所有含 `meta.json` 的資料夾：

- `expiredDate` 已過期：略過，顯示 `Expired! ⚠️`
- 尚未有 `ssl.crt`：申請新憑證
- 憑證剩餘不到 7 天：續期
- 其餘：略過，顯示 `Passed! ✅`

新增一組憑證時，只要建立資料夾與 `meta.json`，再執行 `pnpm refresh` 即可。

### API


| Method | Path                | 回應                                       |
| ------ | ------------------- | ---------------------------------------- |
| GET    | `/ssl/:host/info`   | 憑證資訊（`domains`、`notAfter`、`notBefore` 等） |
| GET    | `/ssl/:host/crt`    | `ssl.crt`                                |
| GET    | `/ssl/:host/bundle` | `bundle.pem`（含私鑰）                        |


**驗證方式**：請求需帶 `Authorization` header，值為用該 host 的 `ssl.key` 對下列內容做 RSA-SHA256（PKCS#1 v1.5）簽章後的 base64url 字串，不需加 `Bearer`：

```js
JSON.stringify({ key: "<host>", ts: Math.floor(Date.now() / 10000) })
```

伺服器接受目前與前一個時間區間（每 10 秒一格），因此客戶端與伺服器的時間需大致同步。驗證失敗一律回 `401`。

若前方有 nginx，可加上 `X-Proxy-From: nginx` header，伺服器會改回傳 `X-Accel-Redirect: /storage/<host>/...` 由 nginx 直接送檔。

## 客戶端

1. 從伺服器端複製對應 host 的 `ssl.key` 到 `CERT_DIR`
2. 設定 `CERT_DIR`、`CERT_FETCH_HOST`、`CERT_HOST_KEY`
3. 啟動：

```bash
pnpm install
pnpm auto-refresh
```

啟動時會先檢查一次，之後每小時檢查一次：

- 本地 `ssl.crt`、`bundle.pem` 都存在且剩餘超過 7 天：略過
- 否則向伺服器拉取新的 crt 與 bundle，確認與本地 `ssl.key` 相符後才寫入
- 伺服器上的憑證還沒比本地新：不覆寫

更新憑證後不會自動重新載入 nginx 等服務，請另行處理。

## Docker

映像檔：`[jcloudyu/sslmgr](https://hub.docker.com/r/jcloudyu/sslmgr)`（`linux/amd64`、`linux/arm64`）

```bash
docker run -d --name sslmgr \
	-p 63039:63039 \
	-e STORAGE_DIR=/app/storage \
	-e TZ=Asia/Taipei \
	-v /srv/sslmgr/storage:/app/storage \
	-v /var/log/sslmgr:/var/log/sslmgr \
	jcloudyu/sslmgr:latest
```


| 掛載點               | 說明                  |
| ----------------- | ------------------- |
| `/app/storage`    | 憑證目錄（`STORAGE_DIR`） |
| `/var/log/sslmgr` | 續期 cron 的 log       |


- `STORAGE_DIR` 必須透過 `-e` 傳入，否則伺服器無法啟動
- 容器預設時區為 UTC，若要在台灣時間 00:00 執行續期，請設定 `TZ=Asia/Taipei`



### 建置與發布

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
	-t jcloudyu/sslmgr:<version> -t jcloudyu/sslmgr:latest --push .
```

