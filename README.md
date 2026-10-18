# WS Port Remapper

اسکریپت Bash برای پنل **3x-ui (Sanaei)** که چند اینباند را که هر کدام روی یک پورت جدا هستند، پشت **یک پورت مشترک** جمع می‌کند و لینک اشتراک کاربر را هم خودکار با آدرس و تنظیمات جدید می‌سازد.

- اینباندهای **WebSocket**: TLS را nginx انجام می‌دهد و درخواست بر اساس **SNI و مسیر (path)** به اینباند درست می‌رسد.
- اینباندهای **WebSocket با security برابر Reality**: nginx آن‌ها را **بدون رمزگشایی** (passthrough) و بر اساس `serverNames` به اینباند درست می‌رساند.
- برای هر اینباند یک **Host** در پنل ساخته می‌شود تا کاربر مجبور نباشد آدرس، پورت، SNI، fingerprint، ALPN و ... را دستی تغییر دهد.

> نسخه: `2.0.0` — مجوز: MIT — سیستم‌عامل: Ubuntu 22.04 / 24.04 (و Debian مشابه)

---

## فهرست

1. [هدف از این اسکریپت](#هدف-از-این-اسکریپت)
2. [چطور کار می‌کند](#چطور-کار-میکند)
3. [پیش‌نیازها](#پیشنیازها)
4. [نصب](#نصب)
5. [شروع سریع](#شروع-سریع)
6. [نحوه‌ی تشخیص اینباندها](#نحوهی-تشخیص-اینباندها)
7. [همه‌ی فلگ‌ها](#همهی-فلگها)
8. [مثال‌ها](#مثالها)
9. [حالت‌های ویژه](#حالتهای-ویژه)
10. [فایل‌های ساخته‌شده و تنظیمات](#فایلهای-ساختهشده-و-تنظیمات)
11. [امنیت و حریم خصوصی](#امنیت-و-حریم-خصوصی)
12. [محدودیت‌ها و نکات مهم](#محدودیتها-و-نکات-مهم)
13. [عیب‌یابی](#عیبیابی)
14. [بازگردانی تغییرات](#بازگردانی-تغییرات)
15. [مجوز](#مجوز)

---

## هدف از این اسکریپت

وقتی چند کانفیگ پشت CDN (مثلاً Cloudflare) دارید، هر اینباند روی یک پورت جدا است (`2053`، `2083`، `2087`، `2096`، `8443`، ...). این وضعیت چند مشکل دارد:

- Cloudflare فقط روی چند پورت مشخص HTTPS را پروکسی می‌کند (`443`، `2053`، `2083`، `2087`، `2096`، `8443`)؛ هر اینباند یک پورت از این محدوده را مصرف می‌کند.
- باز نگه داشتن پورت‌های زیاد روی سرور، ظاهر مشکوک‌تری دارد و مدیریت فایروال را سخت می‌کند.
- در 3x-ui نسخه‌ی 3.10 به بعد، گزینه‌ی External Proxy حذف شده و جای آن **Host** آمده؛ ساختن Host برای هر اینباند به صورت دستی کار تکراری و خطاپذیر است.

این اسکریپت همه‌ی این کارها را یک‌جا و تکرارپذیر انجام می‌دهد:

1. اینباندها را از دیتابیس خود پنل پیدا می‌کند (نه از روی اسم).
2. آن‌ها را به پورت‌های داخلی (`127.0.0.1`) منتقل می‌کند.
3. nginx را طوری تنظیم می‌کند که فقط **یک پورت عمومی** باز باشد.
4. برای هر اینباند Host می‌سازد تا لینک اشتراک خودکار درست شود.
5. تداخل پورت با nginx و haproxy را پیش از هر کاری بررسی و رفع می‌کند.

---

## چطور کار می‌کند

```
Client ──► (Cloudflare) ──► server :8443  (nginx)
                               │
          ┌────────────────────┴──────────────────────────────┐
          │ stream  (only when Reality is present)            │
          │ reads the SNI of the ClientHello, no decryption   │
          ├─ SNI = reality serverName ──► 127.0.0.1:10012  (xray, Reality)
          └─ any other SNI ─────────────► 127.0.0.1:11443  (nginx TLS)
                                             │
                                             ├─ cdn.example.com    /path-a ──► 127.0.0.1:10010 (xray ws)
                                             └─ direct.example.com /path-b ──► 127.0.0.1:10011 (xray ws)
```

اگر هیچ اینباند Reality نداشته باشید، لایه‌ی `stream` ساخته نمی‌شود و nginx مستقیم روی پورت عمومی با TLS گوش می‌دهد.

### اینباندها به سه گروه تقسیم می‌شوند

| گروه | چه اینباندهایی | TLS را چه کسی انجام می‌دهد | آدرس داخل Host |
|---|---|---|---|
| `cdn` | WebSocket با SNI برابر `--cdn-sni` | nginx (گواهی دامنه‌ی CDN) | IP لبه‌ی Cloudflare (`--cdn-address`) |
| `direct` | WebSocket با SNI برابر `--direct-sni` (یا بدون SNI) | nginx (گواهی دامنه‌ی مستقیم) | دامنه‌ی مستقیم یا `--direct-address` |
| `reality` | اینباند **WebSocket** که security آن `reality` باشد | خود xray (nginx فقط عبور می‌دهد) | `--reality-address` (پیش‌فرض: آدرس direct) |

### در Host چه چیزی نوشته می‌شود

- **WebSocket:** `security = tls`، آدرس، پورت عمومی، SNI، fingerprint، ALPN، cipher suites. برای گروه CDN هم ECH و Final Mask (دو Fragment).
- **Reality:** برای هر اینباند Reality یک Host جدا ساخته می‌شود و تنظیمات Reality همان اینباند در آن کپی می‌شود: SNI، fingerprint، `publicKey`، اولین `shortId` غیرخالی، `spiderX` و `mldsa65Verify` (هرکدام که در اینباند باشد). security در Host برابر `reality` است. اگر پنل شما این نوع Host را نپذیرد، اسکریپت خودش با `security = same` دوباره می‌فرستد (پنل کلید و Short ID خود اینباند را نگه می‌دارد) و فقط SNI و fingerprint در Host می‌ماند.

با `--host-security clone` همه‌ی این مقادیر به‌جای مقادیر پیش‌فرض اسکریپت، از **تنظیمات خود اینباند اصلی** کپی می‌شوند.

---

## پیش‌نیازها

- سرور Ubuntu/Debian و دسترسی root
- پنل 3x-ui (Sanaei) نسخه‌ای که **Hosts API** دارد (سری‌های جدید 3.x؛ با 3.10.x استفاده شده)
- یک **API Token** از پنل: `Settings → Security → API Token`
- `nginx`، `jq`، `sqlite3`، `curl`، `ss` (اگر نباشند خود اسکریپت نصب می‌کند)
- برای اینباندهای Reality: ماژول stream برای nginx (بسته‌ی `libnginx-mod-stream`؛ اگر نباشد خودکار نصب می‌شود)
- برای گروه‌های WebSocket: گواهی TLS و کلید دامنه (مثلاً Let's Encrypt یا Cloudflare Origin Certificate)

---

## نصب


```bash
curl -fsSLO https://raw.githubusercontent.com/URT19/3X-CLI-Common-Port/refs/heads/main/ws-port-remapper.sh
chmod +x ws-port-remapper.sh
```

```
sudo ./ws-port-remapper.sh --help
```
 

---

## شروع سریع

۱. توکن را در یک فایل با دسترسی محدود بگذارید (بهتر از دادن توکن در خط فرمان است؛ در خط فرمان از `ps` و تاریخچه‌ی shell دیده می‌شود):

```bash
sudo install -m 600 /dev/null /root/.wspr-token
echo 'YOUR_API_TOKEN' | sudo tee /root/.wspr-token >/dev/null
```

۲. **ابتدا یک اجرای آزمایشی** (هیچ چیز تغییر نمی‌کند، فقط برنامه را نشان می‌دهد):

```bash
sudo ./ws-port-remapper.sh --dry-run \
  --panel-url https://127.0.0.1:2053/your-secret-path \
  --api-token-file /root/.wspr-token \
  --cdn-address 104.16.0.1 \
  --cdn-sni cdn.example.com \
  --cdn-cert /etc/ssl/example/cdn.example.com/fullchain.pem \
  --cdn-key  /etc/ssl/example/cdn.example.com/privkey.pem
```

۳. اجرای واقعی با تأیید قدم‌به‌قدم (`--debug` در هر مرحله جزئیات نشان می‌دهد و از شما می‌پرسد):

```bash
sudo ./ws-port-remapper.sh --debug \
  --panel-url https://127.0.0.1:2053/your-secret-path \
  --api-token-file /root/.wspr-token \
  --cdn-address 104.16.0.1 \
  --cdn-sni cdn.example.com \
  --cdn-cert /etc/ssl/example/cdn.example.com/fullchain.pem \
  --cdn-key  /etc/ssl/example/cdn.example.com/privkey.pem
```

۴. همه‌ی مقادیر در `/etc/ws-port-remapper/settings.env` ذخیره می‌شود؛ دفعه‌ی بعد کافی است:

```bash
sudo ./ws-port-remapper.sh
```

۵. پنل را باز کنید: اینباندها روی `127.0.0.1` هستند و برای هر کدام یک Host با تگ `ws-port-remapper` ساخته شده است. لینک اشتراک یک کاربر را بگیرید و تست کنید.

---

## نحوه‌ی تشخیص اینباندها

اسکریپت دیتابیس پنل (`/etc/x-ui/x-ui.db`) را می‌خواند و `stream_settings` هر اینباند را با `jq` تحلیل می‌کند. ردیف‌های خالی یا خراب (مثل Hysteria، TUIC، AmneziaWG) نادیده گرفته می‌شوند و کار را متوقف نمی‌کنند.

یک اینباند وقتی انتخاب می‌شود که:

- شبکه‌ی آن `ws` باشد. (اینباندهای با شبکه‌ی دیگر، حتی با Reality، نادیده گرفته می‌شوند.)

**اینباندهای WebSocket** بر اساس **SNI** دسته‌بندی می‌شوند. SNI از `tlsSettings.serverName` خوانده می‌شود؛ اگر نبود از `wsSettings.host` و بعد `headers.Host`:

- برابر `--cdn-sni` ← گروه `cdn`
- برابر `--direct-sni` ← گروه `direct`
- بدون SNI (مثلاً اینباند بدون TLS) ← گروه `direct` (اگر `--direct-sni` داده شده باشد)
- هر SNI دیگر ← **نادیده گرفته می‌شود** و هشدار می‌دهد

**اینباندهای WebSocket که security آن‌ها Reality است** همیشه گروه `reality` هستند و مسیریابی‌شان با `serverNames` انجام می‌شود (اگر `serverNames` خالی باشد از `dest` استفاده می‌شود). چون مسیریابی بر اساس SNI است، **هر `serverName` باید یکتا باشد**؛ اگر دو اینباند یک SNI داشته باشند یا SNI با دامنه‌ی CDN/direct یکی باشد، اینباند بعدی رد می‌شود.

> TLS اینباندی که منتقل می‌شود حذف می‌شود، پس SNI آن از دیتابیس پاک می‌شود. اسکریپت گروه هر اینباند را در `state.json` به خاطر می‌سپارد و تنظیمات اصلی TLS را در `origin/` ذخیره می‌کند تا اجرای دوباره درست کار کند.

---

## همه‌ی فلگ‌ها

### پنل

| فلگ | توضیح |
|---|---|
| `--panel-url URL` | آدرس پنل همراه با مسیر وب (web base path)، مثل `https://127.0.0.1:2053/your-secret-path` |
| `--api-token TOKEN` | توکن API (در `ps` دیده می‌شود؛ ترجیحاً از گزینه‌های بعدی استفاده کنید) |
| `--api-token-file PATH` | خواندن توکن از فایل |
| `WSPR_API_TOKEN` | متغیر محیطی برای توکن |
| `--no-save-token` | توکن در فایل تنظیمات ذخیره نشود |
| `--db PATH` | مسیر دیتابیس (پیش‌فرض `/etc/x-ui/x-ui.db`) |
| `--internal-base PORT` | اولین پورت داخلی برای اینباندها (پیش‌فرض `10010`) |
| `--internal-tls-base PORT` | اولین پورت TLS داخلی پشت لایه‌ی stream (پیش‌فرض `11443`) |
| `--port PORT` | **پورت عمومی مشترک**؛ همه‌ی گروه‌ها (CDN، Direct، Reality) پشت همین یک پورت می‌روند (پیش‌فرض `8443`) |

اولویت توکن: `--api-token` ← `--api-token-file` ← `WSPR_API_TOKEN` ← فایل تنظیمات.

### گروه CDN

| فلگ | توضیح |
|---|---|
| `--cdn-address IP` | IP لبه‌ی Cloudflare که در Host نوشته می‌شود |
| `--cdn-sni HOST` | دامنه‌ی CDN (SNI و دامنه‌ی گواهی) |
| `--cdn-cert PATH` | `fullchain.pem` همان دامنه |
| `--cdn-key PATH` | `privkey.pem` همان دامنه |
| `--cdn-remark TEXT` | پیشوند اسم Host |

### گروه Direct

| فلگ | توضیح |
|---|---|
| `--direct-sni HOST` | دامنه‌ی مستقیم |
| `--direct-cert PATH` / `--direct-key PATH` | گواهی و کلید |
| `--direct-address ADDR` | آدرس در Host (پیش‌فرض: همان `--direct-sni`) |
| `--direct-port PORT` | فقط برای این گروه، جای `--port` را می‌گیرد |
| `--direct-remark TEXT` | پیشوند اسم Host |

### گروه Reality

| فلگ | توضیح |
|---|---|
| `--reality-address ADDR` | آدرس در Host (پیش‌فرض: آدرس direct) |
| `--reality-port PORT` | فقط برای این گروه، جای `--port` را می‌گیرد |
| `--reality-remark TEXT` | پیشوند اسم Host |
| `--no-reality` | اینباندهای Reality نادیده گرفته شوند |

### تنظیمات Host

| فلگ | توضیح |
|---|---|
| `--fingerprint FP` | fingerprint پیش‌فرض (پیش‌فرض `chrome`) |
| `--host-security default\|clone` | `default`: مقادیر خود اسکریپت. `clone`: کپی از تنظیمات اینباند اصلی |

### انتخاب اینباند

| فلگ | توضیح |
|---|---|
| `--select` | منوی تعاملی: اینباندهای پیدا‌شده با شماره نشان داده می‌شود (`1,3` یا `2-4` یا `all` یا `q`) |
| `--only 22,26` | فقط همین idها |
| `--exclude 3,7` | این idها رد شوند |
| `--filter-remark TEXT` | فقط اینباندهایی که remark آن‌ها شامل این متن است |
| `--cdn-ids 22,26` / `--direct-ids 3,19` | گروه این idها را دستی تعیین می‌کند و به خاطر می‌سپارد (برای اینباندهایی که TLS‌شان قبلاً حذف شده) |

### حالت‌ها

| فلگ | توضیح |
|---|---|
| `--debug` | در هر مرحله جزئیات نشان می‌دهد و تأیید می‌گیرد |
| `--dry-run` | فقط برنامه را نشان می‌دهد، چیزی تغییر نمی‌کند |
| `--nginx-only` | فقط nginx (و haproxy) را بازسازی و مرتب می‌کند؛ به پنل کاری ندارد |
| `--services "A B"` | سرویس‌هایی که ری‌استارت می‌شوند (پیش‌فرض `x-ui nginx`) |
| `--show-settings` | تنظیمات ذخیره‌شده را نشان می‌دهد |
| `--version` | نسخه |
| `-h`, `--help` | راهنما |

---

## مثال‌ها

### فقط یک دامنه‌ی CDN

```bash
sudo ./ws-port-remapper.sh \
  --panel-url https://127.0.0.1:2053/your-secret-path \
  --api-token-file /root/.wspr-token \
  --cdn-address 104.16.0.1 \
  --cdn-sni cdn.example.com \
  --cdn-cert /etc/ssl/example/cdn.example.com/fullchain.pem \
  --cdn-key  /etc/ssl/example/cdn.example.com/privkey.pem
```

### CDN و Direct با هم (روی یک پورت)

```bash
sudo ./ws-port-remapper.sh \
  --panel-url https://127.0.0.1:2053/your-secret-path \
  --api-token-file /root/.wspr-token \
  --cdn-address 104.16.0.1 \
  --cdn-sni cdn.example.com \
  --cdn-cert /etc/ssl/example/cdn.example.com/fullchain.pem \
  --cdn-key  /etc/ssl/example/cdn.example.com/privkey.pem \
  --direct-sni direct.example.com \
  --direct-cert /etc/ssl/example/direct.example.com/fullchain.pem \
  --direct-key  /etc/ssl/example/direct.example.com/privkey.pem
```

هر دو گروه روی پورت `8443` هستند و nginx با SNI آن‌ها را از هم جدا می‌کند.

```
sudo bash ws-port-remapper.sh --debug \
  --panel-url https://127.0.0.1:34098/BwMeBQgEsxYESa3N5mz \
  --api-token "B6crMBEnPONxe13tFlp3uGfb8s2atGTD8pLOCAsx6as1Ko3" \
  --port 443 \
  --internal-base 10010 \
  --cdn-address 104.66.172.246 \
  --cdn-sni cdn.urt19.com \
  --cdn-cert /cert_folder/cert/cdn.urt19.com/fullchain.pem \
  --cdn-key /cert_folder/cert/cdn.urt19.com/privkey.pem \
  --direct-sni direct.urt19.com \
  --direct-cert /cert_folder/cert/direct.urt19.com/fullchain.pem \
  --direct-key /cert_folder/cert/direct.urt19.com/privkey.pem \
  --host-security clone
```

### اضافه کردن Reality

Reality نیازی به گواهی ندارد. فقط آدرسی که کلاینت باید به آن وصل شود را بدهید (برای Reality نباید IP کلادفلر باشد، چون Reality پشت CDN کار نمی‌کند):

```bash
sudo ./ws-port-remapper.sh \
  --direct-sni direct.example.com \
  --direct-cert /etc/ssl/example/direct.example.com/fullchain.pem \
  --direct-key  /etc/ssl/example/direct.example.com/privkey.pem \
  --reality-address 203.0.113.10 \
  --reality-port 443
```

> (بقیه‌ی تنظیمات مثل آدرس پنل و توکن از اجرای قبلی در `settings.env` ذخیره شده‌اند.)
>
> اگر Reality و WebSocket روی **یک پورت** باشند، nginx لایه‌ی `stream` می‌سازد و WebSocketها پشت آن روی `127.0.0.1:11443` قرار می‌گیرند. اگر `--reality-port` با پورت‌های دیگر فرق کند، Reality پورت خودش را می‌گیرد.

### انتخاب اینباندها به صورت تعاملی

```bash
sudo ./ws-port-remapper.sh --select
```

خروجی نمونه:

```
NO   ID     REMARK                         GROUP    KIND     PORT    ROUTE
1    3      03-WS-DIRECT-TLS               direct   ws       29433   /dirpath
2    22     10-WS-CDN-TLS                  cdn      ws       2096    /cdnpath
3    25     25-VLESS-WS-REALITY            reality  reality  25245   sni: www.example.net
? Select inbounds (numbers like 1,3 or ranges 1-3, "all", "q" to quit) [all]:
```

### فقط بعضی اینباندها بدون منو

```bash
sudo ./ws-port-remapper.sh --only 22,26
sudo ./ws-port-remapper.sh --exclude 3,7
sudo ./ws-port-remapper.sh --filter-remark CDN
```

### کپی تنظیمات امنیتی از اینباند اصلی

```bash
sudo ./ws-port-remapper.sh --host-security clone
```

در این حالت SNI، ALPN، fingerprint، cipherSuites، ECH، `allowInsecure`، pin گواهی، `verifyPeerCertByName` و Final Mask از خود اینباند به Host منتقل می‌شود (برای Reality همیشه، در هر دو حالت، تنظیمات خود اینباند منتقل می‌شود). فیلدی که اینباند اصلی نداشته، در Host هم نمی‌آید.

### فقط بازسازی nginx و haproxy

وقتی اینباندها قبلاً منتقل شده‌اند و فقط می‌خواهید nginx را از نو بسازید/مرتب کنید (مثلاً بعد از تغییر گواهی یا دستکاری دستی):

```bash
sudo ./ws-port-remapper.sh --nginx-only
```

این حالت توکن و آدرس پنل نمی‌خواهد و:

- فایل nginx را از روی اینباندهای منتقل‌شده دوباره می‌سازد،
- تداخل پورت با nginx و haproxy را رفع می‌کند،
- لینک‌های خراب `sites-enabled` را پاک می‌کند،
- اگر `/etc/haproxy/haproxy.cfg` باشد، فقط فاصله‌های اضافه و خطوط خالی تکراری را مرتب می‌کند (با بکاپ و اعتبارسنجی `haproxy -c`؛ اگر نامعتبر شد فایل قبلی برمی‌گردد)،
- nginx و haproxy را reload می‌کند.

### توکن به‌صورت متغیر محیطی و بدون ذخیره

```bash
sudo WSPR_API_TOKEN='YOUR_API_TOKEN' ./ws-port-remapper.sh --no-save-token --panel-url https://127.0.0.1:2053/your-secret-path ...
```

---

## حالت‌های ویژه

### `--debug`

در هر مرحله جزئیات (بدنه‌ی درخواست‌ها، پورت‌ها، فایل‌ها) نشان داده می‌شود و پیش از ادامه تأیید می‌گیرد. برای اولین اجرا روی سرور واقعی توصیه می‌شود.

### `--dry-run`

مرحله‌ی تشخیص، دسته‌بندی، برنامه‌ی پورت‌ها و بررسی تداخل اجرا می‌شود ولی هیچ تغییری در پنل، nginx، haproxy یا سرویس‌ها داده نمی‌شود.

### اجرای دوباره (idempotent)

اجرای دوباره امن است: اینباندها همان‌جا می‌مانند، Hostهای موجود (با همان remark) به‌روزرسانی می‌شوند نه تکرار، و nginx دوباره ساخته می‌شود. بعد از ساخت هر Host، اسکریپت آن را از پنل می‌خواند و بررسی می‌کند که فیلدها واقعاً ذخیره شده باشند.

---

## فایل‌های ساخته‌شده و تنظیمات

| مسیر | توضیح |
|---|---|
| `/etc/ws-port-remapper/settings.env` | تنظیمات ذخیره‌شده (دسترسی `600`) |
| `/etc/ws-port-remapper/state.json` | گروه هر اینباند (برای اجرای دوباره) |
| `/etc/ws-port-remapper/origin/<id>.json` | تنظیمات اصلی TLS اینباند، پیش از حذف (برای `--host-security clone`) |
| `/etc/ws-port-remapper/backups/<زمان>/` | بکاپ دیتابیس، nginx و haproxy پیش از هر تغییر |
| `/var/log/ws-port-remapper.log` | لاگ اجرا (توکن و آدرس پنل در آن مخفی می‌شود) |
| `/etc/nginx/sites-available/ws-port-remapper.conf` | سرورهای HTTPS برای گروه‌های WebSocket (+ لینک در `sites-enabled`) |
| `/etc/nginx/modules-enabled/90-ws-port-remapper-stream.conf` | لایه‌ی stream (فقط وقتی Reality باشد) |

فایل‌های nginx که اسکریپت می‌سازد در ابتدایشان `Managed by WS Port Remapper` دارند و در هر اجرا بازنویسی می‌شوند؛ تغییر دستی در آن‌ها از بین می‌رود.

### بررسی تداخل پورت

پیش از اختصاص هر پورت:

1. پورت عمومی با هیچ اینباندی خارج از برنامه تداخل نداشته باشد،
2. پورت‌های داخلی آزاد باشند (گوش‌دادن، دیتابیس، تنظیمات nginx/haproxy)،
3. اگر فایل دیگری در nginx یا `bind` در haproxy همان پورت عمومی را گرفته باشد، **بکاپ گرفته می‌شود** و فایل nginx حذف / خط `bind` در haproxy کامنت می‌شود (و بعد از آن haproxy اعتبارسنجی می‌شود).

اگر `nginx -t` بعد از نوشتن تنظیمات ناموفق باشد، فایل‌های قبلی خودکار برگردانده می‌شوند.

---

## امنیت و حریم خصوصی

- **توکن API:** ترجیحاً با `--api-token-file` یا `WSPR_API_TOKEN` بدهید. فایل تنظیمات با دسترسی `600` ذخیره می‌شود؛ با `--no-save-token` توکن اصلاً ذخیره نمی‌شود.
- **آدرس پنل:** مسیر وب پنل (web base path) یک راز محسوب می‌شود. در خروجی و فایل لاگ، آدرس پنل با `<panel>` و توکن با `<token>` جایگزین می‌شود تا هنگام ارسال لاگ در Issue چیزی لو نرود.
- پیش از به اشتراک گذاشتن لاگ، دامنه‌ها و IPها را خودتان بررسی کنید؛ آن‌ها مخفی نمی‌شوند.
- اسکریپت هیچ داده‌ای به بیرون از سرور نمی‌فرستد و فقط با API پنل و پکیج‌های سیستم کار دارد.
- `--api-token` در خط فرمان از طریق `ps` برای کاربران دیگر دیده می‌شود.

---

## محدودیت‌ها و نکات مهم

- **قبل از اجرا روی سرور مهم:** ابتدا `--dry-run` و بعد `--debug` را امتحان کنید و از پنل و دیتابیس بکاپ بگیرید (اسکریپت هم بکاپ می‌گیرد).
- **تست‌شدگی:** تشخیص اینباندها، دسته‌بندی، برنامه‌ریزی پورت و تولید و مسیریابی تنظیمات nginx (شامل `stream` و Reality) روی nginx واقعی بررسی شده است. API پنل بر اساس مستندات رسمی Hosts API نوشته شده ولی نام همه‌ی فیلدهای TLS در درخواست مستند نیست؛ به همین دلیل اسکریپت Host را بعد از ساخت می‌خواند و فیلدهایی که ذخیره نشده را نشان می‌دهد. اگر پنل شما رفتار متفاوتی داشت، خروجی `--debug` را (با حذف اطلاعات خصوصی) در Issue بگذارید.
- **فقط ws:** Reality فقط برای اینباندهایی با transport برابر WebSocket شناسایی می‌شود. Reality روی TCP، gRPC، XHTTP و بقیه نادیده گرفته می‌شود.
- **نام فیلدهای Reality در Host:** `publicKey` و `shortId` در مستندات Hosts API نیامده‌اند و بر اساس حدس نوشته شده‌اند. اگر پنل ذخیره‌شان نکند، اسکریپت بعد از ساخت Host هشدار می‌دهد.
- **Reality پشت CDN کار نمی‌کند.** آدرس Host برای Reality باید آدرس واقعی سرور باشد، نه IP کلادفلر.
- **IP واقعی کاربر:** وقتی Reality از nginx `stream` عبور می‌کند، xray اتصال را از `127.0.0.1` می‌بیند.
- **SNI یکتا:** مسیریابی Reality با SNI انجام می‌شود، پس هر اینباند Reality باید `serverName` اختصاصی داشته باشد.
- **اینباندهای بدون TLS:** اینباند WebSocket بدون TLS که منتقل شود، بعد از انتقال از طریق nginx با TLS سرو می‌شود و کانفیگ کلاینت باید با Host جدید به‌روز شود (اشتراک خودکار این کار را می‌کند).
- **Cloudflare:** گزینه‌ی WebSockets را فعال کنید، حالت SSL/TLS را `Full` یا `Full (strict)` بگذارید و پورت عمومی را از پورت‌های پشتیبانی‌شده انتخاب کنید (`443`، `2053`، `2083`، `2087`، `2096`، `8443`).
- پنل را مستقیم از طریق تنظیمات خود 3x-ui اجرا کنید؛ اسکریپت همان API را صدا می‌زند که رابط وب استفاده می‌کند.

---

## عیب‌یابی

| پیام / مشکل | علت و راه‌حل |
|---|---|
| `Panel rejected the API request` | آدرس پنل (همراه با web base path)، توکن، یا فعال بودن API Token را بررسی کنید. گواهی self-signed مشکلی ایجاد نمی‌کند. |
| `Public port N is used by inbound(s) outside the plan` | اینباند دیگری روی پورت عمومی گوش می‌دهد. آن را هم در برنامه بگذارید یا پورت دیگری انتخاب کنید. |
| `SNI '...' matches no configured group, skipped` | SNI اینباند با `--cdn-sni`/`--direct-sni` یکی نیست. اگر TLS قبلاً حذف شده، از `--cdn-ids` یا `--direct-ids` استفاده کنید. |
| `Reality SNI '...' cannot be routed, skipped` | دو اینباند Reality `serverName` یکسان دارند یا با دامنه‌ی CDN/direct یکی است. یکی را عوض کنید. |
| `nginx test failed` | خطای `nginx -t` چاپ می‌شود و تنظیمات قبلی برمی‌گردد. معمولاً مسیر گواهی/کلید غلط است. خطای `socket() [::]:80 failed` یعنی IPv6 در سرور غیرفعال است ولی سایت پیش‌فرض nginx به آن گوش می‌دهد؛ سایت پیش‌فرض را غیرفعال کنید. |
| `nginx has no stream module` | اسکریپت `libnginx-mod-stream` را نصب می‌کند. در توزیع‌های دیگر خودتان ماژول stream را فعال کنید. |
| `Host created ... but these fields did not stick` | پنل بعضی فیلدها را ذخیره نکرد؛ اسم آن‌ها چاپ می‌شود. در پنل دستی تنظیمشان کنید یا خروجی `--debug` را در Issue بگذارید. |
| `Host for inbound N was accepted but not found` | remark Host با چیزی که اسکریپت انتظار داشت فرق دارد؛ پنل را بررسی کنید. |
| اجرا بدون خطا ولی کلاینت وصل نمی‌شود | `--nginx-only` را اجرا کنید و `ss -tlnp` را ببینید؛ `systemctl status nginx x-ui`؛ و از لایه‌ی SNI/path کلاینت مطمئن شوید. |

لاگ کامل: `/var/log/ws-port-remapper.log`

---

## بازگردانی تغییرات

هر اجرا بکاپ‌ها را در `/etc/ws-port-remapper/backups/<زمان>/` می‌گذارد (اسم فایل = مسیر اصلی با `_` به‌جای `/`).

```bash
# ۱) دیتابیس پنل (پورت و listen اینباندها)
sudo systemctl stop x-ui
sudo cp /etc/ws-port-remapper/backups/<زمان>/_etc_x-ui_x-ui.db /etc/x-ui/x-ui.db
sudo systemctl start x-ui

# ۲) nginx
sudo rm -f /etc/nginx/sites-enabled/ws-port-remapper.conf \
           /etc/nginx/sites-available/ws-port-remapper.conf \
           /etc/nginx/modules-enabled/90-ws-port-remapper-stream.conf
sudo nginx -t && sudo systemctl reload nginx
```

Hostهایی که اسکریپت ساخته با تگ `ws-port-remapper` در پنل مشخص‌اند و از رابط وب (یا `POST /panel/api/hosts/del/<groupId>`) قابل حذف هستند.

---

## مجوز

MIT — فایل `LICENSE` را ببینید.
