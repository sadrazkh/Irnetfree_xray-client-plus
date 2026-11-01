# ➕ IRNetFree **Plus**

ابزارهای کنار [IRNetFree](https://github.com/sadrazkh/Irnetfree_xray-client): **اسکنر** کانفیگ و یک **سرور Xray** با پنلی به سبک 3x-ui و ریورس‌پراکسی. پلاس کلاینت نیست و به اینترنت شما وصل نمی‌شود؛ آدرس، پورت یا SNIای را که اسکن پیدا کرد به‌صورت لینک کپی کنید و در IRNetFree وارد کنید.

The tools beside IRNetFree: a **scanner** for Xray configs and a local **Xray server** with a 3x-ui-style panel and reverse proxy. Plus is not a VPN client — copy what a scan finds as a link and import it into IRNetFree.

- **دانلود / Download:** [آخرین نسخه](https://github.com/sadrazkh/Irnetfree_xray-client-plus/releases/latest) — Windows (نصب‌کننده و پرتابل)، macOS (Intel و Apple Silicon)، Linux (AppImage و deb). هر push به `main` یک «dev» پیش‌انتشار هم می‌سازد.
- **بدون دسترسی ادمین:** پلاس با اجازهٔ کاربر عادی اجرا می‌شود؛ فقط دکمهٔ فایروال تب سرور برای همان یک دستور UAC می‌پرسد.
- **کنار IRNetFree:** شناسهٔ برنامه `com.irnetfree.plus` و پوشهٔ دادهٔ `irnetfree-plus` جداست؛ هر دو با هم اجرا می‌شوند.
- **هسته:** در اولین اجرا از «تنظیمات → هسته‌ها» Xray را دریافت کنید. «انتخاب نسخه» هر نسخهٔ دیگری را می‌دهد. MASQUE به Xray 26.9.30 به بالا و حساب WARP به 26.10.10 به بالا نیاز دارد.

---

## 📡 اسکن (Scan)

یک کانفیگ انتخاب کنید و بگویید **چه چیزی** تست شود: **آدرس‌ها × پورت‌ها × SNIها**. همان کانفیگ با هر ترکیب امتحان می‌شود؛ اول **غربال** سریع روی همه (اتصال TCP و چند نمونه تأخیر از داخل تونل)، بعد **تست سرعت** فقط روی برترها، یکی‌یکی تا عدد سرعت واقعی باشد.

- **همهٔ پروتکل‌ها:** VLESS، VMess، Trojan، Shadowsocks (روی TCP، WS، gRPC، XHTTP، HTTPUpgrade؛ TLS یا REALITY)، **Hysteria2**، **وایرگارد**، **MASQUE** روی HTTP/3 و HTTP/2، **WARP روی MASQUE**، و کانفیگ JSON که مستقیم وصل می‌شود (با دیالر fragment).
- **آدرس‌ها:** IPv4، رنج CIDR و `a-b`، **IPv6** و رنج IPv6، **دامنه**؛ هر مورد می‌تواند پورت خودش را داشته باشد (`1.2.3.4:2053`، `[2606::1]:443`). خالی = آدرس خود کانفیگ.
- **پیش‌تنظیم آدرس:** کلودفلر (v4 و v6)، **WARP MASQUE** (`162.159.198.0/24`)، **WARP وایرگارد** (هفت رنج endpoint با پورت‌های WARP)، و **پیشنهادی** که خودش از روی کانفیگ انتخاب می‌کند.
- **چند آدرس، بدون سقف:** «همهٔ آدرس‌ها» (هر رنجی، حتی یک /8 با ۱۶ میلیون آدرس — رنج هیچ‌وقت فهرست نمی‌شود و آدرس‌ها دسته‌دسته تست می‌شوند)، «N تصادفی از همه» (نمونه‌ای یکنواخت از همهٔ رنج‌ها با هم؛ رنج بزرگ‌تر سهم بیشتر) یا «N از هر رنج». هر اجرا آدرس‌های تازه می‌کشد و قبلاً تست‌شده‌ها کنار می‌روند (تاریخچه روی همین دستگاه، قابل پاک کردن). زیر جعبه: «آدرس‌ها: X از Y».
- **پارامترها (جایگشت):** فقط IP نه — **پارامترهای خود کانفیگ** هم با همهٔ جایگشت‌هایشان، روی همان آدرس‌ها: اثرانگشت TLS (`hellochrome_120` هم)، ALPN، cipherSuites (`real-firefox`، `semi-python`؛ فقط با اثرانگشت `unsafe`)، فرگمنت، **finalMask** (پیش‌تنظیم‌های PattNG: `tlshello-0-len`، `tlshello`، `udp-noise`، `merge`)، **dialMode** (`oob.0`)، mux و حالت XHTTP. هر ردیف یک سوئیچ دارد: روشن = مقدارهایش در ترکیب‌ها ضرب می‌شوند، خاموش = مقدار خود کانفیگ. پارامتری که به این کانفیگ نمی‌خورد (مثلاً اثرانگشت روی Hysteria2) دلیلش را می‌گوید و نوشته نمی‌شود. آنچه فقط **Xray-PattN** اجرا می‌کند (dialMode و merge: نسخهٔ 26.10.27 به بالا؛ finalMask) فقط روی PattN تست می‌شود، هرگز به جایش روی هستهٔ رسمی. بیشتر از «حداکثر تست» (پیش‌فرض ۳۰۰)، نمونه‌ای یکنواخت و تکرارپذیر: هر ترکیب سهم برابر و آدرس‌ها پخش در کل رنج. مجموعهٔ پارامترها را با نام ذخیره و دوباره بارگذاری کنید.
- **خط خلاصه:** بالای صفحه، همیشه در دید: «۵۰۰ از ۱٬۱۱۴٬۱۱۲ آدرس × ۳ پورت × ۳ اثرانگشت × ۲ ماسک = ۳۰۰ تست (سقف ۳۰۰، ۳۰۰ نمونهٔ یکنواخت) · روی ۲ هسته».
- **پورت‌ها و SNIها:** فهرست پورت (`443, 2053, 2083-2087`) و فهرست SNI؛ هر SNI با هر آدرس و پورت. SNI روی نام TLS می‌نشیند و Host همان می‌ماند (دامنه‌فرانتینگ)؛ برای MASQUE نام گواهی هم دنبالش می‌رود (cover domain). برای REALITY، ECH و کانفیگ بدون TLS، SNI عوض نمی‌شود و صفحه همین را می‌گوید.
- **دقیق‌تر:**
  - **ECH یک بار:** کانفیگ ECH که از DNS پرسیده می‌شود (`cloudflare-ech.com+udp://1.1.1.1`) یک بار در شروع گرفته و به همهٔ هسته‌ها داده می‌شود؛ تأخیر DNS در عدد نمی‌آید و یک پرسش گم‌شده یک دسته را نمی‌کشد.
  - **TCP فقط جایی که معنا دارد:** Hysteria2، وایرگارد، mKCP و MASQUE روی HTTP/3 روی UDP‌اند؛ برایشان تست TCP انجام نمی‌شود و تأخیر از داخل تونل تصمیم می‌گیرد.
  - **منتظر بالا آمدن هسته:** هر هسته تا وقتی واقعاً گوش ندهد تست نمی‌شود، پس ردیف‌های اول یک سیستم شلوغ بی‌دلیل نمی‌میرند.
  - **هستهٔ قدیمی کنار می‌رود:** هسته‌ای که برای این کانفیگ قدیمی است (MASQUE، WARP، ECH) با دلیلش کنار گذاشته می‌شود.
  - **قبولی یعنی جواب درست:** هدف وقتی قبول است که صفحهٔ تأخیر از داخل تونل همان جوابی را بدهد که باید (۲۰۴ برای cp.cloudflare.com؛ قابل تنظیم) و دست‌کم دو نمونه از سه جواب بگیرد — یک جواب شانسی یا یک صفحهٔ خطا قبول نیست. مهلت تمام‌شده دوباره امتحان می‌شود، «نه» قطعی نه.
  - **پیش‌بررسی:** قبل از هر هسته یک اتصال TCP (یا دست‌دادن TLS با SNI) به هر آدرس؛ آدرس مرده هیچ هسته‌ای نمی‌بیند، پس رنج بزرگ سریع می‌گذرد. تست‌های تأخیر هم‌زمان روی همهٔ هسته‌ها با هم شمرده می‌شوند تا سیستم شلوغ هدف سالم را مرده نشان ندهد.
  - **امتیاز:** اول درصد موفقیت، بعد میانهٔ تأخیر، بعد جیتر (صفحه امتیاز را به‌صورت «۱۰۰٫۶۲» نشان می‌دهد: بخش صحیح درصد موفقیت). هر ردیف ردشده دلیلش را می‌گوید: بدون TCP، TLS، هسته، پروکسی رد کرد، تونل بسته شد، مهلت، جواب غلط، ناپایدار.
- **ساده‌تر:** پیش‌تنظیم سریع / متعادل / دقیق، «چند تا هم‌زمان»، هسته‌ها و تست‌ها؛ بقیهٔ عددها زیر «پیشرفته».
- **بعد از اسکن:** «کپی لینک» یا «کپی JSON» یک ردیف (کانفیگ با همان آدرس و همان پارامترها؛ dialMode و mux در لینک جا نمی‌شوند و JSON کپی می‌شود) یا **«کپی لینک بهترین‌ها»** برای وارد کردن در IRNetFree، «ذخیره در کانفیگ‌ها»، تست دوبارهٔ سرعت، خلاصهٔ **هر ترکیب** (چند بار قبول، نرخ، میانهٔ تأخیر، بهترین آدرس — بهترین بالا)، خروجی CSV و JSON (با پورت، SNI، پارامترها و دلیل رد).

**Scan.** Addresses × ports × SNIs — and, when you turn them on, the config's own **parameters** (TLS fingerprint, ALPN, cipherSuites, fragment, PattNG's finalMask presets, Xray-PattN's dialMode oob, mux, XHTTP mode) in every permutation — through one config, on every installed Xray core. Every input is a row with a switch (on: its values multiply the run; off: the config's own value); a parameter that does not apply says why; what only Xray-PattN runs is tested on PattN alone; past the test limit an even, repeatable sample; named parameter sets; a live summary line on top. No address cap: all of a range (a /8 is walked, never listed), N random from all the ranges together, or N from each. A pass is the expected answer through the tunnel (204 from the probe page) on two of three samples; a TCP/TLS pre-check keeps dead addresses away from the cores; the score ranks by success, then median delay, then jitter; every failed row says why. Every protocol IRNetFree reads — Hysteria2, WireGuard, MASQUE and WARP over MASQUE included; ECH asked of DNS is fetched once for the whole run; a core too old for the config is left out with the reason.

## 🖧 سرور (Server)

xray را روی همین دستگاه به‌عنوان **سرور** اجرا کنید، با مدل و چیدمان 3x-ui (۳.۸)، بدون پنل وب و دیتابیس. هفت زیرتب: **نمای کلی · ورودی‌ها · خروجی‌ها · روتینگ · ریورس · تنظیمات · لاگ**.

- **ورودی‌ها:** VLESS / VMess / Trojan / Shadowsocks روی TCP، WebSocket، gRPC، XHTTP با none، TLS یا **Reality**؛ هر ورودی **تگ** (`inbound-<port>`)، سقف حجم و انقضا دارد. کاربرها با فیلدهای 3x-ui: UUID یا رمز، flow، سهمیه، انقضا، **چرخهٔ ریست**، توضیح، و برای VLESS **تگ ریورس**. لینک و QR هر کاربر؛ مصرف زنده؛ کاربری که سهمیه یا زمانش تمام شود خودکار غیرفعال می‌شود.
- **خروجی‌ها:** مستقیم، مسدود، از کانفیگ‌های شما (با پین گواهی، dialer ضد DPI و helperهای کانفیگ JSON، همان‌طور که IRNetFree می‌سازد) یا از یک لینک. اولین خروجی فعال، پیش‌فرض است.
- **روتینگ:** جدول قوانین به ترتیب اعمال، با سه پیش‌ساخته (آدرس‌های خصوصی، تورنت، تبلیغات).
- **ریورس:** همان **VLESS Reverse Proxy** هسته‌های 26.9 و 3x-ui v3.8.5. دو ویزارد portal و bridge؛ آنچه می‌نویسند قانون و خروجی معمولی است. «کپی طرف مقابل» JSON طرف دیگر را می‌دهد.
- **تنظیمات:** هسته و نسخه‌اش («دریافت آخرین هسته» یا «انتخاب نسخه»)، سطح لاگ، آدرس عمومی، اجرا همراه برنامه، نمایش کانفیگ نهایی. روی ویندوز «اجازه در فایروال» یک قانون `netsh` برای پورت همان ورودی می‌سازد و برای همان یک دستور اجازهٔ ادمین می‌خواهد.

اگر سرور روشن باشد، بستن پنجره برنامه را به سینی سیستم می‌برد تا سرور کار کند. «اجرا با روشن شدن سیستم» در تنظیمات، برنامه را در سینی باز می‌کند.

**Server.** Xray as a server on this machine on 3x-ui's model: tagged inbounds with per-client quotas, expiry and reset cycles, tagged outbounds, a routing table with presets, and the VLESS reverse proxy as two wizards. Closing the window while the server runs keeps it running in the tray.

## 🗂 کانفیگ‌ها (Configs)

آنچه اسکن تست می‌کند و خروجی‌های سرور به آن اشاره می‌کنند. لینک، متن اشتراک، JSON یا فایل `.conf` وایرگارد را بگذارید، یا با «از IRNetFree» کانفیگ‌های IRNetFree همین دستگاه را یک‌جا بیاورید (فقط خوانده می‌شود؛ وارد کردن دوباره همان‌ها را به‌روز می‌کند).

## 🐧 بدون صفحه‌نمایش (Headless)

همان صفحه‌ها روی HTTP، برای سروری بدون صفحه‌نمایش — مثل 3x-ui روی یک VPS:

```bash
npm run server -- --port 6970
```

پیش‌فرض فقط روی `127.0.0.1` گوش می‌دهد (با `ssh -L` برسید). روی هر آدرس دیگری توکن لازم است (`--token` یا `--token-file`). پوشهٔ داده `~/.irnetfree-plus` است یا `--data-dir`.

---

## 🔧 توسعه (Development)

```bash
npm install
npm start                 # the desktop app
npm test                  # Plus's own suite (Node core only)
npm run get-xray          # a local core in bin/ for the checks below
npm run validate          # every server and scan config through `xray run -test`
npm run probe:reverse     # the reverse proxy end to end on 127.0.0.1, both cores
node scripts/probe-scan.js  # a real scan on 127.0.0.1 finds the one good target, both cores
```

### همگام با IRNetFree (Upstream sync)

کد پروتکل (پارسر، سازندهٔ کانفیگ، اجراکنندهٔ هسته، دانلودر و انتخاب نسخهٔ هسته، و استایل‌ها) **عین** IRNetFree است و هرگز در پلاس ویرایش نمی‌شود. هم‌گام‌سازی یک دستور است و merge و برخورد ندارد. جزئیات در [`docs/SYNC.md`](docs/SYNC.md).

The protocol code is IRNetFree's, verbatim, listed with hashes in `upstream-sync.json`; `npm run sync-upstream -- v1.26.0` takes a newer one. See [`docs/SYNC.md`](docs/SYNC.md).

## License

MIT
