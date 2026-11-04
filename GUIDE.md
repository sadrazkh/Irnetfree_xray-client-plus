<div dir="rtl">

# 📖 راهنمای کامل IRNetFree Plus

[بازگشت به صفحه‌ی اصلی](README.md)

## 🚀 نصب و اجرا (Setup)

فایل هر سیستم در [بخش دانلود](README.md#-دانلود) آمده است.

- **بدون دسترسی ادمین:** پلاس با اجازه‌ی کاربر عادی اجرا می‌شود. فقط دکمه‌ی فایروال تب سرور در ویندوز برای همان یک دستور UAC می‌پرسد.
- **کنار IRNetFree:** شناسه‌ی برنامه `com.irnetfree.plus` و پوشه‌ی داده‌ی `irnetfree-plus` جداست، پس هر دو با هم اجرا می‌شوند.
- **هسته:** بار اول از «تنظیمات ← هسته‌ها» Xray را بگیر. «به‌روزرسانی» نسخه‌ی پیشنهادی را نصب می‌کند و «انتخاب نسخه» هر نسخه‌ی دیگری را. MASQUE به Xray نسخه‌ی 26.9.30 به بالا و حساب WARP به 26.10.10 به بالا نیاز دارد.
- **نسخه‌ی در حال توسعه:** پیش‌انتشار `dev` با هر تغییر کد روی `main` دوباره ساخته می‌شود، فقط برای ویندوز. برای ساخت مک و لینوکس، «Dev build» را در تب Actions دستی اجرا کن و گزینه‌ی all platforms را بزن.

## 🍎 اولین اجرا روی مک (macOS first run)

برنامه با گواهی Apple امضا نشده، پس دابل‌کلیک ساده ممکن است رد شود. فقط یک بار روی `IRNetFree Plus.app` راست‌کلیک کن و Open را بزن، یا در ترمینال بنویس:

<div dir="ltr">

```bash
xattr -cr "/Applications/IRNetFree Plus.app"
```

</div>

## 📡 اسکن (Scan)

یک کانفیگ انتخاب کن و بگو **چه چیزی** تست شود: **آدرس‌ها × پورت‌ها × SNIها**. همان کانفیگ با هر ترکیب امتحان می‌شود. اول **غربال** سریع روی همه (اتصال TCP و چند نمونه تأخیر از داخل تونل)، بعد **تست سرعت** فقط روی برترها، یکی‌یکی تا عدد سرعت واقعی باشد.

- **همه‌ی پروتکل‌ها:** VLESS، VMess، Trojan، Shadowsocks (روی TCP، WS، gRPC، XHTTP، HTTPUpgrade؛ TLS یا REALITY)، **Hysteria2**، **وایرگارد**، **MASQUE** روی HTTP/3 و HTTP/2، **WARP روی MASQUE**، و کانفیگ JSON که مستقیم وصل می‌شود (با دیالر fragment).
- **آدرس‌ها:** IPv4، رنج CIDR و `a-b`، **IPv6** و رنج IPv6، **دامنه**. هر مورد می‌تواند پورت خودش را داشته باشد (`1.2.3.4:2053`، `[2606::1]:443`). خالی یعنی آدرس خود کانفیگ.
- **رنج‌های آماده:** کلودفلر (v4 و v6)، **Fastly**، **CloudFront**، **CloudFront منطقه‌ای**، **Gcore**، **WARP MASQUE** (`162.159.198.0/24`)، **WARP وایرگارد** (هفت رنج endpoint با پورت‌های WARP)، و **پیشنهادی** که خودش از روی کانفیگ انتخاب می‌کند.
- **به‌روزرسانی لیست‌ها:** لیست رسمی Cloudflare، Fastly، CloudFront و Gcore را از خودشان می‌گیرد. هر لیستی که نرسد، همان قبلی می‌ماند. CloudFront منطقه‌ای در تست ما از یک شبکه‌ی تمیز جواب نداد و برای امتحان از شبکه‌ی خودت گذاشته شده است.
- **چند آدرس، بدون سقف:**
  - «همه‌ی آدرس‌ها»: هر رنجی، حتی یک /8 با ۱۶ میلیون آدرس. رنج هیچ‌وقت فهرست نمی‌شود و آدرس‌ها دسته‌دسته تست می‌شوند.
  - «N تصادفی از همه»: نمونه‌ای یکنواخت از همه‌ی رنج‌ها با هم، و رنج بزرگ‌تر سهم بیشتری می‌گیرد.
  - «N از هر رنج»: سهم برابر برای هر خط.
  - «N از هر بلوک»: سهم هر رنج به اندازه‌اش بستگی دارد. یک ‎/22 چهار بلوک ۲۵۶تایی است و از هر کدام همین تعداد برداشته می‌شود، و یک ‎/32 همان یک آدرس است. اندازه‌ی بلوک از ‎/16 تا ‎/28 قابل انتخاب است.
  - هر اجرا آدرس‌های تازه می‌کشد و قبلاً تست‌شده‌ها کنار می‌روند. تاریخچه روی همین دستگاه است و پاک می‌شود. زیر جعبه می‌نویسد: «آدرس‌ها: X از Y».
- **پارامترها (جایگشت):** فقط IP نه، **پارامترهای خود کانفیگ** هم با همه‌ی جایگشت‌هایشان، روی همان آدرس‌ها: اثرانگشت TLS (`hellochrome_120` هم)، ALPN، cipherSuites (`real-firefox`، `semi-python`؛ فقط با اثرانگشت `unsafe`)، فرگمنت، **finalMask** (پیش‌تنظیم‌های PattNG: `tlshello-0-len`، `tlshello`، `udp-noise`، `merge`)، **dialMode** (`oob.0`)، mux و حالت XHTTP.
  - هر ردیف یک سوئیچ دارد: روشن یعنی مقدارهایش در ترکیب‌ها ضرب می‌شوند، خاموش یعنی مقدار خود کانفیگ.
  - پارامتری که به این کانفیگ نمی‌خورد (مثلاً اثرانگشت روی Hysteria2) دلیلش را می‌گوید و نوشته نمی‌شود.
  - آنچه فقط **Xray-PattN** اجرا می‌کند (dialMode و merge: نسخه‌ی 26.10.27 به بالا؛ finalMask) فقط روی PattN تست می‌شود، هرگز به جایش روی هسته‌ی رسمی.
  - بیشتر از «حداکثر تست» (پیش‌فرض ۳۰۰)، نمونه‌ای یکنواخت و تکرارپذیر می‌گیرد: هر ترکیب سهم برابر دارد و آدرس‌ها در کل رنج پخش می‌شوند.
  - مجموعه‌ی پارامترها را می‌شود با نام ذخیره و دوباره بارگذاری کرد.
- **خط خلاصه:** بالای صفحه و همیشه در دید: «500 از 1,114,112 آدرس × 3 پورت × 3 اثرانگشت × 2 ماسک = 300 تست (سقف 300، 300 نمونه‌ی یکنواخت) · روی 2 هسته».
- **پورت‌ها و SNIها:** فهرست پورت (`443, 2053, 2083-2087`) و فهرست SNI. هر SNI با هر آدرس و پورت ترکیب می‌شود. SNI روی نام TLS می‌نشیند و Host همان می‌ماند (دامنه‌فرانتینگ). برای MASQUE نام گواهی هم دنبالش می‌رود (cover domain). برای REALITY، ECH و کانفیگ بدون TLS، SNI عوض نمی‌شود و صفحه همین را می‌گوید.
- **دقیق‌تر:**
  - **ECH یک بار:** کانفیگ ECH که از DNS پرسیده می‌شود (`cloudflare-ech.com+udp://1.1.1.1`) یک بار در شروع گرفته و به همه‌ی هسته‌ها داده می‌شود. تأخیر DNS در عدد نمی‌آید و یک پرسش گم‌شده یک دسته را نمی‌کشد.
  - **TCP فقط جایی که معنا دارد:** Hysteria2، وایرگارد، mKCP و MASQUE روی HTTP/3 روی UDP‌اند. برایشان تست TCP انجام نمی‌شود و تأخیر از داخل تونل تصمیم می‌گیرد.
  - **منتظر بالا آمدن هسته:** هر هسته تا وقتی واقعاً گوش ندهد تست نمی‌شود، پس ردیف‌های اول یک سیستم شلوغ بی‌دلیل نمی‌میرند.
  - **هسته‌ی قدیمی کنار می‌رود:** هسته‌ای که برای این کانفیگ قدیمی است (MASQUE، WARP، ECH) با دلیلش کنار گذاشته می‌شود.
  - **قبولی یعنی جواب درست:** هدف وقتی قبول است که صفحه‌ی تأخیر از داخل تونل همان جوابی را بدهد که باید (۲۰۴ برای cp.cloudflare.com؛ قابل تنظیم) و دست‌کم دو نمونه از سه جواب بگیرد. یک جواب شانسی یا یک صفحه‌ی خطا قبول نیست. مهلت تمام‌شده دوباره امتحان می‌شود، «نه» قطعی نه.
  - **پیش‌بررسی:** قبل از هر هسته یک اتصال TCP (یا دست‌دادن TLS با SNI) به هر آدرس. آدرس مرده هیچ هسته‌ای نمی‌بیند، پس رنج بزرگ سریع می‌گذرد. تست‌های تأخیر هم‌زمان روی همه‌ی هسته‌ها با هم شمرده می‌شوند تا سیستم شلوغ هدف سالم را مرده نشان ندهد.
  - **امتیاز:** اول درصد موفقیت، بعد میانه‌ی تأخیر، بعد جیتر (صفحه امتیاز را به‌صورت «100.62» نشان می‌دهد و بخش صحیحش درصد موفقیت است). هر ردیف ردشده دلیلش را می‌گوید: بدون TCP، TLS، هسته، پروکسی رد کرد، تونل بسته شد، مهلت، جواب غلط، ناپایدار.
- **ساده‌تر:** پیش‌تنظیم سریع، متعادل و دقیق، «چند تا هم‌زمان»، هسته‌ها و تست‌ها. بقیه‌ی عددها زیر «پیشرفته» است.
- **بعد از اسکن:** «کپی لینک» یا «کپی JSON» یک ردیف (کانفیگ با همان آدرس و همان پارامترها؛ dialMode و mux در لینک جا نمی‌شوند و JSON کپی می‌شود)، **«کپی لینک بهترین‌ها»** برای وارد کردن در IRNetFree، «ذخیره در کانفیگ‌ها»، تست دوباره‌ی سرعت، خلاصه‌ی **هر ترکیب** (چند بار قبول، نرخ، میانه‌ی تأخیر، بهترین آدرس؛ بهترین بالا)، و خروجی CSV و JSON (با پورت، SNI، پارامترها و دلیل رد).

**Scan.** Addresses × ports × SNIs, and, when you turn them on, the config's own **parameters** (TLS fingerprint, ALPN, cipherSuites, fragment, PattNG's finalMask presets, Xray-PattN's dialMode oob, mux, XHTTP mode) in every permutation, through one config, on every installed Xray core. Every input is a row with a switch (on: its values multiply the run; off: the config's own value). A parameter that does not apply says why; what only Xray-PattN runs is tested on PattN alone; past the test limit an even, repeatable sample; named parameter sets; a live summary line on top. No address cap: all of a range (a /8 is walked, never listed), N random from all the ranges together, N from each, or N from each block. Ranges for Cloudflare, Fastly, CloudFront and Gcore ship with the app and update from each CDN's own list. A pass is the expected answer through the tunnel (204 from the probe page) on two of three samples; a TCP/TLS pre-check keeps dead addresses away from the cores; the score ranks by success, then median delay, then jitter; every failed row says why. Every protocol IRNetFree reads, Hysteria2, WireGuard, MASQUE and WARP over MASQUE included; ECH asked of DNS is fetched once for the whole run; a core too old for the config is left out with the reason.

## 🚦 مسیر اسکن و VPN (Scan path)

وقتی VPN در حالت TUN روشن است، به‌جای آدرس‌ها جواب می‌دهد: همه‌چیز زنده به نظر می‌رسد و نتیجه واقعی نیست. پس پلاس مسیر را می‌سنجد.

- **«بررسی مسیر»:** به آدرسی وصل می‌شود که وجود ندارد. اگر جواب بگیرد، یعنی چیزی وسط راه است و هشدار می‌دهد. این بررسی با شروع هر اسکن هم انجام می‌شود.
- **دو راه دارد:** VPN را خاموش کن، یا تیک **«از یک پورت SOCKS»** را بزن و نشانی پورت را بده (`host:port` یا `user:pass@host:port`).
- **پورت مناسب:** پورت مستقیم IRNetFree که از VPN رد نمی‌شود (IRNetFree ← تنظیمات ← پورت‌های مستقیم). این پورت فقط وقتی IRNetFree وصل است باز است. اگر بسته باشد، پلاس می‌گوید و اسکن نمی‌کند، نه این‌که بی‌خبر مستقیم برود.

محدودیت‌های اسکن از راه پورت:

- کانفیگ‌های UDP از پورت SOCKS عبور نمی‌کنند، پس برنامه اسکنشان را نمی‌پذیرد.
- فرگمنت، finalMask و dialMode به خط واقعی نمی‌رسند، پس نتیجه‌ی این ترکیب‌ها فرق واقعی را نشان نمی‌دهد و اجرا همین را می‌گوید. برای تست آن‌ها VPN را خاموش کن و بدون پورت اسکن کن.
- پروکسی SOCKS پیش از وصل شدن هم می‌گوید «موفق»، پس پیش‌بررسی TCP معنا ندارد. پیش‌بررسی با دست‌دادن TLS انجام می‌شود، و برای کانفیگ بدون TLS پیش‌بررسی نیست و رنج بزرگ کندتر می‌گذرد.

**چیزی که این بررسی نمی‌فهمد:** VPN کرنلی مثل وایرگارد یا OpenVPN ساده. این‌ها آدرسی که وجود ندارد را دور می‌ریزند، پس مسیر سالم به نظر می‌رسد در حالی که اسکن از خروجی VPN انجام می‌شود. اگر چنین VPNی داری، خودت خاموشش کن.

**Scan path.** A VPN in TUN mode answers in place of the addresses, so Plus dials an address that cannot exist and warns if it answers; it does so at every start too. Turn the VPN off, or scan through a SOCKS port such as IRNetFree's direct port, which is open only while IRNetFree is connected; a closed port is refused, never replaced by a direct scan. Through a port, UDP configs are refused and fragment, finalMask and dialMode do not reach the real line. The check does not catch a kernel VPN (plain WireGuard, OpenVPN).

## 🖧 سرور (Server)

xray را روی همین دستگاه به‌عنوان **سرور** اجرا کن، با مدل و چیدمان 3x-ui (۳.۸)، بدون پنل وب و دیتابیس. هفت زیرتب دارد: **نمای کلی · ورودی‌ها · خروجی‌ها · روتینگ · ریورس · تنظیمات · لاگ**.

- **ورودی‌ها:** VLESS، VMess، Trojan و Shadowsocks روی TCP، WebSocket، gRPC و XHTTP با none، TLS یا **Reality**. هر ورودی **تگ** (`inbound-<port>`)، سقف حجم و انقضا دارد. کاربرها با فیلدهای 3x-ui: UUID یا رمز، flow، سهمیه، انقضا، **چرخه‌ی ریست**، توضیح، و برای VLESS **تگ ریورس**. لینک و QR هر کاربر، مصرف زنده، و کاربری که سهمیه یا زمانش تمام شود خودکار غیرفعال می‌شود.
- **خروجی‌ها:** مستقیم، مسدود، از کانفیگ‌های خودت (با پین گواهی، dialer ضد DPI و helperهای کانفیگ JSON، همان‌طور که IRNetFree می‌سازد) یا از یک لینک. اولین خروجی فعال، پیش‌فرض است.
- **روتینگ:** جدول قوانین به ترتیب اعمال، با سه پیش‌ساخته (آدرس‌های خصوصی، تورنت، تبلیغات).
- **ریورس:** همان **VLESS Reverse Proxy** هسته‌های 26.9 و 3x-ui v3.8.5. دو جادوگر portal و bridge دارد و آنچه می‌نویسند قانون و خروجی معمولی است. «کپی تنظیمات آن سر» JSON طرف دیگر را می‌دهد.
- **تنظیمات:** هسته و نسخه‌اش، سطح لاگ، آدرس عمومی، اجرا همراه برنامه و نمایش کانفیگ نهایی. روی ویندوز دکمه‌ی فایروال یک قانون `netsh` برای پورت همان ورودی می‌سازد و برای همان یک دستور اجازه‌ی ادمین می‌خواهد، آن هم فقط وقتی خودت بزنی.

اگر سرور روشن باشد، بستن پنجره برنامه را به سینی سیستم می‌برد تا سرور کار کند. «اجرا با روشن شدن سیستم» در تنظیمات، برنامه را در سینی باز می‌کند.

**Server.** Xray as a server on this machine on 3x-ui's model: tagged inbounds with per-client quotas, expiry and reset cycles, tagged outbounds, a routing table with presets, and the VLESS reverse proxy as two wizards. Closing the window while the server runs keeps it running in the tray.

## 🗂 کانفیگ‌ها (Configs)

آنچه اسکن تست می‌کند و خروجی‌های سرور به آن اشاره می‌کنند. لینک، متن اشتراک، JSON یا فایل `.conf` وایرگارد را بگذار، یا با «از IRNetFree» کانفیگ‌های IRNetFree همین دستگاه را یک‌جا بیاور. فایل IRNetFree فقط خوانده می‌شود، و وارد کردن دوباره همان‌ها را به‌روز می‌کند.

## 🐧 بدون صفحه‌نمایش (Headless)

همان صفحه‌ها روی HTTP، برای سروری بدون صفحه‌نمایش، مثل 3x-ui روی یک VPS. به `npm install` نیاز ندارد:

<div dir="ltr">

```bash
git clone https://github.com/sadrazkh/Irnetfree_xray-client-plus.git
cd Irnetfree_xray-client-plus
node src/server/server.js --port 6970
```

</div>

پیش‌فرض فقط روی `127.0.0.1` گوش می‌دهد، پس از کامپیوتر خودت با SSH برس:

<div dir="ltr">

```bash
ssh -L 6970:127.0.0.1:6970 user@server
```

</div>

بعد `http://127.0.0.1:6970` را باز کن. روی هر آدرس دیگری توکن لازم است (`--token` یا `--token-file`)، و اگر ندهی یکی ساخته و چاپ می‌شود. پوشه‌ی داده `~/.irnetfree-plus` است یا `--data-dir`. این حالت با Node.js نسخه‌ی ۲۲ آزموده می‌شود.

## 🔒 حریم خصوصی و شبکه (Privacy)

کانفیگ‌ها، نتیجه‌ها و تاریخچه‌ی آدرس‌ها روی همان دستگاه می‌مانند. برنامه فقط به این‌ها وصل می‌شود:

| به کجا | چرا | کی |
|---|---|---|
| GitHub | دریافت هسته و بررسی نسخه‌ی تازه | وقتی لازم باشد |
| آدرس‌هایی که خودت داده‌ای | اسکن | در اسکن |
| `cp.cloudflare.com` از داخل تونل | تست تأخیر؛ در «پیشرفته» قابل تغییر | در اسکن |
| `speed.cloudflare.com` از داخل تونل | تست سرعت؛ در «پیشرفته» قابل تغییر | در تست سرعت |
| یک آدرس رزرو‌شده که وجود ندارد | بررسی مسیر | در بررسی مسیر و شروع اسکن |
| سرور DNS کانفیگ ECH | گرفتن کانفیگ ECH | اگر کانفیگ ECH داشته باشد |
| Cloudflare، Fastly، AWS و Gcore | گرفتن لیست رسمی رنج‌ها | فقط با زدن «به‌روزرسانی لیست‌ها» |

## 🔧 توسعه (Development)

<div dir="ltr">

```bash
npm install
npm start                   # the desktop app
npm test                    # Plus's own suite (Node core only; Node.js 21+)
npm run server -- --port 6970   # the headless server
npm run get-xray            # a local core in bin/ for the checks below
npm run validate            # every server and scan config through `xray run -test`
npm run probe:reverse       # the reverse proxy end to end on 127.0.0.1, both cores
node scripts/probe-scan.js  # a real scan on 127.0.0.1 finds the one good target, both cores
npm run update-cdn-ranges   # refresh the CDN lists that ship with the app
```

</div>

### هم‌گام با IRNetFree (Upstream sync)

کد پروتکل (پارسر، سازنده‌ی کانفیگ، اجراکننده‌ی هسته، دانلودر و انتخاب نسخه‌ی هسته، و استایل‌ها) **عین** IRNetFree است و هرگز در پلاس ویرایش نمی‌شود. هم‌گام‌سازی یک دستور است و merge و برخورد ندارد. جزئیات در [`docs/SYNC.md`](docs/SYNC.md).

The protocol code is IRNetFree's, verbatim, listed with hashes in `upstream-sync.json`; `npm run sync-upstream -- <ref>` takes a newer one. See [`docs/SYNC.md`](docs/SYNC.md).

</div>
