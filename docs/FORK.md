# فورک پلاس — نگه‌داری و هم‌گام‌سازی (Fork maintenance & sync)

این سند برای کسی است که کد پلاس را نگه می‌دارد: پلاس چیست، چطور با مخزن اصلی هم‌گام می‌شود، کد تازه کجا می‌نشیند، و هنگام تعارض چه چیزی برنده است.

This document is for whoever maintains Plus: what it is, how it tracks upstream, where new code goes, and what wins in a conflict.

---

## ۱. پلاس چیست؟ (What Plus is)

**IRNetFree Plus** یک فورک از IRNetFree است؛ نه یک برنامهٔ جدا و نه یک شاخهٔ موقت. همان کلاینت، با دو تب تازه:

- **سرور (`xserver`)** — اجرای xray به‌عنوان *سرور* روی همین دستگاه: inbound، کاربر و سهمیه، لینک اشتراک، و مهم‌تر از همه **ریورس‌پراکسی** (bridge/portal).
- **اسکن IP (`scan`)** — یک کانفیگ و یک فهرست IP بگیر، آن‌ها را روی هر هستهٔ xray-ای که نصب است تست کن و بر اساس سرعت و پایداری اندازه‌گیری‌شده رتبه بده.

هدف فورک این است که **گرفتن تغییرات مخزن اصلی ارزان بماند**: هر چیز تازه در فایل‌های تازه است، و فایل‌های مخزن اصلی فقط چند خط قلاب می‌گیرند.

**IRNetFree Plus** is a fork of IRNetFree — not a separate program, not a temporary branch. The same client with two new tabs: a **Server** tab (`xserver`) that runs xray as a server here (inbounds, clients, quotas, share links, and above all **reverse proxy** in bridge/portal roles), and an **IP scan** tab (`scan`) that takes a config plus a list of IPs, tests them on every installed xray-format core, and ranks them by measured speed and stability. The whole point of the fork's layout is that **taking upstream's changes stays cheap**: everything new lives in new files, and upstream files carry only a few hook lines.

---

## ۲. دو ریموت (The two remotes)

| ریموت | آدرس | نقش |
|---|---|---|
| `origin` | `https://github.com/sadrazkh/Irnetfree_xray-client-plus.git` | خودِ پلاس — اینجا push می‌کنیم |
| `upstream` | `https://github.com/sadrazkh/Irnetfree_xray-client.git` | IRNetFree اصلی — فقط از آن fetch می‌کنیم |

اگر یک کلون تازه دارید:

```bash
git remote add upstream https://github.com/sadrazkh/Irnetfree_xray-client.git
git remote -v      # origin باید ...-plus باشد و upstream مخزن اصلی
```

هرگز به `upstream` push نکنید. This is a real clone with two remotes, not a GitHub "fork" object; nothing in the workflow depends on GitHub's fork relationship.

---

## ۳. هم‌گام‌سازی با مخزن اصلی (Syncing with upstream)

```bash
git fetch upstream
git merge upstream/main
npm test && npm run validate
```

- `npm test` باید کامل سبز باشد.
- `npm run validate` کانفیگ‌های ساخته‌شده را با `xray run -test` روی هستهٔ رسمی می‌آزماید؛ برای هستهٔ PattN همان دستور را با `IRNF_XRAY_EXE=bin/xray-pattn.exe` هم اجرا کنید.
- تا وقتی این دو سبز نشده‌اند، merge را commit نکنید.

Run the merge on `main` of this repository (Plus has no long-lived feature branches for upstream syncs). If `npm test` or `npm run validate` fails after a merge, fix it in the merge commit — a red merge that is pushed makes every later sync harder to reason about.

---

## ۴. کد پلاس کجا می‌نشیند؟ (Where Plus code lives)

کد تازه فقط در این مسیرها:

| مسیر | چه چیزی |
|---|---|
| `src/main/xserver/*` | منطق تب سرور در پروسهٔ اصلی |
| `src/main/scan/*` | منطق اسکن IP در پروسهٔ اصلی |
| `src/renderer/plus/*` | رابط کاربری دو تب: `*.js`، `*.css` و `*.i18n.js` |
| `tests/xserver*.test.js`, `tests/scan*.test.js` | تست‌های همان‌ها |
| `docs/FORK.md` | همین سند |

فایل‌های مخزن اصلی فقط **خط قلاب** می‌گیرند — یک `require`، یک فراخوانی ثبت، یک دکمهٔ nav، یک `<section>`، یک `<link>`/`<script>`، یک خط در teardown — و هر خط قلاب با کامنت `// plus` (در JS و CSS) یا `<!-- plus -->` (در HTML) علامت خورده است.

New behaviour goes in new files. Upstream files receive **hook lines only**, and every one of them is marked with a trailing `// plus` (JS/CSS) or `<!-- plus -->` (HTML) so that a merge conflict is recognisable at a glance. Do not refactor upstream code: a rename that touches fifty lines is fifty lines of conflict at the next sync.

Strings for the new tabs live in `src/renderer/plus/<tab>.i18n.js` and are merged through `window.i18n.extend({ fa, en })`; upstream's `i18n.js` dictionary is not edited.

---

## ۵. سیاست تعارض (Conflict policy)

- **در فایل‌های مخزن اصلی، نسخهٔ upstream برنده است.** تعارض را با گرفتن سمت upstream حل کنید و سپس خط‌های قلاب علامت‌دار (`// plus` / `<!-- plus -->`) را دوباره روی همان فایل بگذارید.
- **در فایل‌های پلاس** (`xserver/*`، `scan/*`، `renderer/plus/*`) تعارض معنایی ندارد؛ upstream این فایل‌ها را ندارد.
- اگر یک تعارض در فایل مخزن اصلی *بزرگ* بود، یعنی جایی بیش از حد لازم دست‌کاری شده — منطق را به یک ماژول پلاس منتقل کنید تا دفعهٔ بعد دوباره تکرار نشود.

In upstream files, **upstream wins**: resolve with their side, then re-apply the marked hook lines. Plus's own files never conflict, because upstream does not have them. A large conflict in an upstream file is a signal that something belongs in a Plus module instead.

پس از هر merge، این‌ها را دوباره بررسی کنید (چون در فایل‌های مخزن اصلی‌اند): جدول هویت بخش ۶، `APP_REPO` در `src/main/main.js` و `src/renderer/app.js`، `TASK` در `src/main/autostart.js`، `DEFAULT_SETTINGS` در `src/main/main.js` و `src/server/service.js`، نام‌های artifact در `package.json`، و عنوان نوار بالای پنجره در `src/renderer/index.html`.

---

## ۶. هویت جداگانه (Side-by-side identity)

مالک، نسخهٔ اصلی IRNetFree را روی همین ویندوز اجرا می‌کند. پلاس باید کنارش نصب شود و به آن دست نزند.

| تنظیم | اصلی | پلاس |
|---|---|---|
| `package.json` `name` (‏→ پوشهٔ داده `%APPDATA%\<name>`) | `irnetfree` | `irnetfree-plus` |
| `build.appId` | `com.irnetfree.client` | `com.irnetfree.plus` |
| `build.productName`، شورت‌کات، نام artifactها | `IRNetFree` | `IRNetFree Plus`، `IRNetFree-Plus-…` |
| تسک استارتاپ (`autostart.js` `TASK`) | `IRNetFree` | `IRNetFreePlus` |
| `socksPort` / `httpPort` / `apiPort` پیش‌فرض | 10808 / 10809 / 10085 | **10818 / 10819 / 10095** |
| مخزن انتشار برای بررسی به‌روزرسانی | `sadrazkh/Irnetfree_xray-client` | `sadrazkh/Irnetfree_xray-client-plus` (یک ثابت `APP_REPO`) |
| نوار عنوان | `IR NETFREE` | `IR NETFREE PLUS` |
| نسخه | 1.5.0 | **2.x** |

دو استثنا، عمدی:

- **بستهٔ پشتیبان** (`src/main/backup.js`) همچنان `app: 'IRNetFree'` می‌نویسد، تا یک بکاپ در هر دو جهت بین دو برنامه جابه‌جا شود.
- **`app.name` در `src/renderer/i18n.js`** دست نخورده است؛ آنچه کاربر می‌بیند از نوار عنوان و نام محصول می‌آید.

Two deliberate exceptions: backup bundles keep `app: 'IRNetFree'` so a backup moves between the two apps in both directions, and the i18n `app.name` string is left alone — the "Plus" mark the user sees comes from the title bar and the product name.

---

## ۷. شمارهٔ نسخه (Version numbering)

پلاس نسخه‌های خودش را می‌شمارد و از **۲.x** شروع می‌کند (اولین انتشار پلاس: `2.0.0`، تگ `v2.0.0`). نسخهٔ اصلی روی ۱.x است، پس این دو هرگز به هم نمی‌رسند.

وقتی upstream `package.json` را بالا می‌برد (مثلاً ۱.۵.۰ → ۱.۶.۰)، آن خط در merge تعارض می‌کند: **شمارهٔ پلاس را نگه دارید** و تغییر upstream را دور بریزید. همین کار برای `package-lock.json` (هر دو جای `version`) هم لازم است. اگر آن انتشار upstream ارزش یک انتشار پلاس را داشت، بعد از merge نسخهٔ پلاس را جداگانه بالا ببرید.

Plus numbers its own releases and starts at **2.x** (`2.0.0`, tag `v2.0.0`); upstream is on 1.x, so the two series never collide. When upstream bumps `package.json`, that line conflicts at merge time — **keep the Plus number** and discard upstream's, in `package.json` and in both `version` fields of `package-lock.json`. If the upstream release is worth shipping, bump Plus separately after the merge.
