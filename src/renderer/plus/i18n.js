'use strict';
/**
 * plus: the page's i18n. Upstream's i18n.js is loaded first and never edited
 * (upstream-sync.json); this wraps it: Plus's own dictionaries — the shell's
 * below and every plus/*.i18n.js through extend() — are asked first, and
 * upstream's t() answers the rest (the core picker's cv.*, the core rows'
 * comp.*, the window buttons' tb.*). applyI18n is this file's: it keeps
 * upstream's language in step, then fills every [data-i18n], [data-i18n-ph]
 * and [data-i18n-title] with the combined t().
 */
(function () {
  const upstream = window.i18n;
  const DICT = { fa: {}, en: {} };
  let current = 'fa';

  function t(key) {
    const d = DICT[current] || DICT.fa;
    if (key in d) return d[key];
    const u = upstream ? upstream.t(key) : key;
    if (u !== key) return u;
    return key in DICT.fa ? DICT.fa[key] : key;
  }

  /** Plus dictionaries are merged here; a key two Plus files both define is a mistake, said in the console. */
  function extend(dicts) {
    for (const lang of Object.keys(dicts || {})) {
      if (!DICT[lang]) DICT[lang] = {};
      for (const [k, v] of Object.entries(dicts[lang] || {})) {
        if (k in DICT[lang]) console.error('i18n: duplicate key ' + k);
        DICT[lang][k] = v;
      }
    }
  }

  function applyI18n(lang) {
    current = DICT[lang] ? lang : 'fa';
    if (upstream && upstream.applyI18n) upstream.applyI18n(current);
    const rtl = current === 'fa';
    document.documentElement.lang = current;
    document.documentElement.dir = rtl ? 'rtl' : 'ltr';
    document.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = t(el.getAttribute('data-i18n')); });
    document.querySelectorAll('[data-i18n-ph]').forEach((el) => { el.setAttribute('placeholder', t(el.getAttribute('data-i18n-ph'))); });
    document.querySelectorAll('[data-i18n-title]').forEach((el) => { el.setAttribute('title', t(el.getAttribute('data-i18n-title'))); });
  }

  extend({
    fa: {
      'app.version': 'نسخه',
      'app.idle': 'آماده',
      'app.serverOn': 'سرور روشن',
      'app.scanning': 'در حال اسکن',
      'app.newer': 'نسخهٔ {v} آمده است',
      'app.upToDate': 'آخرین نسخه را دارید ({v})',
      'app.updateFailed': 'به گیت‌هاب نرسید',
      'app.openRelease': 'صفحهٔ دانلود',
      'nav.configs': 'کانفیگ‌ها',

      'cfg.title': 'کانفیگ‌ها',
      'cfg.intro': 'کانفیگ‌هایی که اسکن آن‌ها را می‌سنجد و خروجی‌های سرور به آن‌ها اشاره می‌کنند. لینک، متن اشتراک، JSON یا فایل ‎.conf‎ وایرگارد را این‌جا بگذارید، یا یک‌جا از IRNetFree همین دستگاه بیاورید.',
      'cfg.add': 'افزودن',
      'cfg.addPh': 'vless://…  vmess://…  trojan://…  ss://…  hy2://…  wireguard://…  یا JSON',
      'cfg.addBtn': 'افزودن',
      'cfg.added': '{n} کانفیگ اضافه شد',
      'cfg.addErrors': '{n} خط خوانده نشد',
      'cfg.nothing': 'کانفیگی در این متن نبود',
      'cfg.import': 'از IRNetFree',
      'cfg.imported': 'از IRNetFree: {a} تازه، {u} به‌روز',
      'cfg.importMissing': 'IRNetFree روی این دستگاه پیدا نشد',
      'cfg.importFailed': 'فایل IRNetFree خوانده نشد',
      'cfg.file': 'از فایل',
      'cfg.fileErr': 'فایل خوانده نشد',
      'cfg.list': 'فهرست',
      'cfg.count': '{n} کانفیگ',
      'cfg.search': 'جست‌وجو در نام، آدرس یا پروتکل…',
      'cfg.empty': 'هنوز کانفیگی نیست.',
      'cfg.copy': 'کپی لینک',
      'cfg.scan': 'اسکن این',
      'cfg.remove': 'حذف',
      'cfg.removeConfirm': '«{name}» حذف شود؟',
      'cfg.removed': 'حذف شد',
      'cfg.fromIrnetfree': 'IRNetFree',
      'cfg.copied': 'لینک کپی شد',
      'cfg.noLink': 'این کانفیگ لینک اشتراک ندارد',

      'log.title': 'لاگ',
      'log.copy': 'کپی',
      'log.clear': 'پاک کردن',
      'log.copied': 'لاگ کپی شد',

      'set.cores': 'هسته‌ها',
      'set.coresHint': 'اسکن و سرور هر دو با هستهٔ Xray کار می‌کنند. «به‌روزرسانی» نسخهٔ پیشنهادی را نصب می‌کند و «انتخاب نسخه» هر نسخهٔ دیگری را. MASQUE به Xray نسخهٔ 26.9.30 یا تازه‌تر نیاز دارد و حساب WARP به 26.10.10.',
      'set.look': 'ظاهر',
      'set.lang': 'زبان',
      'set.theme': 'پوسته',
      'set.themeSystem': 'مثل سیستم',
      'set.themeDark': 'تیره',
      'set.themeLight': 'روشن',
      'set.skin': 'ظاهر برنامه',
      'set.openAtLogin': 'اجرا با روشن شدن سیستم',
      'set.openAtLoginSub': 'در سینی سیستم باز می‌شود؛ برای سروری که باید همیشه روشن باشد.',
      'set.about': 'درباره',
      'set.dataDir': 'پوشهٔ داده‌ها',
      'set.aboutHint': 'پلاس ابزار است، نه کلاینت: اسکن کانفیگ و سرور Xray. برای اتصال، لینکی را که اسکن پیدا کرد در IRNetFree وارد کنید.',
      'set.checkUpdate': 'بررسی نسخهٔ تازه',
      'set.openData': 'پوشهٔ داده‌ها',
      'set.saved': 'ذخیره شد'
    },
    en: {
      'app.version': 'Version',
      'app.idle': 'IDLE',
      'app.serverOn': 'SERVER ON',
      'app.scanning': 'SCANNING',
      'app.newer': 'Version {v} is out',
      'app.upToDate': 'You have the latest version ({v})',
      'app.updateFailed': 'Could not reach GitHub',
      'app.openRelease': 'Download page',
      'nav.configs': 'Configs',

      'cfg.title': 'Configs',
      'cfg.intro': 'The configs the scan measures and the server’s exits point at. Paste links, a subscription body, JSON or a WireGuard .conf here, or bring IRNetFree’s configs from this machine in one go.',
      'cfg.add': 'Add',
      'cfg.addPh': 'vless://…  vmess://…  trojan://…  ss://…  hy2://…  wireguard://…  or JSON',
      'cfg.addBtn': 'Add',
      'cfg.added': '{n} config(s) added',
      'cfg.addErrors': '{n} line(s) could not be read',
      'cfg.nothing': 'No config in that text',
      'cfg.import': 'From IRNetFree',
      'cfg.imported': 'From IRNetFree: {a} new, {u} updated',
      'cfg.importMissing': 'IRNetFree was not found on this machine',
      'cfg.importFailed': 'IRNetFree’s file could not be read',
      'cfg.file': 'From a file',
      'cfg.fileErr': 'That file could not be read',
      'cfg.list': 'List',
      'cfg.count': '{n} config(s)',
      'cfg.search': 'Search name, address or protocol…',
      'cfg.empty': 'No configs yet.',
      'cfg.copy': 'Copy link',
      'cfg.scan': 'Scan this',
      'cfg.remove': 'Remove',
      'cfg.removeConfirm': 'Remove “{name}”?',
      'cfg.removed': 'Removed',
      'cfg.fromIrnetfree': 'IRNetFree',
      'cfg.copied': 'Link copied',
      'cfg.noLink': 'This config has no share link',

      'log.title': 'Log',
      'log.copy': 'Copy',
      'log.clear': 'Clear',
      'log.copied': 'Log copied',

      'set.cores': 'Cores',
      'set.coresHint': 'The scan and the server both run on the Xray core. “Update” installs the suggested version, “Choose version” any other. MASQUE needs Xray 26.9.30 or newer, a WARP account 26.10.10.',
      'set.look': 'Look',
      'set.lang': 'Language',
      'set.theme': 'Theme',
      'set.themeSystem': 'Like the system',
      'set.themeDark': 'Dark',
      'set.themeLight': 'Light',
      'set.skin': 'Skin',
      'set.openAtLogin': 'Start with the system',
      'set.openAtLoginSub': 'Opens in the tray — for a server that should always be up.',
      'set.about': 'About',
      'set.dataDir': 'Data folder',
      'set.aboutHint': 'Plus is a tool, not a client: it scans configs and runs an Xray server. To connect, import the link a scan found into IRNetFree.',
      'set.checkUpdate': 'Check for a new version',
      'set.openData': 'Data folder',
      'set.saved': 'Saved'
    }
  });

  window.i18n = { t, applyI18n, extend, get lang() { return current; } };
})();
