package subs

// pageHTML - страница подписки в браузере. Стиль повторяет панель: тёмный фон,
// скруглённые карточки, шрифт Samsung с обычным фолбэком
const pageHTML = `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>WINGS V - подписка</title>
<style>
  /* Шрифты и палитра те же, что в панели: страница подписки - её же лицо,
     просто выданное по ссылке без входа */
  @font-face {
    font-family: 'SamsungOne';
    src: url('{{.PanelBase}}/fonts/samsungone_400.ttf') format('truetype');
    font-weight: 400;
    font-display: swap;
  }
  @font-face {
    font-family: 'SamsungOne';
    src: url('{{.PanelBase}}/fonts/samsungone_700.ttf') format('truetype');
    font-weight: 700;
    font-display: swap;
  }
  @font-face {
    font-family: 'SamsungSharpSans';
    src: url('{{.PanelBase}}/fonts/samsungsharpsans_medium.otf') format('opentype');
    font-weight: 500;
    font-style: normal;
  }
  @font-face {
    font-family: 'SamsungSharpSans';
    src: url('{{.PanelBase}}/fonts/samsungsharpsans_bold.otf') format('opentype');
    font-weight: 700;
    font-display: swap;
  }

  :root {
    color-scheme: dark;
    --page: #000000;
    --card: #1c1c1e;
    --surface: #242427;
    --text: #fbfbfb;
    --muted: rgba(252, 252, 252, 0.62);
    --kicker: rgba(252, 252, 252, 0.55);
    --border: rgba(255, 255, 255, 0.06);
    --accent: #1259d1;
    --badge-bg: rgba(140, 168, 255, 0.14);
    --badge-text: #b7c8ff;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 28px 16px 56px;
    background: var(--page);
    color: var(--text);
    font-family: 'SamsungOne', 'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 24px;
  }
  .samsung-topbar-brand {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: 'SamsungSharpSans', 'SamsungOne', sans-serif;
    font-size: 22px;
    font-weight: 700;
    letter-spacing: -0.01em;
    color: var(--text);
    text-decoration: none;
  }
  .samsung-topbar-divider {
    color: var(--muted);
    font-weight: 400;
    margin: 0 6px;
  }
  .samsung-topbar-tag {
    font-family: 'SamsungSharpSans', 'SamsungOne', sans-serif;
    color: var(--muted);
    font-weight: 500;
    font-size: 14px;
    letter-spacing: 0;
  }
  .card {
    width: 100%;
    max-width: 560px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 26px;
    padding: 28px;
  }
  h1 {
    margin: 0 0 8px;
    font-family: 'SamsungSharpSans', 'SamsungOne', sans-serif;
    font-size: 28px;
    letter-spacing: -0.01em;
  }
  h2 {
    margin: 0 0 4px;
    font-family: 'SamsungSharpSans', 'SamsungOne', sans-serif;
    font-size: 19px;
  }
  p.muted { margin: 0; color: var(--muted); font-size: 14px; line-height: 1.55; }
  .qr {
    display: block;
    width: 236px;
    height: 236px;
    margin: 22px auto 14px;
    border-radius: 22px;
    background: #fff;
    padding: 12px;
  }
  .url {
    display: block;
    width: 100%;
    word-break: break-all;
    text-align: center;
    background: var(--surface);
    border-radius: 16px;
    padding: 13px;
    font-size: 13px;
    color: var(--muted);
    border: 0;
    font-family: inherit;
  }
  .stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 14px;
    margin-top: 18px;
  }
  .stat { background: var(--surface); border-radius: 20px; padding: 18px; }
  .stat-kicker {
    display: block;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--kicker);
  }
  .stat-value {
    display: block;
    margin-top: 8px;
    font-family: 'SamsungSharpSans', 'SamsungOne', sans-serif;
    font-size: 24px;
    font-weight: 700;
  }
  .stat-meta { display: block; margin-top: 4px; font-size: 12px; color: var(--kicker); }
  .track {
    margin-top: 16px;
    height: 8px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.08);
    overflow: hidden;
  }
  .fill { height: 100%; border-radius: 999px; background: var(--accent); }
  .pill {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 12px;
    background: var(--badge-bg);
    color: var(--badge-text);
  }
  .servers { margin: 16px 0 0; padding: 0; list-style: none; display: flex; flex-direction: column; gap: 8px; }
  .servers li {
    background: var(--surface);
    border-radius: 16px;
    padding: 12px 14px;
    font-size: 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }
  .servers .transport { color: var(--kicker); font-size: 12px; text-transform: uppercase; }
  footer { font-size: 12px; color: var(--kicker); text-align: center; max-width: 560px; }
</style>
</head>
<body>
  <div class="samsung-topbar-brand">
    <span class="wordmark-inline">WINGS V</span>
    <span class="samsung-topbar-divider">|</span>
    <span class="samsung-topbar-tag">Federation</span>
  </div>

  <section class="card">
    <h1>Ваша подписка</h1>
    <p class="muted">Отсканируйте код приложением или скопируйте ссылку - серверы приедут сами и будут обновляться.</p>
    {{if .QR}}<img class="qr" src="{{.QR}}" alt="QR-код подписки">{{end}}
    <input class="url" value="{{.URL}}" readonly onclick="this.select()">
  </section>

  <section class="card">
    <h2>Доступ</h2>
    <div class="stats">
      <div class="stat">
        <span class="stat-kicker">Серверов</span>
        <span class="stat-value">{{.Nodes}}</span>
      </div>
      <div class="stat">
        <span class="stat-kicker">Передано</span>
        <span class="stat-value">{{human .UsedBytes}} / {{if .LimitBytes}}{{human .LimitBytes}}{{else}}&#8734;{{end}}</span>
      </div>
      {{if .Trust}}
      <div class="stat">
        <span class="stat-kicker">Доверие</span>
        <span class="stat-value">{{.Trust.Confidence}}</span>
        <span class="stat-meta"><span class="pill">{{band .Trust.Band}}</span></span>
      </div>
      {{end}}
    </div>
    {{if .LimitBytes}}
    <div class="track"><div class="fill" style="width: {{pct .UsedBytes .LimitBytes}}%"></div></div>
    {{end}}
    {{if .Links}}
    <ul class="servers">
      {{range .Links}}<li><span>{{.Name}}</span><span class="transport">{{.Transport}}</span></li>{{end}}
    </ul>
    {{end}}
    {{if not .StickyUntil.IsZero}}
    <p class="muted" style="margin-top:16px">Эти серверы закреплены за вами до {{date .StickyUntil}}.</p>
    {{end}}
  </section>

  <footer>Ссылка закреплена за вашими устройствами. Переслать её другому человеку не выйдет.</footer>
</body>
</html>`
