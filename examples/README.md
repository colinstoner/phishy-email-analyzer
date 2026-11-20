# Examples

- `sample-phish.eml`: a fictional phishing email for `npm run try` (see the main README).
- `*.png`: screenshots of the emails Phishy sends, shown in the main README.

| File | Email |
|---|---|
| `report-phishing.png` | Analysis report: credential phishing (critical) |
| `report-bec.png` | Analysis report: business email compromise (critical) |
| `report-suspicious.png` | Analysis report: suspicious (caution) |
| `report-legitimate.png` | Analysis report: likely legitimate (cleared) |
| `incident-email.png` | Campaign response: the security team's incident email, two actions waiting for approval |
| `campaign-warning.png` | Campaign response: the warning to one employee who received the attack |
| `fanout-alert.png` | Fan-out scan: the security team's alert when a known sender suddenly mails many people (sent when no incident email goes out) |

Everything in them is invented: reserved domains only (`example.com`, `example.net`, `example.org`, `.example`, `.test`) and documentation IP ranges.

## Regenerating the screenshots

The sample data and the rendering live in [`scripts/render-example-emails.ts`](../scripts/render-example-emails.ts). It calls the real template builders (`src/templates/`) and makes no network, AWS, Graph, database or model call.

Write the HTML of every example (default directory: `<os tmpdir>/phishy-example-emails`, or pass `--out <dir>`), to open in a browser or mail client:

```bash
npx tsx scripts/render-example-emails.ts --out /tmp/phishy-example-emails
```

Write the HTML and refresh the PNGs in `examples/`. The screenshot step needs a local Chrome or Chromium (set `CHROME_PATH` if it is not found) and two packages installed without touching `package.json` or the lockfile:

```bash
npm i --no-save --no-package-lock puppeteer-core sharp
npx tsx scripts/render-example-emails.ts --png
```

Each PNG is a 680px-wide light-mode viewport at device scale factor 2, cropped to the email card with a small margin. Long emails are cut at a card row and fade out instead of becoming a tall strip (`maxHeight` per example in the script). `sharp` palette-compresses the images; without it they are written uncompressed and much larger.

After changing a template, rerun this, look at each image, and commit the PNGs that changed.
