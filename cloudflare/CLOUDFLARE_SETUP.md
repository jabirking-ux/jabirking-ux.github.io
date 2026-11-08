# Cloudflare Edge Security Setup for JABIRKING

## Why Cloudflare?

GitHub Pages is a static hosting platform served via Fastly/GitHub CDN. Because GitHub Pages does not support custom `.htaccess`, Nginx configs, or server-side functions:
1. **GitHub Pages cannot block an incoming HTTP GET request before delivering the file** unless routed through an edge proxy.
2. **GitHub Pages cannot inject custom HTTP response headers** (`X-Robots-Tag: noai`, `Permissions-Policy`, custom CSP).

By routing traffic through a **Cloudflare Worker** or putting a custom domain on Cloudflare with DNS proxying:
- **Zero-Byte Delivery**: AI crawlers (GPTBot, ClaudeBot, PerplexityBot, Bytespider, etc.) receive an immediate `403 Forbidden` with the Error 1006 page before any HTML or font bytes leave the edge.
- **Server-Side Enforcement**: Injects `X-Robots-Tag: noindex, nofollow, noai, noimageai` at the HTTP layer, which compliant engines must honor.
- **Super Bot Fight Mode**: Cloudflare's global threat intelligence automatically challenges or drops headless Puppeteer/Selenium scrapers at the TLS handshake level (JA3/JA4 fingerprinting).

---

## Deployment Options

### Option A: Free Cloudflare Worker (Quickest, No Domain Required)

1. Sign up for a free account at [cloudflare.com](https://dash.cloudflare.com/).
2. Navigate to **Workers & Pages** → **Create application** → **Create Worker**.
3. Copy and paste the contents of `worker.js` into the online Cloudflare Worker editor.
4. Click **Deploy**.
5. Your worker will be available at `https://jabirking-security-proxy.<your-subdomain>.workers.dev`.
   - Any crawler hitting this URL is blocked at the edge.
   - Legitimate humans access the proxied site with all security headers injected.

### Option B: Custom Domain with Cloudflare WAF (Production Recommended)

1. Add your custom domain (e.g., `jabirking.com`) to Cloudflare.
2. In Cloudflare DNS, add a CNAME:
   - **Type**: `CNAME`
   - **Name**: `@` or `portfolio`
   - **Target**: `jabirking-ux.github.io`
   - **Proxy status**: `Proxied` (Orange Cloud)
3. In Cloudflare **Security** → **Bots**:
   - Turn on **Bot Fight Mode** (Challenges automated bots and scrapers).
4. In Cloudflare **Security** → **WAF** → **Custom Rules**:
   - Rule Name: `Block AI Crawlers`
   - Expression:
     `(http.user_agent contains "GPTBot") or (http.user_agent contains "ClaudeBot") or (http.user_agent contains "Bytespider") or (http.user_agent contains "PerplexityBot") or (http.user_agent contains "CCBot") or (cf.client.bot)`
   - Action: `Block` or `Managed Challenge`.
5. Attach `worker.js` as a Worker Route to inject the `X-Robots-Tag: noai` headers on all responses.
