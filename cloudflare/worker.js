/**
 * Cloudflare Worker: JABIRKING AI Crawler Denial & Edge Security Proxy
 * 
 * Target Origin: https://jabirking-ux.github.io
 * Purpose: Enforce server-side HTTP security headers, inspect TLS/User-Agent fingerprints,
 *          and immediately reject AI scraping bots with HTTP 403 Error 1006 at the edge
 *          BEFORE any static HTML, fonts, or assets can be retrieved.
 */

// Comprehensive List of Known AI Model Crawlers & Automated Harvesters
const AI_CRAWLER_REGEX = /GPTBot|ChatGPT-User|OAI-SearchBot|ClaudeBot|Claude-User|anthropic-ai|Google-Extended|Bytespider|CCBot|PerplexityBot|Meta-ExternalAgent|Applebot-Extended|Amazonbot|cohere-ai|YouBot|Diffbot|FacebookBot|omgilibot|Scrapy|python-requests|aiohttp|Go-http-client|Wget|curl/i;

// HTML template for Cloudflare Error 1006 Access Denied
function renderError1006(rayId, utcDate) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Access denied | jabirking-ux</title>
  <style>
    body {
      margin: 0; padding: 50px 24px;
      background: #ffffff; color: #404040;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    .cf-wrapper { max-width: 980px; margin: 0 auto; }
    .cf-header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px; margin-bottom: 6px; }
    .cf-title-row { display: flex; align-items: center; gap: 18px; }
    .cf-hand-icon { width: 56px; height: 56px; display: flex; align-items: center; justify-content: center; }
    .cf-code { font-size: 52px; font-weight: 300; color: #333333; margin: 0; line-height: 1; }
    .cf-ray-top { font-size: 13px; color: #444444; }
    .cf-sub { font-size: 32px; font-weight: 300; color: #888888; margin-top: 10px; margin-bottom: 26px; }
    .cf-hr { border: none; border-bottom: 1px solid #dedede; margin: 0 0 36px 0; }
    .cf-heading { font-size: 26px; font-weight: 400; color: #333333; margin: 0 0 16px 0; }
    .cf-text { font-size: 15px; color: #404040; line-height: 1.6; margin: 0; }
    .cf-footer { border-top: 1px solid #dedede; margin-top: 80px; padding-top: 22px; font-size: 13px; color: #888888; }
  </style>
</head>
<body>
  <div class="cf-wrapper">
    <div class="cf-header">
      <div class="cf-title-row">
        <div class="cf-hand-icon">
          <svg width="56" height="56" viewBox="0 0 56 56" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="28" cy="28" r="26" fill="#d93025"/>
            <g transform="translate(10, 10) scale(0.0375)">
              <path d="M280-120q-83 0-141.5-58.5T80-320v-300q0-25 17.5-42.5T140-680q25 0 42.5 17.5T200-620v280h40v-460q0-25 17.5-42.5T300-860q25 0 42.5 17.5T360-800v400h40v-500q0-25 17.5-42.5T460-960q25 0 42.5 17.5T520-900v500h40v-420q0-25 17.5-42.5T620-880q25 0 42.5 17.5T680-820v380h40v-240q0-25 17.5-42.5T780-740q25 0 42.5 17.5T840-680v360q0 83-58.5 141.5T640-120H280Z" fill="#ffffff" transform="translate(0, 960)"/>
            </g>
          </svg>
        </div>
        <h1 class="cf-code">Error 1006</h1>
      </div>
      <div class="cf-ray-top">Ray ID: ${rayId} &bull; ${utcDate}</div>
    </div>
    <div class="cf-sub">Access denied</div>
    <hr class="cf-hr">
    <div class="cf-heading">What happened?</div>
    <p class="cf-text">
      The owner of this website (jabirking-ux) has banned you for "Automated AI Crawler or Scraping Activity."
    </p>
    <div class="cf-footer">
      GitHub Ray ID: ${rayId} &bull; Performance & security by GitHub
    </div>
  </div>
</body>
</html>`;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const userAgent = request.headers.get('User-Agent') || '';
    const rayId = request.headers.get('cf-ray') || Math.random().toString(16).substring(2, 18);
    const utcDate = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

    // 1. Bypass check (?dev.v1.82.1 or ?preview=26.21)
    const isBypassed = url.searchParams.has('dev.v1.82.1') || url.searchParams.get('preview') === '26.21';

    // 2. Immediate Server-Side Edge Denial for AI Crawlers
    if (!isBypassed && AI_CRAWLER_REGEX.test(userAgent)) {
      return new Response(renderError1006(rayId, utcDate), {
        status: 403,
        statusText: 'Forbidden (AI Crawler Denied)',
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'X-Robots-Tag': 'noindex, nofollow, noai, noimageai',
          'Cache-Control': 'no-store, no-cache, must-revalidate',
          'X-Content-Type-Options': 'nosniff'
        }
      });
    }

    // 3. Proxy Request to GitHub Pages Origin
    const originUrl = new URL(request.url);
    originUrl.hostname = 'jabirking-ux.github.io';
    originUrl.protocol = 'https:';

    const originRequest = new Request(originUrl.toString(), {
      method: request.method,
      headers: request.headers,
      body: request.body,
      redirect: 'follow'
    });

    const response = await fetch(originRequest);

    // 4. Clone and Inject Enforceable Security & Anti-AI Headers
    const newHeaders = new Headers(response.headers);

    // AI & Indexing Restrictions (Server-Enforced)
    newHeaders.set('X-Robots-Tag', 'noindex, nofollow, noai, noimageai, noarchive, nosnippet');
    
    // Core HTTP Security Headers
    newHeaders.set('X-Content-Type-Options', 'nosniff');
    newHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    newHeaders.set('Permissions-Policy', 'interest-cohort=(), browsing-topics=(), attribution-reporting=()');
    newHeaders.set('Content-Security-Policy', "default-src 'self' 'unsafe-inline' data: https:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data: https:;");

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    });
  }
};
