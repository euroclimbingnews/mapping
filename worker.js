// Public URLs that require authentication
var PROTECTED_PATHS = [
  '/climbing-map-v4',
  '/climbing-map-v4.html',
  '/climbing-map-v4/',
];

// Protected report downloads
var REPORT_PATHS = {
  '/reports/market-2025': 'ECN 2025 Market Report.pdf',
};

// Allowed referrers for free map data access
var ALLOWED_REFERRERS = [
  'map.euroclimbing.news',
  'www.euroclimbing.news',
  'euroclimbing.news',
  'euroclimbingnews.github.io',
  'localhost',
  '127.0.0.1',
];

// Cache duration: 5 minutes (in seconds)
var CACHE_TTL = 300;

export default {
  async fetch(request, env) {
    var url = new URL(request.url);
    var path = url.pathname;

    // ─── Data API: gym data (free + pro) ───
    if (path === '/api/gyms') {
      return handleGymsRequest(request, env);
    }

    // ─── Data API: roundup data (pro only) ───
    if (path === '/api/roundup') {
      return handleRoundupRequest(request, env);
    }

    // ─── Protected reports ───
    if (REPORT_PATHS[path]) {
      var rToken = url.searchParams.get('token');

      if (!rToken) {
        var rCookies = request.headers.get('Cookie') || '';
        var rMatch = rCookies.match(/ecn_token=([^;]+)/);
        rToken = rMatch ? rMatch[1] : null;
      }

      var rPayload = rToken ? await validateJWT(rToken, env.JWT_SECRET) : null;

      if (!rPayload) {
        return new Response(accessDeniedHTML(), {
          status: 403,
          headers: { 'Content-Type': 'text/html' },
        });
      }

      var fileName = REPORT_PATHS[path];
      var object = await env.PRO_REPORTS.get(fileName);

      if (!object) {
        return new Response('Report not found', { status: 404 });
      }

      return new Response(object.body, {
        headers: {
          'Content-Type': 'application/pdf',
          'Content-Disposition': 'attachment; filename="' + fileName + '"',
          'Cache-Control': 'private, no-store',
        },
      });
    }

    // ─── Protected Pro map ───
    if (PROTECTED_PATHS.some(function(p) { return path === p || path === p + '/'; })) {

      var token = url.searchParams.get('token');
      var tokenFromParam = !!token;

      if (!token) {
        var cookies = request.headers.get('Cookie') || '';
        var match = cookies.match(/ecn_token=([^;]+)/);
        token = match ? match[1] : null;
      }

      var payload = token ? await validateJWT(token, env.JWT_SECRET) : null;

      if (!payload) {
        return new Response(accessDeniedHTML(), {
          status: 403,
          headers: { 'Content-Type': 'text/html' },
        });
      }

      if (tokenFromParam) {
        url.searchParams.delete('token');
        return new Response(null, {
          status: 302,
          headers: {
            'Location': url.toString(),
            'Set-Cookie': 'ecn_token=' + token + '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400',
          },
        });
      }

      var html = await env.ECN_PRO_CONTENT.get('pro-map');

      if (!html) {
        return new Response('Map content not found', { status: 500 });
      }

      var subscriberName = payload.name || 'Subscriber';
      var subscriberId = payload.sub || '';
      html = html.replace('</body>', watermarkHTML(subscriberName, subscriberId) + '</body>');

      return new Response(html, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }

    // Everything else — serve normally
    return env.ASSETS.fetch(request);
  },
};

// ─── Data API handlers ───

async function handleGymsRequest(request, env) {
  // Check referrer — allow requests from our own domains
  var referrer = request.headers.get('Referer') || '';
  var origin = request.headers.get('Origin') || '';
  var source = referrer || origin;

  // Also allow if they have a valid JWT (pro subscribers)
  var hasValidToken = false;
  var cookies = request.headers.get('Cookie') || '';
  var tokenMatch = cookies.match(/ecn_token=([^;]+)/);
  if (tokenMatch) {
    var payload = await validateJWT(tokenMatch[1], env.JWT_SECRET);
    if (payload) hasValidToken = true;
  }

  if (!hasValidToken) {
    // Check referrer for free map access
    var allowed = false;
    for (var i = 0; i < ALLOWED_REFERRERS.length; i++) {
      if (source.indexOf(ALLOWED_REFERRERS[i]) >= 0) {
        allowed = true;
        break;
      }
    }
    if (!allowed) {
      return new Response(JSON.stringify({ error: 'Forbidden' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  // Serve cached data or fetch fresh
  var data = await getCachedData(env, 'cache:gyms', env.SHEET_CSV_URL);
  if (!data) {
    return new Response(JSON.stringify({ error: 'Failed to load gym data' }), {
      status: 502,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return new Response(data, {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Cache-Control': 'private, max-age=60',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

async function handleRoundupRequest(request, env) {
  // Roundup data is Pro-only — require valid JWT
  var cookies = request.headers.get('Cookie') || '';
  var tokenMatch = cookies.match(/ecn_token=([^;]+)/);
  var token = tokenMatch ? tokenMatch[1] : null;

  if (!token) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  var payload = await validateJWT(token, env.JWT_SECRET);
  if (!payload) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  var data = await getCachedData(env, 'cache:roundup', env.ROUNDUP_CSV_URL);
  if (!data) {
    return new Response(JSON.stringify({ error: 'Failed to load roundup data' }), {
      status: 502,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return new Response(data, {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Cache-Control': 'private, max-age=60',
    },
  });
}

// ─── KV Cache ───

async function getCachedData(env, cacheKey, sourceUrl) {
  // Try cache first
  try {
    var cached = await env.ECN_PRO_CONTENT.getWithMetadata(cacheKey);
    if (cached && cached.value && cached.metadata) {
      var age = (Date.now() - cached.metadata.timestamp) / 1000;
      if (age < CACHE_TTL) {
        return cached.value;
      }
    }
  } catch (e) {
    // Cache miss, continue to fetch
  }

  // Fetch fresh data from Google Sheets
  try {
    var resp = await fetch(sourceUrl);
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    var data = await resp.text();

    // Store in cache with timestamp
    try {
      await env.ECN_PRO_CONTENT.put(cacheKey, data, {
        metadata: { timestamp: Date.now() },
      });
    } catch (e) {
      // Cache write failed, non-fatal
    }

    return data;
  } catch (e) {
    // If fetch fails, try serving stale cache
    try {
      var stale = await env.ECN_PRO_CONTENT.get(cacheKey);
      if (stale) return stale;
    } catch (e2) {
      // Nothing available
    }
    return null;
  }
}

// ─── JWT Validation ───

async function validateJWT(token, secret) {
  try {
    var parts = token.split('.');
    if (parts.length !== 3) return null;

    var data = parts[0] + '.' + parts[1];

    var key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    var signature = Uint8Array.from(
      atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')),
      function(c) { return c.charCodeAt(0); }
    );

    var valid = await crypto.subtle.verify(
      'HMAC', key, signature, new TextEncoder().encode(data)
    );

    if (!valid) return null;

    var payload = JSON.parse(
      atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'))
    );

    if (payload.exp < Math.floor(Date.now() / 1000)) return null;

    return payload;
  } catch (e) {
    return null;
  }
}

// ─── Watermark ───

function watermarkHTML(name, id) {
  var shortId = id.substring(0, 8);
  var line = 'ECN Pro \u2014 Licensed to ' + name + ' (' + shortId + ')          ';
  var row = '';
  for (var i = 0; i < 6; i++) {
    row += line;
  }
  var rows = '';
  for (var j = 0; j < 12; j++) {
    rows += row + '<br>';
  }

  return '<div id="ecn-watermark" style="'
    + 'position:fixed;'
    + 'top:0;'
    + 'left:0;'
    + 'width:100%;'
    + 'height:100%;'
    + 'pointer-events:none;'
    + 'z-index:9999;'
    + 'overflow:hidden;'
    + '">'
    + '<div style="'
    + 'position:absolute;'
    + 'top:50%;'
    + 'left:50%;'
    + 'transform:translate(-50%,-50%) rotate(-30deg);'
    + 'white-space:nowrap;'
    + 'font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;'
    + 'font-size:18px;'
    + 'color:rgba(0,0,0,0.06);'
    + 'letter-spacing:2px;'
    + 'user-select:none;'
    + '-webkit-user-select:none;'
    + 'line-height:120px;'
    + 'text-align:center;'
    + 'width:200%;'
    + '">'
    + rows
    + '</div>'
    + '</div>';
}

// ─── Access Denied Page ───

function accessDeniedHTML() {
  return '<!DOCTYPE html>'
    + '<html lang="en">'
    + '<head>'
    + '<meta charset="UTF-8">'
    + '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
    + '<title>ECN Pro \u2014 Access Required</title>'
    + '<style>'
    + '* { margin: 0; padding: 0; box-sizing: border-box; }'
    + 'body {'
    + '  font-family: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif;'
    + '  display: flex;'
    + '  align-items: center;'
    + '  justify-content: center;'
    + '  min-height: 100vh;'
    + '  background: #f5f5f5;'
    + '  color: #1a1a1a;'
    + '}'
    + '.container {'
    + '  text-align: center;'
    + '  max-width: 440px;'
    + '  padding: 40px 24px;'
    + '}'
    + 'h1 {'
    + '  font-size: 24px;'
    + '  margin-bottom: 12px;'
    + '}'
    + 'p {'
    + '  font-size: 16px;'
    + '  color: #555;'
    + '  line-height: 1.5;'
    + '  margin-bottom: 28px;'
    + '}'
    + '.cta {'
    + '  display: inline-block;'
    + '  padding: 14px 28px;'
    + '  background: #1a1a1a;'
    + '  color: #fff;'
    + '  text-decoration: none;'
    + '  border-radius: 6px;'
    + '  font-size: 15px;'
    + '  font-weight: 500;'
    + '  transition: background 0.2s;'
    + '}'
    + '.cta:hover { background: #333; }'
    + '.login-link {'
    + '  display: block;'
    + '  margin-top: 20px;'
    + '  font-size: 14px;'
    + '  color: #777;'
    + '}'
    + '.login-link a { color: #555; }'
    + '</style>'
    + '</head>'
    + '<body>'
    + '<div class="container">'
    + '<h1>ECN Pro \u2014 Site Intelligence Platform</h1>'
    + '<p>Access to this tool requires an active ECN Pro subscription.</p>'
    + '<a href="https://www.euroclimbing.news/pro" class="cta">Learn more about ECN Pro</a>'
    + '<span class="login-link">'
    + 'Already a subscriber? <a href="https://www.euroclimbing.news/membership">Log in here</a>'
    + '</span>'
    + '</div>'
    + '</body>'
    + '</html>';
}
