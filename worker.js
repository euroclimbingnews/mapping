// Public URLs that require authentication
var PROTECTED_PATHS = [
  '/climbing-map-v4',
  '/climbing-map-v4.html',
  '/climbing-map-v4/',
];

export default {
  async fetch(request, env) {
    var url = new URL(request.url);
    var path = url.pathname;

    // Handle protected Pro map paths
    if (PROTECTED_PATHS.some(function(p) { return path === p || path === p + '/'; })) {

      // Check for token in URL param first, then cookie
      var token = url.searchParams.get('token');
      var tokenFromParam = !!token;

      if (!token) {
        var cookies = request.headers.get('Cookie') || '';
        var match = cookies.match(/ecn_token=([^;]+)/);
        token = match ? match[1] : null;
      }

      // Validate the token
      var payload = token ? await validateJWT(token, env.JWT_SECRET) : null;

      if (!payload) {
        return new Response(accessDeniedHTML(), {
          status: 403,
          headers: { 'Content-Type': 'text/html' },
        });
      }

      // If token came via URL param, set cookie and redirect to clean URL
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

      // Token is valid — serve the Pro map from KV with watermark and export
      var html = await env.ECN_PRO_CONTENT.get('pro-map');

      if (!html) {
        return new Response('Map content not found', { status: 500 });
      }

      // Inject watermark and export button before closing </body> tag
      var subscriberName = payload.name || 'Subscriber';
      var subscriberId = payload.sub || '';
      var injection = watermarkHTML(subscriberName, subscriberId) + exportButtonHTML();
      html = html.replace('</body>', injection + '</body>');

      return new Response(html, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }

    // Everything else (free map, images, etc.) — serve normally
    return env.ASSETS.fetch(request);
  },
};

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
    + 'color:rgba(0,0,0,0.05);'
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

// ─── Export Button ───

function exportButtonHTML() {
  return '<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.2/jspdf.umd.min.js"><\/script>'
    + '<div id="ecn-export-control" style="'
    + 'position:fixed;'
    + 'top:10px;'
    + 'right:10px;'
    + 'z-index:10000;'
    + 'font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;'
    + '">'
    + '<button id="ecn-export-btn" style="'
    + 'background:#fff;'
    + 'border:none;'
    + 'border-radius:6px;'
    + 'padding:8px 14px;'
    + 'font-size:13px;'
    + 'font-weight:500;'
    + 'color:#333;'
    + 'cursor:pointer;'
    + 'box-shadow:0 1px 4px rgba(0,0,0,0.2);'
    + 'display:flex;'
    + 'align-items:center;'
    + 'gap:6px;'
    + 'transition:background 0.15s;'
    + '">'
    + '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    + '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>'
    + '<polyline points="7 10 12 15 17 10"/>'
    + '<line x1="12" y1="15" x2="12" y2="3"/>'
    + '</svg>'
    + 'Export'
    + '</button>'
    + '<div id="ecn-export-menu" style="'
    + 'display:none;'
    + 'margin-top:4px;'
    + 'background:#fff;'
    + 'border-radius:6px;'
    + 'box-shadow:0 2px 8px rgba(0,0,0,0.2);'
    + 'overflow:hidden;'
    + '">'
    + '<button class="ecn-export-option" data-format="jpg" style="'
    + 'display:block;'
    + 'width:100%;'
    + 'padding:10px 16px;'
    + 'border:none;'
    + 'background:#fff;'
    + 'font-size:13px;'
    + 'color:#333;'
    + 'cursor:pointer;'
    + 'text-align:left;'
    + 'transition:background 0.1s;'
    + '">Export as JPG</button>'
    + '<button class="ecn-export-option" data-format="pdf" style="'
    + 'display:block;'
    + 'width:100%;'
    + 'padding:10px 16px;'
    + 'border:none;'
    + 'border-top:1px solid #eee;'
    + 'background:#fff;'
    + 'font-size:13px;'
    + 'color:#333;'
    + 'cursor:pointer;'
    + 'text-align:left;'
    + 'transition:background 0.1s;'
    + '">Export as PDF</button>'
    + '</div>'
    + '</div>'
    + '<script>'
    + '(function() {'
    + '  var btn = document.getElementById("ecn-export-btn");'
    + '  var menu = document.getElementById("ecn-export-menu");'
    + '  var logoUrl = "/ECN_Pro_Logo.png";'
    + '  var logoImg = null;'
    + ''
    + '  var img = new Image();'
    + '  img.crossOrigin = "anonymous";'
    + '  img.onload = function() { logoImg = img; };'
    + '  img.src = logoUrl;'
    + ''
    + '  btn.addEventListener("click", function(e) {'
    + '    e.stopPropagation();'
    + '    menu.style.display = menu.style.display === "none" ? "block" : "none";'
    + '  });'
    + ''
    + '  document.addEventListener("click", function() {'
    + '    menu.style.display = "none";'
    + '  });'
    + ''
    + '  btn.addEventListener("mouseenter", function() { btn.style.background = "#f5f5f5"; });'
    + '  btn.addEventListener("mouseleave", function() { btn.style.background = "#fff"; });'
    + '  var options = document.querySelectorAll(".ecn-export-option");'
    + '  options.forEach(function(opt) {'
    + '    opt.addEventListener("mouseenter", function() { opt.style.background = "#f5f5f5"; });'
    + '    opt.addEventListener("mouseleave", function() { opt.style.background = "#fff"; });'
    + '  });'
    + ''
    + '  options.forEach(function(opt) {'
    + '    opt.addEventListener("click", function(e) {'
    + '      e.stopPropagation();'
    + '      menu.style.display = "none";'
    + '      var format = opt.getAttribute("data-format");'
    + '      exportMap(format);'
    + '    });'
    + '  });'
    + ''
    + '  function exportMap(format) {'
    + '    try {'
    + '      var mapCanvas = map.getCanvas();'
    + '      var width = mapCanvas.width;'
    + '      var height = mapCanvas.height;'
    + ''
    + '      var canvas = document.createElement("canvas");'
    + '      canvas.width = width;'
    + '      canvas.height = height;'
    + '      var ctx = canvas.getContext("2d");'
    + ''
    + '      ctx.drawImage(mapCanvas, 0, 0);'
    + ''
    + '      if (logoImg) {'
    + '        var logoHeight = 40;'
    + '        var logoWidth = logoImg.width * (logoHeight / logoImg.height);'
    + '        var padding = 12;'
    + '        var x = width - logoWidth - padding;'
    + '        var y = height - logoHeight - padding;'
    + ''
    + '        ctx.fillStyle = "rgba(255,255,255,0.85)";'
    + '        ctx.beginPath();'
    + '        if (ctx.roundRect) {'
    + '          ctx.roundRect(x - 8, y - 6, logoWidth + 16, logoHeight + 12, 4);'
    + '        } else {'
    + '          ctx.rect(x - 8, y - 6, logoWidth + 16, logoHeight + 12);'
    + '        }'
    + '        ctx.fill();'
    + ''
    + '        ctx.drawImage(logoImg, x, y, logoWidth, logoHeight);'
    + '      }'
    + ''
    + '      if (format === "jpg") {'
    + '        var link = document.createElement("a");'
    + '        link.download = "ECN-Pro-Map-Export.jpg";'
    + '        link.href = canvas.toDataURL("image/jpeg", 0.95);'
    + '        link.click();'
    + '      } else if (format === "pdf") {'
    + '        var jsPDF = window.jspdf.jsPDF;'
    + '        var imgData = canvas.toDataURL("image/jpeg", 0.95);'
    + '        var orientation = width > height ? "landscape" : "portrait";'
    + '        var pdf = new jsPDF(orientation, "px", [width, height]);'
    + '        pdf.addImage(imgData, "JPEG", 0, 0, width, height);'
    + '        pdf.save("ECN-Pro-Map-Export.pdf");'
    + '      }'
    + '    } catch (err) {'
    + '      alert("Export failed. Please try again.");'
    + '      console.error("ECN Export error:", err);'
    + '    }'
    + '  }'
    + '})();'
    + '<\/script>';
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
