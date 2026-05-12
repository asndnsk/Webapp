/**
 * پراکسی پیشرفته با پشتیبانی از Session و Cookie
 * @version 4.0.0
 */

const AUTH_KEY = Deno.env.get("AUTH_KEY") || "";
const WORKER_HOST = Deno.env.get("WORKER_HOST") || null;
const ENABLE_LOGGING = Deno.env.get("ENABLE_LOGGING") === "true";
const SESSION_TTL = parseInt(Deno.env.get("SESSION_TTL") || "3600"); // 1 ساعت

// ذخیره‌سازی ساده Cookie (برای محیط بدون状態)
// در محیط واقعی باید از Redis یا KV Store استفاده کنید
const sessionStore = new Map<string, Map<string, string>>();
const userAgentStore = new Map<string, string>();

async function handleRequest(request: Request): Promise<Response> {
  const requestId = crypto.randomUUID();
  
  try {
    // بررسی لوپ
    if (request.headers.get("x-relay-hop") === "1") {
      return jsonResponse({ error: "loop detected" }, 508);
    }

    // دریافت Client ID (از IP + User-Agent)
    const clientIP = request.headers.get("cf-connecting-ip") || 
                     request.headers.get("x-forwarded-for") || 
                     "unknown";
    const userAgent = request.headers.get("user-agent") || "unknown";
    const clientId = `${clientIP}:${userAgent}`;
    
    // ذخیره User-Agent برای استفاده بعدی
    userAgentStore.set(clientId, userAgent);
    
    // GET درخواست = خروجی HTML برای تست
    if (request.method === "GET") {
      return new Response(getStatusHTML(Array.from(sessionStore.keys()).length), {
        headers: { "content-type": "text/html" }
      });
    }
    
    // Parse بدنه
    let reqBody;
    try {
      reqBody = await request.json();
    } catch {
      return jsonResponse({ error: "invalid json" }, 400);
    }
    
    // احراز هویت
    if (AUTH_KEY && reqBody.k !== AUTH_KEY) {
      return jsonResponse({ error: "unauthorized" }, 401);
    }
    
    // مدیریت درخواست با قابلیت حفظ کوکی
    return await handleWithSession(reqBody, clientId, requestId, request);
    
  } catch (err) {
    console.error(err);
    return jsonResponse({ error: String(err) }, 500);
  }
}

async function handleWithSession(req: any, clientId: string, requestId: string, originalRequest: Request): Promise<Response> {
  // دریافت یا ایجاد سشن برای این کلاینت
  let cookies = sessionStore.get(clientId) || new Map();
  
  // ساخت هدرهای کوکی از سشن ذخیره شده
  const cookieHeader = Array.from(cookies.entries())
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");
  
  // ساخت هدرهای درخواست
  const headers = new Headers();
  
  // اضافه کردن هدرهای سفارشی از کاربر
  if (req.h && typeof req.h === "object") {
    for (const [key, value] of Object.entries(req.h)) {
      if (typeof value === "string") {
        headers.set(key, value);
      }
    }
  }
  
  // اضافه کردن کوکی‌های ذخیره شده
  if (cookieHeader) {
    headers.set("cookie", cookieHeader);
  }
  
  // اضافه کردن هدرهای اصلی
  headers.set("x-relay-hop", "1");
  headers.set("x-request-id", requestId);
  headers.set("user-agent", userAgentStore.get(clientId) || originalRequest.headers.get("user-agent") || "Mozilla/5.0");
  
  // اضافه کردن هدرهای مهم برای شبیه‌سازی مرورگر واقعی
  headers.set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
  headers.set("accept-language", "en-US,en;q=0.5");
  headers.set("accept-encoding", "gzip, deflate, br");
  headers.set("sec-ch-ua", '"Not A(Brand";v="99", "Chromium";v="121"');
  headers.set("sec-ch-ua-mobile", "?0");
  headers.set("sec-ch-ua-platform", '"Windows"');
  headers.set("sec-fetch-dest", "document");
  headers.set("sec-fetch-mode", "navigate");
  headers.set("sec-fetch-site", "none");
  headers.set("upgrade-insecure-requests", "1");
  
  // پشتیبانی از WebSocket (اگر درخواست upgrade باشد)
  const isWebSocket = req.m === "WEBSOCKET" || reqBody.ws === true;
  
  const options: RequestInit = {
    method: (req.m || "GET").toUpperCase(),
    headers,
    redirect: req.r === false ? "manual" : "follow",
  };
  
  // اضافه کردن بدنه در صورت وجود
  if (req.b) {
    try {
      options.body = base64ToBytes(req.b);
    } catch {
      return jsonResponse({ error: "invalid base64 body" }, 400);
    }
  }
  
  try {
    const targetURL = new URL(req.u);
    
    // جلوگیری از self-fetch
    if (WORKER_HOST && (targetURL.hostname === WORKER_HOST || targetURL.hostname.endsWith(`.${WORKER_HOST}`))) {
      return jsonResponse({ error: "self-fetch blocked" }, 400);
    }
    
    // WebSocket پشتیبانی
    if (isWebSocket) {
      return await handleWebSocket(targetURL, headers);
    }
    
    // درخواست معمولی
    const resp = await fetch(targetURL.toString(), options);
    const buffer = await resp.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    
    // **ذخیره کوکی‌های جدید از پاسخ**
    const setCookieHeaders = resp.headers.getSetCookie();
    if (setCookieHeaders.length > 0) {
      for (const setCookie of setCookieHeaders) {
        // استخراج نام و مقدار کوکی
        const match = setCookie.match(/^([^=]+)=([^;]+)/);
        if (match) {
          const [_, name, value] = match;
          cookies.set(name, value);
          
          // بررسی انقضای کوکی
          if (setCookie.includes("Expires=") || setCookie.includes("Max-Age=0")) {
            cookies.delete(name);
          }
        }
      }
      
      // به‌روزرسانی سشن
      sessionStore.set(clientId, cookies);
      
      // پاک کردن سشن‌های قدیمی (هر 100 درخواست یکبار)
      if (Math.random() < 0.01) {
        cleanOldSessions();
      }
      
      if (ENABLE_LOGGING) {
        console.log(`[${requestId}] Stored ${cookies.size} cookies for client ${clientId}`);
      }
    }
    
    // حذف هدر Set-Cookie از پاسخ (اختیاری)
    const responseHeaders = headersToObject(resp.headers);
    delete responseHeaders["set-cookie"];
    
    return jsonResponse({
      s: resp.status,
      h: responseHeaders,
      b: bytesToBase64(bytes),
      cookies_stored: cookies.size
    });
    
  } catch (err) {
    console.error(`[${requestId}] Fetch error:`, err);
    return jsonResponse({ error: String(err) }, 500);
  }
}

// پشتیبانی از WebSocket
async function handleWebSocket(targetURL: URL, headers: Headers): Promise<Response> {
  try {
    // تبدیل به ws:// یا wss://
    const wsURL = new URL(targetURL.toString());
    wsURL.protocol = wsURL.protocol === "https:" ? "wss:" : "ws:";
    
    // این یک پیاده‌سازی ساده است
    // برای WebSocket واقعی نیاز به کانکشن مستقیم دارید
    return jsonResponse({ 
      error: "WebSocket requires direct connection",
      ws_url: wsURL.toString(),
      suggestion: "Use native WebSocket API directly"
    }, 501);
    
  } catch (err) {
    return jsonResponse({ error: String(err) }, 500);
  }
}

// پاک کردن سشن‌های قدیمی
function cleanOldSessions() {
  // محدود کردن تعداد سشن‌ها برای جلوگیری از مصرف حافظه
  if (sessionStore.size > 1000) {
    const toDelete = Array.from(sessionStore.keys()).slice(0, 200);
    for (const key of toDelete) {
      sessionStore.delete(key);
    }
    if (ENABLE_LOGGING) {
      console.log(`Cleaned old sessions, now ${sessionStore.size} active`);
    }
  }
}

// HTML وضعیت برای تست
function getStatusHTML(activeSessions: number): string {
  return `
<!DOCTYPE html>
<html>
<head>
  <title>Proxy Status</title>
  <style>
    body { font-family: monospace; padding: 20px; background: #0a0e27; color: #00ff88; }
    .status { background: #1a1f35; padding: 20px; border-radius: 10px; }
    .good { color: #00ff88; }
    .info { color: #ffaa00; }
  </style>
</head>
<body>
  <div class="status">
    <h1>🚀 Relay Proxy Active</h1>
    <p>Status: <span class="good">✅ Running</span></p>
    <p>Active Sessions: <span class="info">${activeSessions}</span></p>
    <p>Session TTL: ${SESSION_TTL} seconds</p>
    <hr>
    <p>To use this proxy, send POST requests with:</p>
    <pre>{
  "k": "your-auth-key",
  "u": "https://target-site.com",
  "m": "GET|POST|...",
  "h": {"Custom-Header": "value"},
  "b": "base64-body"
}</pre>
  </div>
</body>
</html>
  `;
}

// توابع کمکی (همان‌های قبلی)
function headersToObject(headers: Headers): Record<string, string> {
  const obj: Record<string, string> = {};
  headers.forEach((value, key) => {
    if (key.toLowerCase() !== "set-cookie") {
      obj[key] = value;
    }
  });
  return obj;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    binary += String.fromCharCode.apply(null, Array.from(chunk));
  }
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 
      "content-type": "application/json",
      "access-control-allow-origin": "*"
    }
  });
}

Deno.serve(handleRequest);
