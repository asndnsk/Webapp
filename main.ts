/**
 * پراکسی پیشرفته برای Deno Deploy
 * کاملاً سازگار با Google Apps Script
 * @version 3.0.0
 */

// ========== تنظیمات از Environment Variables ==========
const AUTH_KEY = Deno.env.get("AUTH_KEY") || ""; // کلید احراز هویت (اجباری)
const WORKER_HOST = Deno.env.get("WORKER_HOST") || null;
const ENABLE_LOGGING = Deno.env.get("ENABLE_LOGGING") === "true";
const MAX_BODY_SIZE = parseInt(Deno.env.get("MAX_BODY_SIZE") || "10485760"); // 10MB
const ALLOWED_ORIGINS = Deno.env.get("ALLOWED_ORIGINS")?.split(",") || [];

// هدرهایی که نباید ارسال شوند (مطابق با SKIP_HEADERS در GAS)
const SKIP_HEADERS: Record<string, boolean> = {
  host: true,
  connection: true,
  "content-length": true,
  "transfer-encoding": true,
  "proxy-connection": true,
  "proxy-authorization": true,
};

// ========== توابع اصلی ==========

async function handleRequest(request: Request): Promise<Response> {
  const startTime = Date.now();
  const requestId = crypto.randomUUID();
  
  try {
    if (ENABLE_LOGGING) {
      console.log(`[${requestId}] Incoming request to ${request.method} ${request.url}`);
    }

    // بررسی لوپ
    if (request.headers.get("x-relay-hop") === "1") {
      return jsonResponse({ e: "loop detected" }, 508);
    }

    // Parse بدنه درخواست
    let reqBody;
    try {
      reqBody = await request.json();
    } catch {
      return jsonResponse({ e: "invalid json body" }, 400);
    }

    // ========== احراز هویت با کلید (سازگار با GAS) ==========
    if (AUTH_KEY && reqBody.k !== AUTH_KEY) {
      if (ENABLE_LOGGING) {
        console.log(`[${requestId}] Unauthorized attempt`);
      }
      return jsonResponse({ e: "unauthorized" }, 401);
    }

    // پشتیبانی از درخواست تکی
    if (reqBody.u) {
      const result = await handleSingleRequest(reqBody, requestId);
      return jsonResponse(result);
    }
    
    // پشتیبانی از درخواست دسته‌ای (batch) - سازگار با doBatch_ در GAS
    if (Array.isArray(reqBody.q)) {
      const results = await handleBatchRequests(reqBody.q, requestId);
      return jsonResponse({ q: results });
    }

    return jsonResponse({ e: "missing url or batch array" }, 400);
    
  } catch (err) {
    console.error(`[${requestId}] Error:`, err);
    return jsonResponse({ e: String(err) }, 500);
  }
}

// ========== پردازش درخواست تکی ==========

async function handleSingleRequest(req: any, requestId: string): Promise<any> {
  // اعتبارسنجی URL (مطابق isValidRelayRequest_ در GAS)
  if (!isValidUrl(req.u)) {
    return { e: "bad url" };
  }

  let targetURL: URL;
  try {
    targetURL = new URL(req.u);
    if (!["http:", "https:"].includes(targetURL.protocol)) {
      return { e: "bad url: only HTTP/HTTPS allowed" };
    }
  } catch {
    return { e: "bad url: invalid format" };
  }

  // جلوگیری از self-fetch
  if (isSelfFetch(targetURL.hostname)) {
    return { e: "self-fetch blocked" };
  }

  // جلوگیری از دسترسی به IP های داخلی
  if (isInternalIP(targetURL.hostname)) {
    return { e: "internal ip blocked" };
  }

  // ساخت هدرها (با فیلتر SKIP_HEADERS)
  const headers = new Headers();
  if (req.h && typeof req.h === "object") {
    for (const [key, value] of Object.entries(req.h)) {
      const lowerKey = key.toLowerCase();
      // فیلتر هدرهای ممنوع (مطابق با SKIP_HEADERS در GAS)
      if (!SKIP_HEADERS[lowerKey] && !isSensitiveHeader(lowerKey)) {
        headers.set(key, String(value));
      }
    }
  }
  headers.set("x-relay-hop", "1");
  headers.set("x-request-id", requestId);

  // تنظیمات درخواست (سازگار با buildWorkerPayload_ در GAS)
  const options: RequestInit = {
    method: (req.m || "GET").toUpperCase(),
    headers,
    redirect: req.r === false ? "manual" : "follow",
  };

  // پردازش بدنه (پشتیبانی از b و ct)
  if (req.b) {
    try {
      const bodyBytes = base64ToBytes(req.b);
      if (bodyBytes.length > MAX_BODY_SIZE) {
        return { e: `body size exceeds limit (${MAX_BODY_SIZE} bytes)` };
      }
      options.body = bodyBytes;
      
      // اگر Content-Type مشخص شده، به هدرها اضافه کن
      if (req.ct) {
        headers.set("content-type", req.ct);
      }
    } catch {
      return { e: "invalid base64 body" };
    }
  }

  // اجرای درخواست با timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30000);
  
  try {
    const resp = await fetch(targetURL.toString(), { ...options, signal: controller.signal });
    clearTimeout(timeoutId);
    
    const buffer = await resp.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    
    if (ENABLE_LOGGING) {
      const duration = Date.now() - startTimeMap.get(requestId) || 0;
      console.log(`[${requestId}] Response: ${resp.status} in ${duration}ms`);
    }
    
    // خروجی سازگار با فرمت مورد انتظار GAS
    return {
      s: resp.status,
      h: headersToObject(resp.headers),
      b: bytesToBase64(bytes),
    };
    
  } catch (fetchError) {
    clearTimeout(timeoutId);
    if (fetchError.name === "AbortError") {
      return { e: "request timeout (30s)" };
    }
    throw fetchError;
  }
}

// ========== پردازش درخواست دسته‌ای (Batch) ==========

async function handleBatchRequests(items: any[], requestId: string): Promise<any[]> {
  if (ENABLE_LOGGING) {
    console.log(`[${requestId}] Processing batch of ${items.length} requests`);
  }
  
  // اجرای موازی درخواست‌ها برای بهبود performance
  const promises = items.map(async (item, index) => {
    try {
      if (!isValidUrl(item.u)) {
        return { e: "bad url" };
      }
      return await handleSingleRequest(item, `${requestId}_${index}`);
    } catch (err) {
      return { e: String(err) };
    }
  });
  
  const results = await Promise.all(promises);
  
  if (ENABLE_LOGGING) {
    console.log(`[${requestId}] Batch completed: ${results.length} requests`);
  }
  
  return results;
}

// ========== توابع کمکی ==========

// ذخیره زمان شروع برای هر درخواست (برای لاگ)
const startTimeMap = new Map<string, number>();

function isValidUrl(url: string): boolean {
  return typeof url === "string" && /^https?:\/\//i.test(url);
}

function isSelfFetch(hostname: string): boolean {
  if (!WORKER_HOST) {
    return false;
  }
  const cleanHostname = hostname.split(":")[0];
  const cleanWorkerHost = WORKER_HOST.split(":")[0];
  
  return cleanHostname === cleanWorkerHost || 
         cleanHostname.endsWith("." + cleanWorkerHost);
}

function isInternalIP(hostname: string): boolean {
  const internalPatterns = [
    /^127\.\d+\.\d+\.\d+$/,
    /^10\.\d+\.\d+\.\d+$/,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$/,
    /^192\.168\.\d+\.\d+$/,
    /^169\.254\.\d+\.\d+$/,
    /^::1$/,
    /^fc00:/,
    /^fe80:/
  ];
  
  return internalPatterns.some(pattern => pattern.test(hostname));
}

function isSensitiveHeader(headerName: string): boolean {
  const sensitive = [
    "authorization",
    "cookie",
    "set-cookie",
    "x-forwarded-for",
    "x-real-ip"
  ];
  return sensitive.includes(headerName.toLowerCase());
}

function headersToObject(headers: Headers): Record<string, string> {
  const obj: Record<string, string> = {};
  headers.forEach((value, key) => {
    const lowerKey = key.toLowerCase();
    if (!SKIP_HEADERS[lowerKey] && !isSensitiveHeader(lowerKey)) {
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
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "Content-Type"
  };
  
  if (ALLOWED_ORIGINS.length > 0) {
    headers["access-control-allow-origin"] = ALLOWED_ORIGINS.join(",");
  }
  
  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}

function handleOptions(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "access-control-allow-headers": "Content-Type",
      "access-control-max-age": "86400"
    }
  });
}

// ========== نقطه ورود اصلی ==========

Deno.serve(async (request: Request) => {
  // CORS preflight
  if (request.method === "OPTIONS") {
    return handleOptions();
  }
  
  // فقط POST مجاز است (مثل GAS)
  if (request.method !== "POST") {
    return jsonResponse({ e: "method not allowed" }, 405);
  }
  
  // ثبت زمان شروع
  const requestId = crypto.randomUUID();
  startTimeMap.set(requestId, Date.now());
  
  const response = await handleRequest(request);
  
  // پاک کردن زمان شروع
  startTimeMap.delete(requestId);
  
  return response;
});
