/**
 * MHR-CFW Exit Worker — Deno Deploy version
 * Adapted from Cloudflare Workers implementation
 */

const AUTH_KEY = Deno.env.get("AUTH_KEY") || "CHANGE_ME_TO_A_STRONG_SECRET";
const DEFAULT_AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";

const RELAY_HOP_HEADER = "x-relay-hop";
const MAX_BATCH_SIZE = 40;

const SKIP_HEADERS = new Set([
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "proxy-connection",
  "proxy-authorization",
  "priority",
  "te",
]);

/**
 * Main request handler
 */
async function handleRequest(req: Request): Promise<Response> {
  // Fail-closed if AUTH_KEY not configured
  if (AUTH_KEY === DEFAULT_AUTH_KEY) {
    return jsonResponse({ e: "configure AUTH_KEY in environment" }, 500);
  }

  if (req.method !== "POST") {
    return jsonResponse({ e: "method not allowed" }, 405);
  }

  if (req.headers.get(RELAY_HOP_HEADER) === "1") {
    return jsonResponse({ e: "loop detected" }, 508);
  }

  let reqBody;
  try {
    reqBody = await req.json();
  } catch {
    return jsonResponse({ e: "bad json" }, 400);
  }

  if (!reqBody || reqBody.k !== AUTH_KEY) {
    return jsonResponse({ e: "unauthorized" }, 401);
  }

  const selfHost = new URL(req.url).hostname;

  // Batch mode
  if (Array.isArray(reqBody.q)) {
    if (reqBody.q.length === 0) return jsonResponse({ q: [] });
    if (reqBody.q.length > MAX_BATCH_SIZE) {
      return jsonResponse(
        { e: `batch too large (${reqBody.q.length} > ${MAX_BATCH_SIZE})` },
        400
      );
    }

    const results = await Promise.all(
      reqBody.q.map((item) =>
        processOne(item, selfHost).catch((err) => ({
          e: `fetch failed: ${String(err)}`,
        }))
      )
    );
    return jsonResponse({ q: results });
  }

  // Single mode
  try {
    const result = await processOne(reqBody, selfHost);
    if (result.e) {
      return jsonResponse(result, 400);
    }
    return jsonResponse(result);
  } catch (err) {
    return jsonResponse({ e: `fetch failed: ${String(err)}` }, 502);
  }
}

/**
 * Process single request item
 */
async function processOne(
  item: Record<string, any>,
  selfHost: string
): Promise<Record<string, any>> {
  // Validation
  if (!item || typeof item !== "object") {
    return { e: "bad item" };
  }

  if (
    !item.u ||
    typeof item.u !== "string" ||
    !/^https?:\/\//i.test(item.u)
  ) {
    return { e: "bad url" };
  }

  let targetUrl: URL;
  try {
    targetUrl = new URL(item.u);
  } catch {
    return { e: "bad url" };
  }

  if (targetUrl.hostname === selfHost) {
    return { e: "self-fetch blocked" };
  }

  // Build headers
  const headers = new Headers();
  if (item.h && typeof item.h === "object") {
    for (const [k, v] of Object.entries(item.h)) {
      if (SKIP_HEADERS.has(k.toLowerCase())) continue;
      try {
        headers.set(k, String(v));
      } catch {
        // Skip problematic headers
      }
    }
  }
  headers.set(RELAY_HOP_HEADER, "1");

  // Prepare fetch options
  const method = (item.m || "GET").toUpperCase();
  const fetchOptions: RequestInit = {
    method,
    headers,
    redirect: item.r === false ? "manual" : "follow",
  };

  // Handle body
  const bodyAllowed = method !== "GET" && method !== "HEAD";
  if (item.b && bodyAllowed) {
    try {
      const binaryString = atob(item.b);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      fetchOptions.body = bytes;
      if (item.ct && !headers.has("content-type")) {
        headers.set("content-type", item.ct);
      }
    } catch {
      return { e: "bad body base64" };
    }
  }

  // Execute fetch
  let resp: Response;
  try {
    resp = await fetch(targetUrl.toString(), fetchOptions);
  } catch (err) {
    return { e: `fetch failed: ${String(err)}` };
  }

  // Process response
  const buffer = await resp.arrayBuffer();
  const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));

  const responseHeaders: Record<string, string> = {};
  resp.headers.forEach((v, k) => {
    responseHeaders[k] = v;
  });

  return {
    s: resp.status,
    h: responseHeaders,
    b: base64,
  };
}

/**
 * Helper: JSON response
 */
function jsonResponse(
  obj: Record<string, any>,
  status = 200
): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * Deno Deploy entry point
 */
Deno.serve({ port: 8000 }, handleRequest);
