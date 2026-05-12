// مقدار WORKER_HOST را با hostname مورد نظر خودت عوض کن
const WORKER_HOST = "CHANGE_ME_WORKER_HOST";

async function handleRequest(request: Request): Promise<Response> {
  try {
    if (request.headers.get("x-relay-hop") === "1") {
      return json({ e: "loop detected" }, 508);
    }

    const req = await request.json();
    if (!req.u) {
      return json({ e: "missing url" }, 400);
    }

    const targetURL = new URL(req.u);
    if (isSelfFetch(targetURL.hostname)) {
      return json({ e: "self-fetch blocked" }, 400);
    }

    const headers = new Headers();
    if (req.h && typeof req.h === "object") {
      for (const [key, value] of Object.entries(req.h)) {
        headers.set(key, value);
      }
    }
    headers.set("x-relay-hop", "1");

    const options: RequestInit = {
      method: (req.m || "GET").toUpperCase(),
      headers,
      redirect: req.r === false ? "manual" : "follow",
    };

    if (req.b) {
      options.body = Uint8Array.from(atob(req.b), (char) => char.charCodeAt(0));
    }

    const resp = await fetch(targetURL.toString(), options);
    const buffer = await resp.arrayBuffer();
    const bytes = new Uint8Array(buffer);

    return json({
      s: resp.status,
      h: headersToObject(resp.headers),
      b: bytesToBase64(bytes),
    });
  } catch (err) {
    return json({ e: String(err) }, 500);
  }
}

function headersToObject(headers: Headers): Record<string, string> {
  const obj: Record<string, string> = {};
  headers.forEach((value, key) => {
    obj[key] = value;
  });
  return obj;
}

function isSelfFetch(hostname: string): boolean {
  if (!WORKER_HOST || WORKER_HOST === "CHANGE_ME_WORKER_HOST") {
    return false;
  }
  return hostname === WORKER_HOST || hostname.endsWith("." + WORKER_HOST);
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + chunkSize)));
  }
  return btoa(binary);
}

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}

// نقطه ورود اصلی برای Deno Deploy
Deno.serve(handleRequest);
