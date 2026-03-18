const ALLOWED_HOSTS = [
  "vivatops.store",
  "lob1.newserbir.site",
  "cdn.jsdelivr.net",
];

const PROXY_PATH = "/api/embed-proxy";

function isAllowedHost(hostname) {
  return ALLOWED_HOSTS.some(
    (host) => hostname === host || hostname.endsWith(`.${host}`),
  );
}

function toProxyUrl(url) {
  return `${PROXY_PATH}?url=${encodeURIComponent(url)}`;
}

function rewriteIframeSrc(html, baseUrl) {
  return html.replace(
    /(<iframe\b[^>]*?\bsrc\s*=\s*["'])([^"']+)(["'][^>]*>)/gi,
    (_match, prefix, src, suffix) => {
      if (
        src.startsWith("data:") ||
        src.startsWith("javascript:") ||
        src.startsWith("about:")
      ) {
        return `${prefix}${src}${suffix}`;
      }

      let absolute;
      try {
        absolute = new URL(src, baseUrl).toString();
      } catch {
        return `${prefix}${src}${suffix}`;
      }
      return `${prefix}${toProxyUrl(absolute)}${suffix}`;
    },
  );
}

function sanitizeHtml(html, baseUrl) {
  let output = html;

  // Disable the upstream anti-sandbox block that renders:
  // "Sandboxed Embedding Blocked / Sandbox not Allowed / Prohibited".
  output = output.replace(
    /var\s+sandboxCheckPassed\s*=\s*!true\s*\|\|\s*!detectAndBlockSandbox\(\)\s*;/g,
    "var sandboxCheckPassed = true;",
  );

  return rewriteIframeSrc(output, baseUrl);
}

export default async (request) => {
  const requestUrl = new URL(request.url);
  const upstream = requestUrl.searchParams.get("url");

  if (!upstream) {
    return new Response("Missing url parameter", { status: 400 });
  }

  let parsed;
  try {
    parsed = new URL(upstream);
  } catch {
    return new Response("Invalid URL", { status: 400 });
  }

  if (!["https:", "http:"].includes(parsed.protocol)) {
    return new Response("Unsupported protocol", { status: 400 });
  }

  if (!isAllowedHost(parsed.hostname)) {
    return new Response("Domain not allowed", { status: 403 });
  }

  try {
    const upstreamHeaders = new Headers();
    upstreamHeaders.set(
      "user-agent",
      request.headers.get("user-agent") || "Mozilla/5.0",
    );
    upstreamHeaders.set("referer", "https://vivatops.store/");
    upstreamHeaders.set("origin", "https://vivatops.store");
    if (request.headers.has("range")) {
      upstreamHeaders.set("range", request.headers.get("range"));
    }

    const upstreamResponse = await fetch(parsed.toString(), {
      method: "GET",
      headers: upstreamHeaders,
      redirect: "follow",
    });

    const contentType = upstreamResponse.headers.get("content-type") || "";
    const headers = new Headers(upstreamResponse.headers);
    headers.delete("content-security-policy");
    headers.delete("x-frame-options");
    headers.delete("content-length");
    headers.set("Access-Control-Allow-Origin", "*");
    headers.set("Access-Control-Allow-Methods", "GET, OPTIONS");

    if (contentType.includes("text/html")) {
      const html = await upstreamResponse.text();
      const sanitized = sanitizeHtml(html, upstreamResponse.url || parsed.toString());
      headers.set("content-type", "text/html; charset=utf-8");
      return new Response(sanitized, {
        status: upstreamResponse.status,
        headers,
      });
    }

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      headers,
    });
  } catch {
    return new Response("Failed to load upstream content", { status: 502 });
  }
};

export const config = {
  path: PROXY_PATH,
};
