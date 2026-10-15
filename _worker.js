import { connect } from "cloudflare:sockets";

// ============================================
// CONSTANTS & DEFAULT CONFIGURATION
// ============================================
const DEFAULT_LOCAL_PROXIES = [
  "bpb.yousef.isegaro.com",
  "galaxytunnel.cloud-ip.cc",
  "www.visa.com.hk",
  "www.visa.com.sg"
];

const DEFAULT_DOH_URL = ["https://cloudflare-dns.com/dns-query","https://dns.google/dns-query","https://dns.quad9.net/dns-query","https://dns.adguard-dns.com/dns-query"];
const CONNECTION_TIMEOUT_MS = 30000; // 30 seconds timeout
const DEFAULT_RATE_LIMIT_PER_MINUTE = 500;
const DEFAULT_WS_PATH = "galaxy-tunnel";
const MAX_CONFIG_PATH_LENGTH = 128;

// ============================================
// AD & TRACKER DOMAIN BLOCKING
// Domain-based filtering only; encrypted/server-side ads cannot be identified here.
// ============================================
const AD_DOMAIN_SUFFIXES = [
  "doubleclick.net",
  "googleadservices.com",
  "googlesyndication.com",
  "adservice.google.com",
  "pagead2.googlesyndication.com",
  "adcolony.com",
  "appsflyer.com",
  "unityads.unity3d.com",
  "vungle.com",
  "applovin.com",
  "flurry.com",
  "adjust.com",
  "branch.io",
  "admob.com",
  "mopub.com",
  "criteo.com",
  "taboola.com",
  "outbrain.com",
  "scorecardresearch.com",
  "quantserve.com",
  "popads.net",
  "inmobi.com",
  "adroll.com",
  "amazon-adsystem.com",
  "adsafeprotected.com",
  "moatads.com",
  "openx.net",
  "rubiconproject.com",
  "pubmatic.com"
];

function isAdDomain(domain) {
  if (!domain || typeof domain !== "string") return false;
  const lower = domain.toLowerCase().trim().replace(/\.$/, "");
  if (AD_DOMAIN_SUFFIXES.some((suffix) => lower === suffix || lower.endsWith("." + suffix))) {
    return true;
  }
  return /^(ad|ads|adservice|adserver|telemetry|track|tracker|analytics)\./i.test(lower);
}

// ============================================
// DESTINATION ROUTE RULES & SERVER FALLBACK
// Env format:
// ROUTE_RULES=[{"match":"youtube.com","server":"edge-a"}]
// ROUTE_SERVERS=[{"name":"edge-a","host":"proxy.example.com","port":443}]
// ============================================
function parseJsonEnv(value, fallback = []) {
  if (!value) return fallback;
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : fallback;
  } catch {
    return fallback;
  }
}

function routeMatch(host, rule) {
  const pattern = String(rule?.match || rule?.domain || rule?.ip || "").toLowerCase().trim();
  if (!pattern) return false;
  const value = String(host || "").toLowerCase().trim();
  if (pattern.startsWith("*.")) return value.endsWith(pattern.slice(1));
  return value === pattern || value.endsWith("." + pattern);
}

function resolveRouteTarget(address, port, rawRules, rawServers, logger) {
  const rules = parseJsonEnv(rawRules);
  const servers = parseJsonEnv(rawServers);
  const rule = rules.find((candidate) => routeMatch(address, candidate) &&
    (!candidate.port || Number(candidate.port) === Number(port)));
  if (!rule) return null;

  const server = servers.find((item) => String(item.name || item.id) === String(rule.server || ""));
  if (!server?.host || isPrivateOrBlockedHost(String(server.host))) {
    if (logger) logger.warn("ROUTE_SERVER_INVALID", { address, route: rule.server || null });
    return null;
  }
  return {
    name: String(server.name || server.id || "route-server"),
    host: String(server.host),
    port: Number(server.port || port),
    rule: String(rule.match || rule.domain || rule.ip || "")
  };
}

// ============================================
// STRUCTURED LOGGER WITH REQUEST ID (Item 9)
// ============================================
class Logger {
  constructor(requestId, clientIp = "unknown") {
    this.requestId = requestId;
    this.clientIp = clientIp;
  }

  log(level, event, details = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      requestId: this.requestId,
      clientIp: this.clientIp,
      event,
      ...details
    };
    if (level === "ERROR") {
      console.error(JSON.stringify(entry));
    } else if (level === "WARN") {
      console.warn(JSON.stringify(entry));
    } else {
      console.log(JSON.stringify(entry));
    }
  }

  info(event, details) {
    this.log("INFO", event, details);
  }

  warn(event, details) {
    this.log("WARN", event, details);
  }

  error(event, details) {
    this.log("ERROR", event, details);
  }
}

function generateRequestId() {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return "req_" + Math.random().toString(36).substring(2, 12);
}

// ============================================
// URL SANITIZATION & SSRF PROTECTION (Item 3)
// ============================================
function isPrivateOrBlockedHost(hostname) {
  if (!hostname) return true;
  const host = hostname.toLowerCase().trim();

  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "0.0.0.0" ||
    host === "::1" ||
    host === "[::1]" ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".lan")
  ) {
    return true;
  }

  // IPv4 Private Range Checks
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = host.match(ipv4Regex);
  if (match) {
    const [_, a, b] = match.map(Number);
    if (a === 10) return true;                         // 10.0.0.0/8
    if (a === 127) return true;                        // 127.0.0.0/8
    if (a === 169 && b === 254) return true;          // 169.254.0.0/16 Link-Local
    if (a === 172 && b >= 16 && b <= 31) return true;  // 172.16.0.0/12
    if (a === 192 && b === 168) return true;          // 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true;// 100.64.0.0/10 CGNAT
    if (a === 0) return true;                          // 0.0.0.0/8
  }

  // IPv6 Private & Local Range Checks
  if (host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80") || host.startsWith("[fc") || host.startsWith("[fd") || host.startsWith("[fe80")) {
    return true;
  }

  return false;
}

function sanitizeUrl(urlStr) {
  if (!urlStr || typeof urlStr !== "string") return null;
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    if (isPrivateOrBlockedHost(parsed.hostname)) {
      return null;
    }
    // Remove auth credentials from URL if any
    parsed.username = "";
    parsed.password = "";
    return parsed.toString();
  } catch {
    return null;
  }
}

// ============================================
// RATE LIMITER (Item 4)
// ============================================
class RateLimiter {
  constructor(limitPerMinute = DEFAULT_RATE_LIMIT_PER_MINUTE) {
    this.limit = limitPerMinute;
    this.records = new Map();
  }

  check(ip) {
    const now = Date.now();
    const windowMs = 60000;
    let clientRecord = this.records.get(ip);

    if (!clientRecord || now - clientRecord.startTime > windowMs) {
      clientRecord = { count: 1, startTime: now };
      this.records.set(ip, clientRecord);
      return { allowed: true, remaining: this.limit - 1, resetIn: 60 };
    }

    clientRecord.count += 1;
    const remaining = Math.max(0, this.limit - clientRecord.count);
    const resetIn = Math.ceil((clientRecord.startTime + windowMs - now) / 1000);

    if (clientRecord.count > this.limit) {
      return { allowed: false, remaining: 0, resetIn };
    }

    // Periodic map cleanup
    if (this.records.size > 5000) {
      for (const [key, val] of this.records.entries()) {
        if (now - val.startTime > windowMs) {
          this.records.delete(key);
        }
      }
    }

    return { allowed: true, remaining, resetIn };
  }
}

const rateLimiter = new RateLimiter();

// ============================================
// PROXY POOL MANAGER CLASS (Item 5)
// ============================================
class ProxyPoolManager {
  constructor(defaultProxies = DEFAULT_LOCAL_PROXIES, ttlMs = 300000) {
    this.defaultProxies = defaultProxies;
    this.pool = [...defaultProxies];
    this.lastFetchTime = 0;
    this.ttlMs = ttlMs;
    this.isFetching = false;
  }

  async getProxy(defaultProxy, rawUrl, logger) {
    const sanitizedUrl = sanitizeUrl(rawUrl);
    const now = Date.now();

    if (
      sanitizedUrl &&
      !sanitizedUrl.includes("YOUR_USERNAME") &&
      now - this.lastFetchTime > this.ttlMs &&
      !this.isFetching
    ) {
      this.isFetching = true;
      try {
        if (logger) logger.info("FETCHING_PROXY_LIST", { url: sanitizedUrl });
        const response = await fetch(sanitizedUrl, {
          cf: { cacheTtl: 300, cacheEverything: true }
        });
        if (response.ok) {
          const text = await response.text();
          const fetchedIPs = text
            .split("\n")
            .map((line) => line.trim())
            .filter((line) => line.length > 0 && !line.startsWith("#") && !isPrivateOrBlockedHost(line));

          if (fetchedIPs.length > 0) {
            this.pool = Array.from(new Set([...fetchedIPs, ...this.defaultProxies]));
            if (defaultProxy && !isPrivateOrBlockedHost(defaultProxy) && !this.pool.includes(defaultProxy)) {
              this.pool.unshift(defaultProxy);
            }
            this.lastFetchTime = now;
            if (logger) logger.info("PROXY_POOL_UPDATED", { poolSize: this.pool.length });
          }
        }
      } catch (err) {
        if (logger) logger.warn("PROXY_FETCH_ERROR", { error: err.message });
      } finally {
        this.isFetching = false;
      }
    }

    const validDefault = defaultProxy && !isPrivateOrBlockedHost(defaultProxy) ? defaultProxy : this.defaultProxies[0];
    if (this.pool.length === 0) {
      return validDefault;
    }
    return this.pool[Math.floor(Math.random() * this.pool.length)] || validDefault;
  }

  getPoolSize() {
    return this.pool.length;
  }

  getAllProxies() {
    return [...this.pool];
  }
}

const proxyPoolManager = new ProxyPoolManager();

// ============================================
// IPV6 RFC 5952 ZERO COMPRESSION (Item 7)
// ============================================
function formatIPv6(hextets) {
  const numbers = hextets.map((h) => (typeof h === "string" ? parseInt(h, 16) : h));
  const hex = numbers.map((n) => (n || 0).toString(16));

  let longestStart = -1;
  let longestLen = 0;
  let currentStart = -1;
  let currentLen = 0;

  for (let i = 0; i < 8; i++) {
    if (numbers[i] === 0) {
      if (currentStart === -1) {
        currentStart = i;
        currentLen = 1;
      } else {
        currentLen++;
      }
      if (currentLen > longestLen) {
        longestStart = currentStart;
        longestLen = currentLen;
      }
    } else {
      currentStart = -1;
      currentLen = 0;
    }
  }

  // RFC 5952 requires compressing only when run of 0s is > 1
  if (longestLen > 1) {
    const left = hex.slice(0, longestStart).join(":");
    const right = hex.slice(longestStart + longestLen).join(":");
    if (left === "" && right === "") return "::";
    if (left === "") return `::${right}`;
    if (right === "") return `${left}::`;
    return `${left}::${right}`;
  }

  return hex.join(":");
}

// ============================================
// SECURITY & CORS HEADERS (Item 6 & 12)
// ============================================
function getSecurityHeaders(customContentType = "text/html; charset=utf-8") {
  return {
    "Content-Type": customContentType,
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With, Upgrade, Sec-WebSocket-Key, Sec-WebSocket-Version, Sec-WebSocket-Protocol",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-XSS-Protection": "1; mode=block",
    "Permissions-Policy": "interest-cohort=()",
    "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet",
    "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data: blob:;"
  };
}

function isValidUUID(uuid) {
  if (!uuid || typeof uuid !== "string") return false;
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid.trim());
}

// ============================================
// HOSTED IMAGE PAGE
// ============================================
const HOSTED_IMAGE_URL = "https://i.ibb.co/yc2TMYKj/VEGA-1792076229748.jpg";

function getImagePage() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Network Scene</title>
  <style>
    html, body { margin: 0; padding: 0; background: #fff; }
    img { display: block; width: 100%; height: auto; max-width: 2560px; margin: 0 auto; }
  </style>
</head>
<body>
  <img src="${HOSTED_IMAGE_URL}" alt="Network connected devices">
</body>
</html>`;
}

// ============================================
// VLESS CONFIGURATION & SUBSCRIPTION OUTPUT
// ============================================
function normalizeWsPath(value) {
  const path = String(value || DEFAULT_WS_PATH)
    .trim()
    .replace(/^\/+|\/+$/g, "");
  if (!path || path.length > MAX_CONFIG_PATH_LENGTH || /[\s\\?#]/.test(path)) {
    return DEFAULT_WS_PATH;
  }
  return path;
}

function encodeBase64Utf8(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function generateVlessConfigs(host, uuid, wsPath, proxyIP = "") {
  const cleanHost = String(host || "").replace(/[^a-zA-Z0-9.:-]/g, "");
  const cleanUuid = String(uuid || "").trim().toLowerCase();
  const cleanPath = normalizeWsPath(wsPath);
  const encodedPath = `%2F${encodeURIComponent(cleanPath)}%3Fed%3D2048`;
  const titleHost = cleanHost.replace(/[^a-zA-Z0-9.-]/g, "");

  const tls = `vless://${cleanUuid}@${cleanHost}:443?encryption=none&security=tls&sni=${cleanHost}&type=ws&host=${cleanHost}&path=${encodedPath}#Galaxy-TLS%20(${titleHost})`;
  const configs = [tls];

  // CMLiu-style edge address mode: connect to the proxy/edge address while
  // preserving the Worker hostname in Host/SNI so no custom DNS setup is
  // required. The same Worker endpoint accepts 443/TLS and 8080/plain WS.
  const cleanProxy = String(proxyIP || "").trim().split(/[\s,]+/)[0]
    .replace(/^\[/, "").replace(/\](:\d+)?$/, "").replace(/:\d+$/, "");
  const edgeAddress = cleanProxy || cleanHost;
  const ws8080 = `vless://${cleanUuid}@${edgeAddress}:8080?encryption=none&security=none&type=ws&host=${cleanHost}&path=${encodedPath}#Galaxy-WS-8080%20(${edgeAddress})`;
  configs.push(ws8080);

  if (cleanProxy && !isPrivateOrBlockedHost(cleanProxy)) {
    configs.push(`vless://${cleanUuid}@${cleanProxy}:443?encryption=none&security=tls&sni=${cleanHost}&type=ws&host=${cleanHost}&path=${encodedPath}#Galaxy-ProxyIP%20(${cleanProxy})`);
  }

  return {
    tls,
    http: ws8080,
    proxy: configs.find((item) => item.includes("Galaxy-ProxyIP")) || "",
    plainList: configs.join("\n"),
    base64: encodeBase64Utf8(configs.join("\n"))
  };
}

// ============================================
// MAIN WORKER FETCH HANDLER
// ============================================
const worker_default = {
  async fetch(request, env, ctx) {
    const requestId = generateRequestId();
    const clientIp = request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "unknown";
    const logger = new Logger(requestId, clientIp);

    // Rate Limiting (Item 4)
    const rateLimit = rateLimiter.check(clientIp);
    if (!rateLimit.allowed) {
      logger.warn("RATE_LIMIT_EXCEEDED", { remaining: rateLimit.remaining, resetIn: rateLimit.resetIn });
      return new Response(
        JSON.stringify({ error: "Too Many Requests", retryAfterSeconds: rateLimit.resetIn }),
        {
          status: 429,
          headers: {
            ...getSecurityHeaders("application/json"),
            "Retry-After": rateLimit.resetIn.toString(),
            "X-RateLimit-Limit": DEFAULT_RATE_LIMIT_PER_MINUTE.toString(),
            "X-RateLimit-Remaining": "0"
          }
        }
      );
    }

    const url = new URL(request.url);
    const pathname = url.pathname.replace(/^\/+|\/+$/g, "");

    // Load configurations from env (Item 2: fully configurable via wrangler.toml / env)
    const userID = env.UUID || env.uuid || "";
    const proxyIP = env.PROXYIP || env.proxyip || env.PROXY_IP || DEFAULT_LOCAL_PROXIES[0];
    const rawProxyListUrl = env.PROXY_LIST_URL || "";
    const dohURL = env.DNS_RESOLVER_URL || DEFAULT_DOH_URL;
    const configuredWsPath = normalizeWsPath(env.WS_PATH || DEFAULT_WS_PATH);
    const routeRulesRaw = env.ROUTE_RULES || "";
    const routeServersRaw = env.ROUTE_SERVERS || "";

    // Health check endpoint (Item 10)
    if (url.pathname === "/health" || url.pathname === "/api/health") {
      logger.info("HEALTH_CHECK_REQUESTED");
      return new Response(
        JSON.stringify({
          status: "healthy",
          service: "hosted-image-worker",
          timestamp: new Date().toISOString(),
          uuidConfigured: isValidUUID(userID),
          proxyPoolSize: proxyPoolManager.getPoolSize(),
          wsPath: configuredWsPath,
          rateLimitRemaining: rateLimit.remaining
        }),
        {
          status: 200,
          headers: getSecurityHeaders("application/json")
        }
      );
    }

    // CORS preflight options
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: getSecurityHeaders("text/plain") });
    }

    // Base64 VLESS subscription
    if (url.pathname === "/sub" && request.method === "GET") {
      if (!isValidUUID(userID)) {
        logger.warn("SUBSCRIPTION_REQUEST_WITHOUT_UUID");
        return new Response("UUID is not configured", {
          status: 401,
          headers: getSecurityHeaders("text/plain; charset=utf-8")
        });
      }

      const host = request.headers.get("Host") || url.host;
      const configs = generateVlessConfigs(host, userID, configuredWsPath, proxyIP);
      logger.info("SUBSCRIPTION_SERVED", { host, wsPath: configuredWsPath });
      return new Response(configs.base64, {
        status: 200,
        headers: {
          ...getSecurityHeaders("text/plain; charset=utf-8"),
          "Subscription-Userinfo": "upload=0; download=0; total=0; expire=0",
          "Profile-Update-Interval": "24"
        }
      });
    }

    // Handle WebSocket connection
    const upgradeHeader = request.headers.get("Upgrade");
    if (upgradeHeader === "websocket") {
      // Camouflage WebSocket path leak risk (Item 11)
      if (pathname !== configuredWsPath) {
        logger.warn("UNAUTHORIZED_WS_PATH", { path: pathname, expected: configuredWsPath });
        return new Response(getImagePage(), {
          status: 404,
          headers: getSecurityHeaders("text/html; charset=utf-8")
        });
      }

      // Check UUID validity for WebSocket upgrade (Item 1)
      if (!isValidUUID(userID)) {
        logger.warn("WS_ATTEMPT_WITHOUT_UUID");
        return new Response(getImagePage(), {
          status: 401,
          headers: getSecurityHeaders("text/html; charset=utf-8")
        });
      }

      return await proxyOverWSHandler(
        request,
        userID,
        proxyIP,
        rawProxyListUrl,
        dohURL,
        logger,
        routeRulesRaw,
        routeServersRaw
      );
    }

    // All non-WebSocket HTTP requests serve the hosted image page.
    logger.info("IMAGE_PAGE_SERVED");
    return new Response(getImagePage(), {
      status: 200,
      headers: getSecurityHeaders("text/html; charset=utf-8")
    });
  }
};

// ============================================
// WEBSOCKET PROXY STREAM HANDLER
// ============================================
async function proxyOverWSHandler(
  request,
  userID,
  defaultProxy,
  rawProxyListUrl,
  dohURL,
  logger,
  routeRulesRaw = "",
  routeServersRaw = ""
) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let address = "";
  let portWithRandomLog = "";

  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, logger);

  const remoteSocketWrapper = { value: null };
  let udpStreamWrite = null;
  let isDns = false;

  readableWebSocketStream.pipeTo(
    new WritableStream({
      async write(chunk) {
        if (isDns && udpStreamWrite) {
          return udpStreamWrite(chunk);
        }
        if (remoteSocketWrapper.value) {
          const writer = remoteSocketWrapper.value.writable.getWriter();
          await writer.write(chunk);
          writer.releaseLock();
          return;
        }

        // Process VLESS Protocol Header
        const result = processVlessHeader(chunk, userID);

        if (result.hasError) {
          logger.error("VLESS_HEADER_ERROR", { message: result.message });
          throw new Error(result.message);
        }

        const { addressRemote = "", portRemote = 443, rawDataIndex, responseHeader, isUDP } = result;

        // SSRF check on target destination
        if (isPrivateOrBlockedHost(addressRemote)) {
          logger.warn("BLOCKED_PRIVATE_DESTINATION", { address: addressRemote });
          throw new Error("Access to private destination is blocked");
        }

        address = addressRemote;
        portWithRandomLog = `${portRemote} ${isUDP ? "udp" : "tcp"}`;

        if (isUDP && portRemote !== 53) {
          logger.warn("NON_DNS_UDP_REJECTED", { port: portRemote });
          throw new Error("UDP proxy only enabled for DNS (port 53)");
        }
        if (isUDP && portRemote === 53) {
          isDns = true;
        }

        const rawClientData = chunk.slice(rawDataIndex);

        if (isDns) {
          const { write } = await handleUDPOutBound(webSocket, responseHeader, dohURL, logger);
          udpStreamWrite = write;
          udpStreamWrite(rawClientData);
          return;
        }

        handleTCPOutBound(
          remoteSocketWrapper,
          addressRemote,
          portRemote,
          rawClientData,
          webSocket,
          responseHeader,
          defaultProxy,
          rawProxyListUrl,
          logger,
          routeRulesRaw,
          routeServersRaw
        );
      },
      close() {
        logger.info("WS_STREAM_CLOSED");
      },
      abort(reason) {
        logger.warn("WS_STREAM_ABORTED", { reason: String(reason) });
      }
    })
  ).catch((err) => {
    logger.error("WS_PIPE_ERROR", { error: err.message });
  });

  return new Response(null, { status: 101, webSocket: client });
}

// ============================================
// TCP OUTBOUND WITH TIMEOUT & HYBRID PROXY (Item 8)
// ============================================
async function handleTCPOutBound(
  remoteSocket,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  responseHeader,
  defaultProxy,
  rawProxyListUrl,
  logger,
  routeRulesRaw = "",
  routeServersRaw = ""
) {
  if (isAdDomain(addressRemote)) {
    logger.info("AD_DOMAIN_BLOCKED", {
      address: addressRemote,
      port: portRemote
    });
    safeCloseWebSocket(webSocket);
    return;
  }

  const route = resolveRouteTarget(addressRemote, portRemote, routeRulesRaw, routeServersRaw, logger);
  const primaryAddress = route?.host || addressRemote;
  const primaryPort = route?.port || portRemote;
  if (route) logger.info("DESTINATION_ROUTE_SELECTED", {
    destination: addressRemote,
    route: route.rule,
    server: route.name,
    target: `${primaryAddress}:${primaryPort}`
  });

  let timeoutTimer = null;

  const resetTimeout = () => {
    if (timeoutTimer) clearTimeout(timeoutTimer);
    timeoutTimer = setTimeout(() => {
      logger.warn("CONNECTION_TIMEOUT_REACHED", { address: addressRemote, port: portRemote });
      safeCloseWebSocket(webSocket);
      if (remoteSocket.value && remoteSocket.value.close) {
        try { remoteSocket.value.close(); } catch {}
      }
    }, CONNECTION_TIMEOUT_MS);
  };

  async function connectAndWrite(address, port) {
    resetTimeout();
    const tcpSocket2 = connect({ hostname: address, port });
    remoteSocket.value = tcpSocket2;
    logger.info("TCP_CONNECTING", { target: `${address}:${port}` });

    const writer = tcpSocket2.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket2;
  }

  async function retry() {
    const activeProxy = await proxyPoolManager.getProxy(defaultProxy, rawProxyListUrl, logger);
    const target = activeProxy || addressRemote;
    logger.info("RETRYING_VIA_PROXY", { proxy: target, port: portRemote });

    try {
      const tcpSocket2 = await connectAndWrite(target, portRemote);
      tcpSocket2.closed
        .catch((error) => {
          logger.warn("RETRY_TCP_CLOSED_ERROR", { error: error.message });
        })
        .finally(() => {
          if (timeoutTimer) clearTimeout(timeoutTimer);
          safeCloseWebSocket(webSocket);
        });
      remoteSocketToWS(tcpSocket2, webSocket, responseHeader, null, logger, resetTimeout);
    } catch (retryErr) {
      logger.error("RETRY_CONNECT_FAILED", { error: retryErr.message });
      safeCloseWebSocket(webSocket);
    }
  }

  try {
    const tcpSocket = await connectAndWrite(primaryAddress, primaryPort);
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, logger, resetTimeout);
  } catch (err) {
    logger.warn("DIRECT_TCP_FAILED_RETRYING", { error: err.message });
    await retry();
  }
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, logger) {
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        controller.enqueue(event.data);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        logger.error("WS_EVENT_ERROR", { error: err.message });
        controller.error(err);
      });

      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    cancel(reason) {
      logger.warn("WS_STREAM_CANCELED", { reason: String(reason) });
      safeCloseWebSocket(webSocketServer);
    }
  });
}

// ============================================
// VLESS PROTOCOL PARSER (Item 7: with formatIPv6)
// ============================================
function processVlessHeader(vlessBuffer, userID2) {
  if (vlessBuffer.byteLength < 24) {
    return { hasError: true, message: "Invalid VLESS data" };
  }

  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
  const slicedBufferString = stringify(slicedBuffer);

  const uuids = userID2.includes(",") ? userID2.split(",") : [userID2];
  const isValidUser = uuids.some((userUuid) => slicedBufferString === userUuid.trim());

  if (!isValidUser) {
    return { hasError: true, message: "Invalid VLESS user" };
  }

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

  let isUDP = false;
  if (command === 1) {
    isUDP = false;
  } else if (command === 2) {
    isUDP = true;
  } else {
    return { hasError: true, message: `VLESS command ${command} not supported` };
  }

  const portIndex = 18 + optLength + 1;
  const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  const addressIndex = portIndex + 2;
  const addressType = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1))[0];

  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2:
      addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3: {
      addressLength = 16;
      const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const rawHextets = [];
      for (let i = 0; i < 8; i++) {
        rawHextets.push(dataView.getUint16(i * 2));
      }
      // IPv6 RFC 5952 Zero-Compression (Item 7)
      addressValue = formatIPv6(rawHextets);
      break;
    }
    default:
      return { hasError: true, message: `Invalid VLESS address type ${addressType}` };
  }

  if (!addressValue) {
    return { hasError: true, message: "VLESS address value is empty" };
  }

  const responseHeader = new Uint8Array([version[0], 0]);
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    responseHeader,
    isUDP
  };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, logger, onDataActivity) {
  let header = responseHeader;
  let hasIncomingData = false;

  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          hasIncomingData = true;
          if (onDataActivity) onDataActivity();
          if (webSocket.readyState !== 1) {
            throw new Error("WebSocket not open");
          }
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
          logger.info("REMOTE_SOCKET_CLOSED", { hadData: hasIncomingData });
        },
        abort(reason) {
          logger.warn("REMOTE_READABLE_ABORT", { reason: String(reason) });
        }
      })
    )
    .catch((error) => {
      logger.error("REMOTE_SOCKET_PIPE_ERROR", { error: error.message });
      safeCloseWebSocket(webSocket);
    });

  if (hasIncomingData === false && retry) {
    logger.info("NO_DATA_RECEIVED_TRIGGERING_RETRY");
    retry();
  }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { earlyData: null, error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arrayBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arrayBuffer.buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
  }
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset + 0]] +
    byteToHex[arr[offset + 1]] +
    byteToHex[arr[offset + 2]] +
    byteToHex[arr[offset + 3]] +
    "-" +
    byteToHex[arr[offset + 4]] +
    byteToHex[arr[offset + 5]] +
    "-" +
    byteToHex[arr[offset + 6]] +
    byteToHex[arr[offset + 7]] +
    "-" +
    byteToHex[arr[offset + 8]] +
    byteToHex[arr[offset + 9]] +
    "-" +
    byteToHex[arr[offset + 10]] +
    byteToHex[arr[offset + 11]] +
    byteToHex[arr[offset + 12]] +
    byteToHex[arr[offset + 13]] +
    byteToHex[arr[offset + 14]] +
    byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) {
    throw TypeError("Stringified UUID is invalid");
  }
  return uuid;
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === 1 || socket.readyState === 2) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}

async function handleUDPOutBound(webSocket, responseHeader, dohURL, logger) {
  let isHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength; ) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
    flush() {}
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          const resp = await fetch(dohURL, {
            method: "POST",
            headers: { "content-type": "application/dns-message" },
            body: chunk
          });
          const dnsQueryResult = await resp.arrayBuffer();
          const udpSize = dnsQueryResult.byteLength;
          const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 255, udpSize & 255]);

          if (webSocket.readyState === 1) {
            logger.info("DOH_QUERY_SUCCESS", { responseSize: udpSize });
            if (isHeaderSent) {
              webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
            } else {
              webSocket.send(await new Blob([responseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
              isHeaderSent = true;
            }
          }
        }
      })
    )
    .catch((error) => {
      logger.error("DNS_UDP_ERROR", { error: error.message });
    });

  const writer = transformStream.writable.getWriter();
  return { write: (chunk) => writer.write(chunk) };
}

export default worker_default;
