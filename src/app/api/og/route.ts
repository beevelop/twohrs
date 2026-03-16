import { NextRequest, NextResponse } from "next/server";
import dns from "node:dns/promises";
import type { IncomingHttpHeaders, IncomingMessage } from "node:http";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP } from "node:net";
import { createBrotliDecompress, createUnzip } from "node:zlib";
import { createClient } from "@/lib/supabase/server";

const MAX_HTML_BYTES = 100_000; // Only read first 100KB (OG tags are in <head>)
const REQUEST_TIMEOUT_MS = 8_000;
const MAX_REDIRECTS = 5;
const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);

type ResolvedAddress = {
  address: string;
  family: 4 | 6;
};

const DISALLOWED_IPS = new BlockList();

// IPv4 private, loopback, link-local, carrier-grade NAT, multicast, and other
// non-public ranges that should never be reachable from this route.
DISALLOWED_IPS.addSubnet("0.0.0.0", 8, "ipv4");
DISALLOWED_IPS.addSubnet("10.0.0.0", 8, "ipv4");
DISALLOWED_IPS.addSubnet("100.64.0.0", 10, "ipv4");
DISALLOWED_IPS.addSubnet("127.0.0.0", 8, "ipv4");
DISALLOWED_IPS.addSubnet("169.254.0.0", 16, "ipv4");
DISALLOWED_IPS.addSubnet("172.16.0.0", 12, "ipv4");
DISALLOWED_IPS.addSubnet("192.0.0.0", 24, "ipv4");
DISALLOWED_IPS.addSubnet("192.0.2.0", 24, "ipv4");
DISALLOWED_IPS.addSubnet("192.168.0.0", 16, "ipv4");
DISALLOWED_IPS.addSubnet("198.18.0.0", 15, "ipv4");
DISALLOWED_IPS.addSubnet("198.51.100.0", 24, "ipv4");
DISALLOWED_IPS.addSubnet("203.0.113.0", 24, "ipv4");
DISALLOWED_IPS.addSubnet("224.0.0.0", 4, "ipv4");
DISALLOWED_IPS.addSubnet("240.0.0.0", 4, "ipv4");
DISALLOWED_IPS.addSubnet("::", 128, "ipv6");
DISALLOWED_IPS.addSubnet("::1", 128, "ipv6");
DISALLOWED_IPS.addSubnet("100::", 64, "ipv6");
DISALLOWED_IPS.addSubnet("2001:2::", 48, "ipv6");
DISALLOWED_IPS.addSubnet("2001:db8::", 32, "ipv6");
DISALLOWED_IPS.addSubnet("fc00::", 7, "ipv6");
DISALLOWED_IPS.addSubnet("fe80::", 10, "ipv6");
DISALLOWED_IPS.addSubnet("ff00::", 8, "ipv6");

/** Pick a User-Agent that the target site recognises as a known crawler. */
function getUserAgentForDomain(hostname: string): string {
  // X/Twitter blocks most bot UAs (404/403) but accepts WhatsApp
  if (hostname.includes("x.com") || hostname.includes("twitter.com")) {
    return "WhatsApp/2.23.20.0";
  }
  return "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)";
}

/** Decode common HTML entities in meta tag content (e.g. &amp; → &). */
function decodeHtmlEntities(str: string): string {
  return str
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#0*(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

/** Resolve relative / protocol-relative image URLs against the page URL. */
function resolveImageUrl(src: string, pageUrl: URL): string {
  if (src.startsWith("//")) return `https:${src}`;
  if (src.startsWith("/")) return `${pageUrl.origin}${src}`;
  return src;
}

function normalizeHostname(hostname: string): string {
  return hostname.replace(/^\[(.*)\]$/, "$1");
}

function extractIpv4FromMappedIpv6(ip: string): string | null {
  const normalized = normalizeHostname(ip).toLowerCase();
  const prefix = "::ffff:";
  if (!normalized.startsWith(prefix)) return null;

  const mappedPart = normalized.slice(prefix.length);
  if (mappedPart.includes(".")) {
    return isIP(mappedPart) === 4 ? mappedPart : null;
  }

  const segments = mappedPart.split(":").filter(Boolean);
  if (segments.length !== 2) return null;

  const numbers = segments.map((segment) => Number.parseInt(segment, 16));
  if (numbers.some((segment) => Number.isNaN(segment) || segment < 0 || segment > 0xffff)) {
    return null;
  }

  return [
    numbers[0] >> 8,
    numbers[0] & 0xff,
    numbers[1] >> 8,
    numbers[1] & 0xff,
  ].join(".");
}

function isDisallowedIPAddress(ip: string): boolean {
  const normalized = normalizeHostname(ip);
  const mappedIpv4 = extractIpv4FromMappedIpv6(normalized);
  if (mappedIpv4) return isDisallowedIPAddress(mappedIpv4);

  const family = isIP(normalized);
  if (family === 0) return true;

  return DISALLOWED_IPS.check(normalized, family === 4 ? "ipv4" : "ipv6");
}

async function resolvePublicAddress(hostname: string): Promise<ResolvedAddress> {
  const normalizedHostname = normalizeHostname(hostname);
  const literalFamily = isIP(normalizedHostname);

  if (literalFamily) {
    if (isDisallowedIPAddress(normalizedHostname)) {
      throw new Error("Internal URLs not allowed");
    }

    return { address: normalizedHostname, family: literalFamily as 4 | 6 };
  }

  let addresses;
  try {
    addresses = await dns.lookup(normalizedHostname, {
      all: true,
      verbatim: true,
    });
  } catch {
    throw new Error("DNS resolution failed");
  }

  if (addresses.length === 0) {
    throw new Error("DNS resolution failed");
  }

  if (addresses.some(({ address }) => isDisallowedIPAddress(address))) {
    throw new Error("Internal URLs not allowed");
  }

  const preferredAddress = addresses.find(({ family }) => family === 4) ?? addresses[0];
  return {
    address: preferredAddress.address,
    family: preferredAddress.family as 4 | 6,
  };
}

function getHeaderValue(headers: IncomingHttpHeaders, key: string): string | null {
  const value = headers[key];
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value[0] ?? null;
  return null;
}

function getRemainingTime(deadline: number): number {
  const remaining = deadline - Date.now();
  if (remaining <= 0) {
    throw new Error("Request timed out");
  }
  return remaining;
}

async function performPinnedRequest(url: URL, deadline: number): Promise<IncomingMessage> {
  const hostname = normalizeHostname(url.hostname);
  const resolved = await resolvePublicAddress(hostname);
  const request = url.protocol === "https:" ? httpsRequest : httpRequest;
  const timeoutMs = getRemainingTime(deadline);

  return new Promise((resolve, reject) => {
    const req = request(
      {
        protocol: url.protocol,
        hostname,
        port: url.port || undefined,
        path: `${url.pathname}${url.search}`,
        method: "GET",
        headers: {
          "User-Agent": getUserAgentForDomain(hostname),
          "Accept": "text/html",
          "Accept-Language": "de-DE,de;q=0.9,en;q=0.8",
          "Accept-Encoding": "gzip, deflate, br",
          "Host": url.host,
        },
        lookup: (_lookupHostname, _options, callback) => {
          callback(null, resolved.address, resolved.family);
        },
        servername: url.protocol === "https:" && !isIP(hostname) ? hostname : undefined,
      },
      (response) => resolve(response)
    );

    req.on("error", reject);
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error("Request timed out"));
    });
    req.end();
  });
}

async function fetchUrlWithRedirects(initialUrl: URL): Promise<{ finalUrl: URL; response: IncomingMessage }> {
  const deadline = Date.now() + REQUEST_TIMEOUT_MS;
  let currentUrl = new URL(initialUrl.toString());

  for (let redirectCount = 0; redirectCount <= MAX_REDIRECTS; redirectCount++) {
    const response = await performPinnedRequest(currentUrl, deadline);
    const statusCode = response.statusCode ?? 0;

    if (!REDIRECT_STATUS_CODES.has(statusCode)) {
      return { finalUrl: currentUrl, response };
    }

    const location = getHeaderValue(response.headers, "location");
    response.resume();

    if (!location) {
      throw new Error("Redirect response missing location header");
    }

    if (redirectCount === MAX_REDIRECTS) {
      throw new Error("Too many redirects");
    }

    const nextUrl = new URL(location, currentUrl);
    if (!["http:", "https:"].includes(nextUrl.protocol)) {
      throw new Error("Only HTTP(S) redirects allowed");
    }

    currentUrl = nextUrl;
  }

  throw new Error("Too many redirects");
}

export async function GET(request: NextRequest) {
  // Auth check — only authenticated users can fetch OG data
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const url = request.nextUrl.searchParams.get("url");

  if (!url) {
    return NextResponse.json({ error: "URL parameter required" }, { status: 400 });
  }

  // Validate URL format
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    return NextResponse.json({ error: "Invalid URL" }, { status: 400 });
  }

  // Only allow http/https
  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    return NextResponse.json({ error: "Only HTTP(S) URLs allowed" }, { status: 400 });
  }

  // Block adult domains
  const { isDomainBlocked } = await import("@/lib/moderation/blocked-domains");
  if (isDomainBlocked(parsedUrl.hostname)) {
    return NextResponse.json({ error: "Domain blocked" }, { status: 403 });
  }

  try {
    const { finalUrl, response } = await fetchUrlWithRedirects(parsedUrl);
    const statusCode = response.statusCode ?? 0;

    if (statusCode < 200 || statusCode >= 300) {
      response.resume();
      // Fall back to URL-based preview for sites that block cloud IPs
      const fallback = buildFallbackFromUrl(parsedUrl);
      if (fallback) return NextResponse.json(fallback);
      return NextResponse.json({ error: "Failed to fetch URL" }, { status: 502 });
    }

    const contentType = getHeaderValue(response.headers, "content-type") || "";
    if (!contentType.includes("text/html")) {
      response.resume();
      return NextResponse.json({ error: "URL is not an HTML page" }, { status: 400 });
    }

    // Only read first 100KB — OG tags are always in <head>
    const html = await readPartialBody(response, MAX_HTML_BYTES);

    // Extract from og:* and twitter:* tags (the "real" OG data)
    const metaTitle =
      extractMetaContent(html, "og:title") ||
      extractMetaContent(html, "twitter:title");
    const metaDescription =
      extractMetaContent(html, "og:description") ||
      extractMetaContent(html, "twitter:description");
    const rawImage =
      extractMetaContent(html, "og:image") ||
      extractMetaContent(html, "twitter:image") ||
      extractMetaContent(html, "twitter:image:src");
    const ogImage = rawImage ? resolveImageUrl(rawImage, finalUrl) : null;
    const ogUrl = extractMetaContent(html, "og:url") || finalUrl.toString();
    // Generic <meta name="description"> is only used as a last-resort supplement,
    // not as a signal that the page has real OG data.
    const fallbackDescription = extractMetaContent(html, "description");

    // If no real OG/twitter meta tags found, the page is likely a login
    // redirect or generic shell — use URL-based fallback instead of the
    // bare <title> tag which is usually just the platform name.
    const hasRealOgData = metaTitle || metaDescription || ogImage;
    if (!hasRealOgData) {
      const fallback = buildFallbackFromUrl(parsedUrl);
      if (fallback) return NextResponse.json(fallback);
      // Last resort: use the <title> tag
      const titleTag = extractTag(html, "title");
      if (titleTag) {
        return NextResponse.json({ title: titleTag, description: null, image: null, url: ogUrl });
      }
      return NextResponse.json({ error: "No OG data found" }, { status: 404 });
    }

    return NextResponse.json({
      title: metaTitle || extractTag(html, "title") || null,
      description: metaDescription || fallbackDescription || null,
      image: ogImage || null,
      url: ogUrl,
    });
  } catch (error) {
    if (error instanceof Error) {
      if (error.message === "Internal URLs not allowed") {
        return NextResponse.json({ error: error.message }, { status: 400 });
      }

      if (
        error.message === "DNS resolution failed" ||
        error.message === "Only HTTP(S) redirects allowed" ||
        error.message === "Redirect response missing location header"
      ) {
        return NextResponse.json({ error: error.message }, { status: 400 });
      }
    }

    // On timeout / network error, still try URL-based fallback
    const fallback = buildFallbackFromUrl(parsedUrl);
    if (fallback) return NextResponse.json(fallback);
    return NextResponse.json({ error: "Request timed out or failed" }, { status: 504 });
  }
}

async function readPartialBody(response: IncomingMessage, maxBytes: number): Promise<string> {
  const encoding = (getHeaderValue(response.headers, "content-encoding") || "").toLowerCase();
  const stream =
    encoding.includes("br")
      ? response.pipe(createBrotliDecompress())
      : encoding.includes("gzip") || encoding.includes("deflate")
        ? response.pipe(createUnzip())
        : response;
  const decoder = new TextDecoder();
  let bytesRead = 0;
  let result = "";

  try {
    for await (const chunk of stream) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const remaining = maxBytes - bytesRead;
      if (remaining <= 0) break;

      const slice = buffer.subarray(0, remaining);
      result += decoder.decode(slice, { stream: true });
      bytesRead += slice.length;

      if (bytesRead >= maxBytes) {
        break;
      }
    }
  } finally {
    if (stream !== response) {
      stream.destroy();
    }
    response.destroy();
  }

  return result + decoder.decode();
}

function extractMetaContent(html: string, property: string): string | null {
  // Find the meta tag containing this property/name
  const escaped = escapeRegex(property);
  const tagRegex = new RegExp(
    `<meta[^>]*(?:property|name)=["']${escaped}["'][^>]*>`,
    "i"
  );
  const tagMatch = html.match(tagRegex);
  if (!tagMatch) return null;

  // Extract content value — handle double and single quotes separately
  const tag = tagMatch[0];
  const dblQuote = tag.match(/content="([^"]*)"/i);
  if (dblQuote) return decodeHtmlEntities(dblQuote[1]);
  const sglQuote = tag.match(/content='([^']*)'/i);
  if (sglQuote) return decodeHtmlEntities(sglQuote[1]);
  return null;
}

function extractTag(html: string, tag: string): string | null {
  const regex = new RegExp(`<${tag}[^>]*>([^<]*)</${tag}>`, "i");
  const match = html.match(regex);
  return match ? match[1].trim() || null : null;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Build a minimal preview from the URL itself when the site blocks scraping
 * (e.g. Instagram blocks cloud server IPs).
 */
function buildFallbackFromUrl(parsedUrl: URL): { title: string; description: string | null; image: null; url: string } | null {
  const host = parsedUrl.hostname.replace("www.", "");
  const path = parsedUrl.pathname;

  if (host === "instagram.com") {
    const reelMatch = path.match(/^\/reels?\/([^/]+)/);
    if (reelMatch) return { title: "Instagram Reel", description: null, image: null, url: parsedUrl.toString() };
    const postMatch = path.match(/^\/p\/([^/]+)/);
    if (postMatch) return { title: "Instagram Post", description: null, image: null, url: parsedUrl.toString() };
    const storyMatch = path.match(/^\/stories\/([^/]+)/);
    if (storyMatch) return { title: `Instagram Story – @${storyMatch[1]}`, description: null, image: null, url: parsedUrl.toString() };
    const userMatch = path.match(/^\/([a-zA-Z0-9_.]+)\/?$/);
    if (userMatch) return { title: `@${userMatch[1]} auf Instagram`, description: null, image: null, url: parsedUrl.toString() };
    return { title: "Instagram", description: null, image: null, url: parsedUrl.toString() };
  }

  if (host === "x.com" || host === "twitter.com") {
    const tweetMatch = path.match(/^\/([^/]+)\/status\/(\d+)/);
    if (tweetMatch) return { title: `Post von @${tweetMatch[1]} auf X`, description: null, image: null, url: parsedUrl.toString() };
    const userMatch = path.match(/^\/([a-zA-Z0-9_]+)\/?$/);
    if (userMatch) return { title: `@${userMatch[1]} auf X`, description: null, image: null, url: parsedUrl.toString() };
    return { title: "X (Twitter)", description: null, image: null, url: parsedUrl.toString() };
  }

  if (host === "tiktok.com" || host.endsWith(".tiktok.com")) {
    const videoMatch = path.match(/\/@([^/]+)\/video\/(\d+)/);
    if (videoMatch) return { title: `TikTok von @${videoMatch[1]}`, description: null, image: null, url: parsedUrl.toString() };
    const userMatch = path.match(/^\/@([^/]+)\/?$/);
    if (userMatch) return { title: `@${userMatch[1]} auf TikTok`, description: null, image: null, url: parsedUrl.toString() };
  }

  return null;
}
