import { createAgent } from '@lucid-agents/core';
import { http } from '@lucid-agents/http';
import { createAgentApp } from '@lucid-agents/hono';
import { payments, paymentsFromEnv } from '@lucid-agents/payments';
import { analytics, getSummary, getAllTransactions, exportToCSV } from '@lucid-agents/analytics';
import { z } from 'zod';
import { parse } from 'node-html-parser';
import * as tls from 'tls';

const agent = await createAgent({
  name: 'url-intel',
  version: '1.0.0',
  description: 'URL metadata and web intelligence for AI agents. Extract OpenGraph, Twitter cards, HTTP headers, SSL certs, and redirect chains.',
})
  .use(http())
  .use(payments({ config: paymentsFromEnv() }))
  .use(analytics())
  .build();

const { app, addEntrypoint } = await createAgentApp(agent);

// === HELPERS ===

interface FetchResult {
  url: string;
  status: number;
  headers: Record<string, string>;
  html?: string;
  error?: string;
}

async function fetchURL(url: string, followRedirects = true): Promise<FetchResult> {
  try {
    const response = await fetch(url, {
      redirect: followRedirects ? 'follow' : 'manual',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; URLIntelBot/1.0; +https://url-intel.dev)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
    });
    
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });
    
    const contentType = headers['content-type'] || '';
    let html: string | undefined;
    
    if (contentType.includes('text/html') || contentType.includes('application/xhtml')) {
      html = await response.text();
    }
    
    return { url: response.url, status: response.status, headers, html };
  } catch (error) {
    return { url, status: 0, headers: {}, error: String(error) };
  }
}

function extractMetadata(html: string) {
  const root = parse(html);
  
  const getMeta = (name: string) => {
    const el = root.querySelector(`meta[property="${name}"], meta[name="${name}"]`);
    return el?.getAttribute('content') || null;
  };
  
  const getLink = (rel: string) => {
    const el = root.querySelector(`link[rel="${rel}"]`);
    return el?.getAttribute('href') || null;
  };
  
  const title = root.querySelector('title')?.text?.trim() || null;
  
  return {
    title,
    description: getMeta('description') || getMeta('og:description'),
    canonical: getLink('canonical'),
    favicon: getLink('icon') || getLink('shortcut icon'),
    openGraph: {
      title: getMeta('og:title'),
      description: getMeta('og:description'),
      image: getMeta('og:image'),
      url: getMeta('og:url'),
      type: getMeta('og:type'),
      siteName: getMeta('og:site_name'),
    },
    twitter: {
      card: getMeta('twitter:card'),
      title: getMeta('twitter:title'),
      description: getMeta('twitter:description'),
      image: getMeta('twitter:image'),
      site: getMeta('twitter:site'),
      creator: getMeta('twitter:creator'),
    },
    robots: getMeta('robots'),
    author: getMeta('author'),
    keywords: getMeta('keywords'),
  };
}

async function getSSLInfo(hostname: string): Promise<Record<string, any>> {
  return new Promise((resolve) => {
    try {
      const socket = tls.connect(443, hostname, { servername: hostname }, () => {
        const cert = socket.getPeerCertificate();
        socket.destroy();
        
        if (!cert || !cert.subject) {
          resolve({ error: 'No certificate found' });
          return;
        }
        
        resolve({
          subject: {
            commonName: cert.subject.CN,
            organization: cert.subject.O,
          },
          issuer: {
            commonName: cert.issuer?.CN,
            organization: cert.issuer?.O,
          },
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          serialNumber: cert.serialNumber,
          fingerprint: cert.fingerprint,
          bits: cert.bits,
          subjectAltNames: cert.subjectaltname?.split(', ').map((s: string) => s.replace('DNS:', '')),
        });
      });
      
      socket.on('error', (err) => {
        resolve({ error: String(err) });
      });
      
      socket.setTimeout(10000, () => {
        socket.destroy();
        resolve({ error: 'Connection timeout' });
      });
    } catch (err) {
      resolve({ error: String(err) });
    }
  });
}

async function followRedirects(url: string, maxHops = 10): Promise<Array<{ url: string; status: number }>> {
  const chain: Array<{ url: string; status: number }> = [];
  let currentUrl = url;
  
  for (let i = 0; i < maxHops; i++) {
    try {
      const response = await fetch(currentUrl, {
        redirect: 'manual',
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; URLIntelBot/1.0)',
        },
      });
      
      chain.push({ url: currentUrl, status: response.status });
      
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (!location) break;
        currentUrl = location.startsWith('/') 
          ? new URL(location, currentUrl).href 
          : location;
      } else {
        break;
      }
    } catch (err) {
      chain.push({ url: currentUrl, status: 0 });
      break;
    }
  }
  
  return chain;
}

function analyzeHeaders(headers: Record<string, string>) {
  return {
    security: {
      strictTransportSecurity: headers['strict-transport-security'] || null,
      contentSecurityPolicy: headers['content-security-policy'] ? 'present' : null,
      xFrameOptions: headers['x-frame-options'] || null,
      xContentTypeOptions: headers['x-content-type-options'] || null,
      xXssProtection: headers['x-xss-protection'] || null,
      referrerPolicy: headers['referrer-policy'] || null,
    },
    caching: {
      cacheControl: headers['cache-control'] || null,
      etag: headers['etag'] ? 'present' : null,
      expires: headers['expires'] || null,
      lastModified: headers['last-modified'] || null,
    },
    server: {
      server: headers['server'] || null,
      poweredBy: headers['x-powered-by'] || null,
      contentType: headers['content-type'] || null,
      contentEncoding: headers['content-encoding'] || null,
    },
    raw: headers,
  };
}

// === FREE ENDPOINT ===
addEntrypoint({
  key: 'overview',
  description: 'Free overview - check agent status and capabilities',
  input: z.object({}),
  handler: async () => {
    return { 
      output: { 
        agent: 'url-intel',
        version: '1.0.0',
        description: 'URL metadata and web intelligence for AI agents',
        capabilities: ['metadata', 'headers', 'ssl', 'redirects', 'full-report'],
        pricing: {
          overview: 'FREE',
          metadata: '$0.001',
          headers: '$0.001',
          ssl: '$0.002',
          redirects: '$0.002',
          'full-report': '$0.005',
        },
        dataSource: 'Live HTTP requests',
        fetchedAt: new Date().toISOString(),
      } 
    };
  },
});

// === PAID ENDPOINT 1: Metadata ($0.001) ===
addEntrypoint({
  key: 'metadata',
  description: 'Extract OpenGraph, Twitter cards, and page metadata from a URL',
  input: z.object({ 
    url: z.string().url().describe('Full URL to analyze (https://example.com)'),
  }),
  price: '1000',
  handler: async (ctx) => {
    const result = await fetchURL(ctx.input.url);
    
    if (result.error) {
      return { output: { error: result.error, url: ctx.input.url } };
    }
    
    const metadata = result.html ? extractMetadata(result.html) : null;
    
    return { 
      output: { 
        url: result.url,
        status: result.status,
        metadata,
        fetchedAt: new Date().toISOString(),
      } 
    };
  },
});

// === PAID ENDPOINT 2: Headers ($0.001) ===
addEntrypoint({
  key: 'headers',
  description: 'Analyze HTTP headers including security, caching, and server info',
  input: z.object({ 
    url: z.string().url().describe('Full URL to analyze'),
  }),
  price: '1000',
  handler: async (ctx) => {
    const result = await fetchURL(ctx.input.url);
    
    if (result.error) {
      return { output: { error: result.error, url: ctx.input.url } };
    }
    
    const analysis = analyzeHeaders(result.headers);
    
    return { 
      output: { 
        url: result.url,
        status: result.status,
        headers: analysis,
        fetchedAt: new Date().toISOString(),
      } 
    };
  },
});

// === PAID ENDPOINT 3: SSL ($0.002) ===
addEntrypoint({
  key: 'ssl',
  description: 'Get SSL/TLS certificate details for a domain',
  input: z.object({ 
    url: z.string().describe('URL or domain to check SSL (https://example.com or example.com)'),
  }),
  price: '2000',
  handler: async (ctx) => {
    let hostname: string;
    try {
      const parsed = new URL(ctx.input.url.startsWith('http') ? ctx.input.url : `https://${ctx.input.url}`);
      hostname = parsed.hostname;
    } catch {
      return { output: { error: 'Invalid URL or domain', input: ctx.input.url } };
    }
    
    const sslInfo = await getSSLInfo(hostname);
    
    return { 
      output: { 
        hostname,
        ssl: sslInfo,
        fetchedAt: new Date().toISOString(),
      } 
    };
  },
});

// === PAID ENDPOINT 4: Redirects ($0.002) ===
addEntrypoint({
  key: 'redirects',
  description: 'Follow and document the redirect chain for a URL',
  input: z.object({ 
    url: z.string().url().describe('URL to follow redirects'),
    maxHops: z.number().min(1).max(20).optional().default(10),
  }),
  price: '2000',
  handler: async (ctx) => {
    const chain = await followRedirects(ctx.input.url, ctx.input.maxHops);
    
    return { 
      output: { 
        originalUrl: ctx.input.url,
        finalUrl: chain[chain.length - 1]?.url || ctx.input.url,
        hops: chain.length,
        hasRedirects: chain.length > 1,
        chain,
        fetchedAt: new Date().toISOString(),
      } 
    };
  },
});

// === PAID ENDPOINT 5: Full Report ($0.005) ===
addEntrypoint({
  key: 'full-report',
  description: 'Complete URL analysis: metadata, headers, SSL, and redirects',
  input: z.object({ 
    url: z.string().url().describe('URL for full analysis'),
  }),
  price: '5000',
  handler: async (ctx) => {
    const [pageResult, chain] = await Promise.all([
      fetchURL(ctx.input.url),
      followRedirects(ctx.input.url),
    ]);
    
    let hostname: string;
    try {
      hostname = new URL(ctx.input.url).hostname;
    } catch {
      return { output: { error: 'Invalid URL', input: ctx.input.url } };
    }
    
    const sslInfo = await getSSLInfo(hostname);
    const metadata = pageResult.html ? extractMetadata(pageResult.html) : null;
    const headers = analyzeHeaders(pageResult.headers);
    
    return { 
      output: { 
        url: ctx.input.url,
        finalUrl: pageResult.url,
        status: pageResult.status,
        metadata,
        headers,
        ssl: sslInfo,
        redirects: {
          hops: chain.length,
          hasRedirects: chain.length > 1,
          chain,
        },
        fetchedAt: new Date().toISOString(),
      } 
    };
  },
});

// === ANALYTICS ENDPOINTS (FREE) ===
addEntrypoint({
  key: 'analytics',
  description: 'Payment analytics summary',
  input: z.object({
    windowMs: z.number().optional().describe('Time window in ms'),
  }),
    // Free endpoint - no price
  handler: async (ctx) => {
    const tracker = agent.analytics?.paymentTracker;
    if (!tracker) {
      return { output: { error: 'Analytics not available', payments: [] } };
    }
    const summary = await getSummary(tracker, ctx.input.windowMs);
    return { 
      output: { 
        ...summary,
        outgoingTotal: summary.outgoingTotal.toString(),
        incomingTotal: summary.incomingTotal.toString(),
        netTotal: summary.netTotal.toString(),
      } 
    };
  },
});

addEntrypoint({
  key: 'analytics-transactions',
  description: 'Recent payment transactions',
  input: z.object({
    windowMs: z.number().optional(),
    limit: z.number().optional().default(50),
  }),
    // Free endpoint - no price
  handler: async (ctx) => {
    const tracker = agent.analytics?.paymentTracker;
    if (!tracker) {
      return { output: { transactions: [] } };
    }
    const txs = await getAllTransactions(tracker, ctx.input.windowMs);
    return { output: { transactions: txs.slice(0, ctx.input.limit) } };
  },
});

addEntrypoint({
  key: 'analytics-csv',
  description: 'Export payment data as CSV',
  input: z.object({ windowMs: z.number().optional() }),
    // Free endpoint - no price
  handler: async (ctx) => {
    const tracker = agent.analytics?.paymentTracker;
    if (!tracker) {
      return { output: { csv: '' } };
    }
    const csv = await exportToCSV(tracker, ctx.input.windowMs);
    return { output: { csv } };
  },
});

// Serve icon
app.get('/icon.png', async (c) => {
  try {
    const file = Bun.file('./icon.png');
    const exists = await file.exists();
    if (!exists) {
      return c.json({ error: 'Icon not found' }, 404);
    }
    return new Response(file, {
      headers: { 'Content-Type': 'image/png' },
    });
  } catch {
    return c.json({ error: 'Icon not found' }, 404);
  }
});

// ERC-8004 registration
app.get('/.well-known/erc8004.json', (c) => {
  const baseUrl = process.env.BASE_URL || 'https://url-intel-production.up.railway.app';
  return c.json({
    type: 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1',
    name: 'url-intel',
    description: 'URL metadata and web intelligence for AI agents. Extract OpenGraph, Twitter cards, HTTP headers, SSL certs, and redirect chains. 1 free + 5 paid endpoints via x402.',
    image: `${baseUrl}/icon.png`,
    services: [
      { name: 'web', endpoint: baseUrl },
      { name: 'A2A', endpoint: `${baseUrl}/.well-known/agent.json`, version: '0.3.0' },
    ],
    x402Support: true,
    active: true,
    registrations: [],
    supportedTrust: ['reputation'],
  });
});

const port = Number(process.env.PORT ?? 3000);
console.log(`URL Intel Agent running on port ${port}`);

export default { port, fetch: app.fetch };
