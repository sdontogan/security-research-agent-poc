import {
  AGENT_POLICY,
  AGENT_SYSTEM_PROMPT,
  CONTRACT_SOURCE,
  SOURCE_REGISTRY,
  VERDICT_SCHEMA,
} from '../_lib/domain-agent-contract';

interface RateLimiter {
  limit(input: { key: string }): Promise<{ success: boolean }>;
}
interface AiBinding {
  run(model: string, input: Record<string, unknown>): Promise<unknown>;
}
interface Env {
  AI?: AiBinding;
  TURNSTILE_SITE_KEY?: string;
  TURNSTILE_SECRET_KEY?: string;
  CHAT_RATE_LIMITER?: RateLimiter;
  CHAT_GLOBAL_LIMITER?: RateLimiter;
}
interface Context {
  request: Request;
  env: Env;
}
interface ResearchRequest {
  domain?: unknown;
  virustotalApiKey?: unknown;
  turnstileToken?: unknown;
  sessionId?: unknown;
  website?: unknown;
}
interface EvidenceSource {
  id: string;
  name: string;
  status: 'success' | 'unavailable' | 'not_configured';
  summary: string;
  sourceUrl: string;
  observedAt: string;
  facts: Record<string, unknown>;
  warnings: string[];
  durationMs: number;
}
interface AgentVerdict {
  verdict:
    | 'likely_malicious'
    | 'suspicious'
    | 'no_current_threat_evidence'
    | 'inconclusive';
  confidence: number;
  executive_summary: string;
  supporting_evidence: string[];
  contradicting_evidence: string[];
  uncertainties: string[];
  recommended_next_steps: string[];
  sources_used: string[];
  mode: 'llm' | 'evidence_fallback';
}

const MODEL = '@cf/meta/llama-3.1-8b-instruct-fast';
const ALLOWED_ORIGINS = new Set([
  'https://beyond-features.com',
  'https://www.beyond-features.com',
]);
const DOMAIN_PATTERN =
  /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const NON_PUBLIC_SUFFIXES = [
  '.internal',
  '.invalid',
  '.lan',
  '.local',
  '.localhost',
  '.test',
];
const SOURCE_TIMEOUT_MS = AGENT_POLICY.limits.source_timeout_seconds * 1000;
const DNS_TYPES = [
  { code: 1, label: 'A' },
  { code: 28, label: 'AAAA' },
  { code: 15, label: 'MX' },
  { code: 2, label: 'NS' },
] as const;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
      'x-content-type-options': 'nosniff',
    },
  });

function normalizeDomain(value: unknown) {
  if (typeof value !== 'string') return '';
  const domain = value.trim().toLowerCase().replace(/\.$/, '');
  if (
    !DOMAIN_PATTERN.test(domain) ||
    NON_PUBLIC_SUFFIXES.some((suffix) => domain.endsWith(suffix))
  ) {
    return '';
  }
  return domain;
}

async function verifyTurnstile(
  token: string,
  secret: string,
  remoteIp: string,
) {
  const form = new FormData();
  form.set('secret', secret);
  form.set('response', token);
  if (remoteIp) form.set('remoteip', remoteIp);
  const response = await fetch(
    'https://challenges.cloudflare.com/turnstile/v0/siteverify',
    { method: 'POST', body: form },
  );
  if (!response.ok) return false;
  const result = (await response.json()) as {
    success?: boolean;
    hostname?: string;
  };
  const testMode = secret === '1x0000000000000000000000000000000AA';
  return (
    result.success === true &&
    (!result.hostname ||
      result.hostname === 'beyond-features.com' ||
      result.hostname === 'www.beyond-features.com' ||
      (testMode &&
        (result.hostname === 'localhost' || result.hostname === 'example.com')))
  );
}

function sourceResult(
  input: Omit<EvidenceSource, 'observedAt' | 'durationMs'>,
  startedAt: number,
): EvidenceSource {
  return {
    ...input,
    observedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
  };
}

async function lookupDns(domain: string): Promise<EvidenceSource> {
  const startedAt = Date.now();
  const responses = await Promise.all(
    DNS_TYPES.map(async ({ code, label }) => {
      try {
        const response = await fetch(
          `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${code}`,
          {
            headers: { accept: 'application/dns-json' },
            signal: AbortSignal.timeout(SOURCE_TIMEOUT_MS),
          },
        );
        if (!response.ok) return { label, unavailable: true, answers: [] };
        const payload = (await response.json()) as {
          Status?: unknown;
          Answer?: unknown;
        };
        const answers = Array.isArray(payload.Answer)
          ? payload.Answer.filter((answer): answer is Record<string, unknown> =>
              Boolean(
                answer &&
                typeof answer === 'object' &&
                answer.type === code &&
                typeof answer.data === 'string',
              ),
            )
              .slice(0, 8)
              .map((answer) => ({
                type: label,
                value: String(answer.data).slice(0, 300),
                ttl:
                  typeof answer.TTL === 'number'
                    ? Math.max(0, Math.min(answer.TTL, 2_592_000))
                    : null,
              }))
          : [];
        return { label, unavailable: false, answers };
      } catch {
        return { label, unavailable: true, answers: [] };
      }
    }),
  );
  const records = responses.flatMap((item) => item.answers).slice(0, 24);
  const unavailable = responses
    .filter((item) => item.unavailable)
    .map((item) => item.label);
  const failed = unavailable.length === DNS_TYPES.length;
  return sourceResult(
    {
      id: 'cloudflare_dns',
      name: 'Cloudflare DNS',
      status: failed ? 'unavailable' : 'success',
      summary: failed
        ? 'Passive DNS queries were unavailable.'
        : `Returned ${records.length} bounded A, AAAA, MX, and NS records.`,
      sourceUrl: `https://radar.cloudflare.com/domains/domain/${domain}`,
      facts: { records },
      warnings: unavailable.length
        ? [`Unavailable DNS record types: ${unavailable.join(', ')}.`]
        : [],
    },
    startedAt,
  );
}

function readRdapEvent(events: unknown, names: string[]) {
  if (!Array.isArray(events)) return null;
  for (const value of events.slice(0, 30)) {
    if (!value || typeof value !== 'object') continue;
    const event = value as Record<string, unknown>;
    if (
      typeof event.eventAction === 'string' &&
      names.includes(event.eventAction.toLowerCase()) &&
      typeof event.eventDate === 'string'
    ) {
      return event.eventDate.slice(0, 50);
    }
  }
  return null;
}

function readRegistrar(entities: unknown) {
  if (!Array.isArray(entities)) return null;
  for (const value of entities.slice(0, 30)) {
    if (!value || typeof value !== 'object') continue;
    const entity = value as Record<string, unknown>;
    if (!Array.isArray(entity.roles) || !entity.roles.includes('registrar'))
      continue;
    const vcard = entity.vcardArray;
    if (Array.isArray(vcard) && Array.isArray(vcard[1])) {
      for (const field of vcard[1]) {
        if (
          Array.isArray(field) &&
          field[0] === 'fn' &&
          typeof field[3] === 'string'
        ) {
          return field[3].slice(0, 160);
        }
      }
    }
    if (typeof entity.handle === 'string') return entity.handle.slice(0, 160);
  }
  return null;
}

async function lookupRdap(domain: string): Promise<EvidenceSource> {
  const startedAt = Date.now();
  try {
    const bootstrapResponse = await fetch(
      'https://data.iana.org/rdap/dns.json',
      {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(SOURCE_TIMEOUT_MS),
      },
    );
    if (!bootstrapResponse.ok) throw new Error('RDAP bootstrap failed');
    const bootstrap = (await bootstrapResponse.json()) as {
      services?: unknown;
    };
    if (!Array.isArray(bootstrap.services))
      throw new Error('RDAP bootstrap format failed');
    const tld = domain.split('.').at(-1);
    let registryBase = '';
    for (const service of bootstrap.services) {
      if (
        !Array.isArray(service) ||
        !Array.isArray(service[0]) ||
        !Array.isArray(service[1])
      ) {
        continue;
      }
      if (service[0].includes(tld) && typeof service[1][0] === 'string') {
        registryBase = service[1][0];
        break;
      }
    }
    if (!registryBase) throw new Error('No authoritative RDAP service');
    const registryUrl = new URL(
      `domain/${encodeURIComponent(domain)}`,
      registryBase.endsWith('/') ? registryBase : `${registryBase}/`,
    );
    if (registryUrl.protocol !== 'https:')
      throw new Error('Unsafe RDAP service');
    const response = await fetch(registryUrl, {
      headers: { accept: 'application/rdap+json, application/json' },
      redirect: 'follow',
      signal: AbortSignal.timeout(SOURCE_TIMEOUT_MS),
    });
    const finalUrl = new URL(response.url);
    if (!response.ok || finalUrl.protocol !== 'https:')
      throw new Error('RDAP failed');
    if (Number(response.headers.get('content-length') || 0) > 750_000) {
      throw new Error('RDAP response too large');
    }
    const payload = (await response.json()) as Record<string, unknown>;
    const registrationDate = readRdapEvent(payload.events, [
      'registration',
      'registered',
    ]);
    const expirationDate = readRdapEvent(payload.events, [
      'expiration',
      'expiry',
    ]);
    const statuses = Array.isArray(payload.status)
      ? payload.status.slice(0, 15).map((value) => String(value).slice(0, 120))
      : [];
    const nameservers = Array.isArray(payload.nameservers)
      ? payload.nameservers
          .slice(0, 12)
          .map((value) =>
            value && typeof value === 'object'
              ? String((value as Record<string, unknown>).ldhName || '').slice(
                  0,
                  253,
                )
              : '',
          )
          .filter(Boolean)
      : [];
    return sourceResult(
      {
        id: 'rdap',
        name: 'RDAP registration data',
        status: 'success',
        summary: registrationDate
          ? `Registration metadata dates to ${registrationDate.slice(0, 10)}.`
          : 'Returned registration metadata without a public registration date.',
        sourceUrl: `https://lookup.icann.org/en/lookup?name=${domain}`,
        facts: {
          registrar: readRegistrar(payload.entities),
          registrationDate,
          expirationDate,
          statuses,
          nameservers,
        },
        warnings: [],
      },
      startedAt,
    );
  } catch {
    return sourceResult(
      {
        id: 'rdap',
        name: 'RDAP registration data',
        status: 'unavailable',
        summary: 'Structured registration data was unavailable.',
        sourceUrl: `https://lookup.icann.org/en/lookup?name=${domain}`,
        facts: {},
        warnings: ['The report continues without registration-age evidence.'],
      },
      startedAt,
    );
  }
}

async function lookupCertificates(domain: string): Promise<EvidenceSource> {
  const startedAt = Date.now();
  const url = new URL('https://api.certspotter.com/v1/issuances');
  url.searchParams.set('domain', domain);
  url.searchParams.set('include_subdomains', 'true');
  url.searchParams.set('expand', 'dns_names,issuer');
  url.searchParams.set('match_wildcards', 'true');
  try {
    const response = await fetch(url, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(SOURCE_TIMEOUT_MS),
    });
    if (
      !response.ok ||
      Number(response.headers.get('content-length') || 0) > 900_000
    ) {
      throw new Error('Certificate source failed');
    }
    const payload = (await response.json()) as unknown;
    if (!Array.isArray(payload)) throw new Error('Certificate format failed');
    const rows = payload
      .slice(0, 100)
      .filter((value): value is Record<string, unknown> =>
        Boolean(value && typeof value === 'object'),
      );
    const observedDates = rows
      .map((row) =>
        typeof row.not_before === 'string' ? row.not_before.slice(0, 50) : '',
      )
      .filter(Boolean)
      .sort();
    const issuers = [
      ...new Set(
        rows
          .map((row) => {
            const issuer = row.issuer;
            return issuer &&
              typeof issuer === 'object' &&
              typeof (issuer as Record<string, unknown>).name === 'string'
              ? String((issuer as Record<string, unknown>).name).slice(0, 160)
              : '';
          })
          .filter(Boolean),
      ),
    ].slice(0, 10);
    return sourceResult(
      {
        id: 'certificate_transparency',
        name: 'Certificate Transparency',
        status: 'success',
        summary: `Returned ${rows.length} bounded existing certificate issuances.`,
        sourceUrl: 'https://certificate.transparency.dev/',
        facts: {
          issuanceCount: rows.length,
          firstObserved: observedDates[0] || null,
          lastObserved: observedDates.at(-1) || null,
          issuers,
        },
        warnings:
          rows.length === 100
            ? ['Results were capped at 100 recent certificate issuances.']
            : [],
      },
      startedAt,
    );
  } catch {
    return sourceResult(
      {
        id: 'certificate_transparency',
        name: 'Certificate Transparency',
        status: 'unavailable',
        summary: 'Certificate Transparency data was unavailable.',
        sourceUrl: 'https://certificate.transparency.dev/',
        facts: {},
        warnings: [
          'The report continues without certificate-history evidence.',
        ],
      },
      startedAt,
    );
  }
}

async function lookupVirusTotal(
  domain: string,
  apiKey: string,
): Promise<EvidenceSource> {
  const startedAt = Date.now();
  if (!apiKey) {
    return sourceResult(
      {
        id: 'virustotal',
        name: 'VirusTotal',
        status: 'not_configured',
        summary: 'Not queried because no visitor API key was supplied.',
        sourceUrl: `https://www.virustotal.com/gui/domain/${domain}`,
        facts: {},
        warnings: [
          'Reputation confidence is capped without a reputation source.',
        ],
      },
      startedAt,
    );
  }
  try {
    const response = await fetch(
      `https://www.virustotal.com/api/v3/domains/${domain}`,
      {
        headers: { 'x-apikey': apiKey },
        signal: AbortSignal.timeout(SOURCE_TIMEOUT_MS),
      },
    );
    if ([401, 403].includes(response.status)) {
      throw new Error('VirusTotal rejected the API key or its permissions.');
    }
    if (response.status === 404) {
      throw new Error('VirusTotal has no existing report for this domain.');
    }
    if (response.status === 429) {
      throw new Error('The VirusTotal key has reached its request limit.');
    }
    if (!response.ok) throw new Error('VirusTotal is temporarily unavailable.');
    const payload = (await response.json()) as {
      data?: { attributes?: Record<string, unknown> };
    };
    const attributes = payload.data?.attributes;
    const stats = attributes?.last_analysis_stats;
    if (!attributes || !stats || typeof stats !== 'object') {
      throw new Error('VirusTotal returned an unexpected report format.');
    }
    const counts = stats as Record<string, unknown>;
    const count = (name: string) => {
      const value = Number(counts[name] || 0);
      return Number.isFinite(value) && value >= 0 ? Math.min(value, 1000) : 0;
    };
    const tags = Array.isArray(attributes.tags)
      ? attributes.tags.slice(0, 8).map((tag) => String(tag).slice(0, 80))
      : [];
    return sourceResult(
      {
        id: 'virustotal',
        name: 'VirusTotal',
        status: 'success',
        summary: `Returned ${count('malicious')} malicious and ${count('suspicious')} suspicious detections.`,
        sourceUrl: `https://www.virustotal.com/gui/domain/${domain}`,
        facts: {
          malicious: count('malicious'),
          suspicious: count('suspicious'),
          harmless: count('harmless'),
          undetected: count('undetected'),
          reputation:
            typeof attributes.reputation === 'number'
              ? attributes.reputation
              : null,
          tags,
        },
        warnings: [],
      },
      startedAt,
    );
  } catch (error) {
    return sourceResult(
      {
        id: 'virustotal',
        name: 'VirusTotal',
        status: 'unavailable',
        summary:
          error instanceof Error
            ? error.message
            : 'VirusTotal could not complete the lookup.',
        sourceUrl: `https://www.virustotal.com/gui/domain/${domain}`,
        facts: {},
        warnings: [
          'The report continues without VirusTotal reputation evidence.',
        ],
      },
      startedAt,
    );
  }
}

function lexicalFacts(domain: string) {
  const labels = domain.split('.');
  const hostname = labels.slice(0, -1).join('.');
  return {
    characterCount: domain.length,
    labelCount: labels.length,
    digitCount: (hostname.match(/\d/g) || []).length,
    hyphenCount: (hostname.match(/-/g) || []).length,
    containsPunycode: labels.some((label) => label.startsWith('xn--')),
    containsLongLabel: labels.some((label) => label.length >= 30),
  };
}

function stringArray(value: unknown, maximum = 6) {
  return Array.isArray(value)
    ? value
        .filter((item): item is string => typeof item === 'string')
        .map((item) => item.replace(/[<>]/g, '').trim().slice(0, 300))
        .filter(Boolean)
        .slice(0, maximum)
    : [];
}

function boundedVerdict(value: unknown): Omit<AgentVerdict, 'mode'> | null {
  if (!value || typeof value !== 'object') return null;
  const result = value as Record<string, unknown>;
  if (
    typeof result.verdict !== 'string' ||
    !AGENT_POLICY.verdicts.includes(
      result.verdict as (typeof AGENT_POLICY.verdicts)[number],
    ) ||
    !Number.isInteger(result.confidence) ||
    typeof result.executive_summary !== 'string'
  ) {
    return null;
  }
  return {
    verdict: result.verdict as AgentVerdict['verdict'],
    confidence: Math.max(0, Math.min(Number(result.confidence), 100)),
    executive_summary: result.executive_summary
      .replace(/[<>]/g, '')
      .trim()
      .slice(0, 900),
    supporting_evidence: stringArray(result.supporting_evidence),
    contradicting_evidence: stringArray(result.contradicting_evidence),
    uncertainties: stringArray(result.uncertainties),
    recommended_next_steps: stringArray(result.recommended_next_steps, 5),
    sources_used: stringArray(result.sources_used, 8).map((item) =>
      item.slice(0, 80),
    ),
  };
}

function fallbackVerdict(sources: EvidenceSource[]): AgentVerdict {
  const vt = sources.find((source) => source.id === 'virustotal');
  const malicious = Number(vt?.facts.malicious || 0);
  const suspicious = Number(vt?.facts.suspicious || 0);
  const successful = sources.filter((source) => source.status === 'success');
  const unavailable = sources.filter((source) => source.status !== 'success');
  let verdict: AgentVerdict['verdict'] = 'inconclusive';
  let confidence = 30;
  let summary =
    'The available passive evidence is insufficient for a confident automated verdict.';
  if (malicious >= AGENT_POLICY.priority_thresholds.high_malicious_detections) {
    verdict = 'likely_malicious';
    confidence = 85;
    summary = `VirusTotal reports ${malicious} malicious detections, so the domain warrants urgent review.`;
  } else if (
    malicious >= AGENT_POLICY.priority_thresholds.medium_malicious_detections ||
    suspicious >= AGENT_POLICY.priority_thresholds.medium_suspicious_detections
  ) {
    verdict = 'suspicious';
    confidence = 70;
    summary = `VirusTotal reports ${malicious} malicious and ${suspicious} suspicious detections; manual review is recommended.`;
  } else if (vt?.status === 'success' && successful.length >= 3) {
    verdict = 'no_current_threat_evidence';
    confidence = 55;
    summary =
      'The queried sources did not return a current threat signal, but that is not proof the domain is safe.';
  }
  return {
    verdict,
    confidence,
    executive_summary: summary,
    supporting_evidence: successful.map(
      (source) => `${source.name}: ${source.summary}`,
    ),
    contradicting_evidence: [],
    uncertainties: unavailable.map(
      (source) => `${source.name}: ${source.summary}`,
    ),
    recommended_next_steps: [
      'Review the linked source records and confirm domain ownership.',
      'Correlate the result with DNS, email, proxy, and endpoint telemetry.',
      'Escalate confirmed indicators through the normal security process.',
    ],
    sources_used: successful.map((source) => source.name),
    mode: 'evidence_fallback',
  };
}

function applyVerdictGuardrails(
  verdict: AgentVerdict,
  sources: EvidenceSource[],
) {
  const result: AgentVerdict = {
    ...verdict,
    supporting_evidence: [...verdict.supporting_evidence],
    uncertainties: [...verdict.uncertainties],
  };
  const successfulSources = sources.filter(
    (source) => source.status === 'success',
  );
  const successfulNames = successfulSources.flatMap((source) => [
    source.id.toLowerCase(),
    source.name.toLowerCase(),
  ]);
  const citesSuccessfulSource = (statement: string) => {
    const normalized = statement.toLowerCase();
    return successfulNames.some((name) => normalized.includes(name));
  };
  const describesMissingSource = (statement: string) =>
    /\b(not queried|not configured|unavailable|missing|lack of|without)\b/i.test(
      statement,
    );
  const useReadableSourceName = (statement: string) => {
    const normalized = statement.toLowerCase();
    for (const source of sources) {
      for (const label of [source.id, source.name]) {
        const prefix = `${label.toLowerCase()}:`;
        if (normalized.startsWith(prefix)) {
          return `${source.name}:${statement.slice(prefix.length)}`;
        }
      }
    }
    return statement;
  };
  const misplacedUncertainties = result.supporting_evidence.filter(
    describesMissingSource,
  );
  result.supporting_evidence = result.supporting_evidence.filter(
    (statement) =>
      !describesMissingSource(statement) && citesSuccessfulSource(statement),
  );
  result.contradicting_evidence = result.contradicting_evidence.filter(
    (statement) =>
      statement.length >= 20 &&
      !describesMissingSource(statement) &&
      citesSuccessfulSource(statement),
  );
  result.uncertainties.unshift(...misplacedUncertainties);
  result.sources_used = successfulSources
    .filter((source) =>
      result.sources_used.some((value) => {
        const normalized = value.toLowerCase();
        return (
          normalized === source.id || normalized === source.name.toLowerCase()
        );
      }),
    )
    .map((source) => source.name);
  const vt = sources.find((source) => source.id === 'virustotal');
  const malicious = Number(vt?.facts.malicious || 0);
  const suspicious = Number(vt?.facts.suspicious || 0);
  if (malicious >= AGENT_POLICY.priority_thresholds.high_malicious_detections) {
    result.verdict = 'likely_malicious';
    result.supporting_evidence.unshift(
      `VirusTotal: ${malicious} malicious detections were returned.`,
    );
  } else if (
    (malicious >=
      AGENT_POLICY.priority_thresholds.medium_malicious_detections ||
      suspicious >=
        AGENT_POLICY.priority_thresholds.medium_suspicious_detections) &&
    result.verdict === 'no_current_threat_evidence'
  ) {
    result.verdict = 'suspicious';
    result.supporting_evidence.unshift(
      `VirusTotal: ${malicious} malicious and ${suspicious} suspicious detections were returned.`,
    );
  }
  if (vt?.status !== 'success') {
    result.confidence = Math.min(
      result.confidence,
      AGENT_POLICY.confidence_caps.no_reputation_source,
    );
    result.uncertainties.unshift(
      'No successful reputation source was available; confidence is capped.',
    );
  }
  if (
    /\b(safe|benign|legitimate|trustworthy|harmless)\b/i.test(
      result.executive_summary,
    )
  ) {
    const guardedSummaries: Record<AgentVerdict['verdict'], string> = {
      likely_malicious:
        'The available evidence contains strong threat signals that warrant urgent manual review. The verdict is based on the current sources listed below, not a final determination of the domain’s intent.',
      suspicious:
        'The available evidence contains signals that warrant manual review. Compare the supporting evidence, missing information, and source records below before taking action.',
      no_current_threat_evidence:
        vt?.status === 'success'
          ? 'The available sources did not show a current threat signal. This does not prove the domain is safe, and the assessment can change as new evidence appears.'
          : 'The available passive sources did not show a current threat signal. This does not prove the domain is safe, and confidence is limited because no reputation source was available.',
      inconclusive:
        'The available evidence is not sufficient for a reliable conclusion. Review the missing information and source records below before making a decision.',
    };
    result.executive_summary = guardedSummaries[result.verdict];
  }
  const unavailable = sources.filter((source) => source.status !== 'success');
  if (unavailable.length > sources.length / 2) {
    result.confidence = Math.min(
      result.confidence,
      AGENT_POLICY.confidence_caps.majority_sources_unavailable,
    );
    result.verdict = 'inconclusive';
  }
  result.supporting_evidence = [
    ...new Set(result.supporting_evidence.map(useReadableSourceName)),
  ].slice(0, 6);
  result.contradicting_evidence = [
    ...new Set(result.contradicting_evidence.map(useReadableSourceName)),
  ].slice(0, 6);
  result.uncertainties = [
    ...new Set(result.uncertainties.map(useReadableSourceName)),
  ].slice(0, 6);
  result.executive_summary = result.executive_summary.replace(
    /\b\d{1,3}% confidence\b/gi,
    `${result.confidence}% confidence`,
  );
  return result;
}

async function synthesizeVerdict(
  env: Env,
  domain: string,
  sources: EvidenceSource[],
  lexical: ReturnType<typeof lexicalFacts>,
) {
  const fallback = fallbackVerdict(sources);
  if (!env.AI || !sources.some((source) => source.status === 'success')) {
    return {
      verdict: applyVerdictGuardrails(fallback, sources),
      error: 'LLM unavailable.',
    };
  }
  const prompt = JSON.stringify({
    subject: { type: 'public_domain', value: domain },
    lexicalFacts: lexical,
    evidence: sources.map((source) => ({
      id: source.id,
      name: source.name,
      status: source.status,
      summary: source.summary,
      facts: source.facts,
      warnings: source.warnings,
      observedAt: source.observedAt,
    })),
    policy: {
      verdicts: AGENT_POLICY.verdicts,
      confidenceCaps: AGENT_POLICY.confidence_caps,
      guardrails: AGENT_POLICY.guardrails,
    },
  }).slice(0, 18_000);
  try {
    const response = (await env.AI.run(MODEL, {
      messages: [
        { role: 'system', content: AGENT_SYSTEM_PROMPT },
        { role: 'user', content: prompt },
      ],
      response_format: {
        type: 'json_schema',
        json_schema: VERDICT_SCHEMA,
      },
      max_tokens: 750,
      temperature: 0.1,
    })) as { response?: unknown };
    const parsed =
      typeof response.response === 'string'
        ? JSON.parse(response.response)
        : response.response;
    const bounded = boundedVerdict(parsed);
    if (!bounded) throw new Error('The LLM returned an invalid verdict.');
    return {
      verdict: applyVerdictGuardrails({ ...bounded, mode: 'llm' }, sources),
      error: null,
    };
  } catch (error) {
    return {
      verdict: applyVerdictGuardrails(fallback, sources),
      error:
        error instanceof Error
          ? `LLM synthesis was unavailable: ${error.message.slice(0, 160)}`
          : 'LLM synthesis was unavailable.',
    };
  }
}

export async function onRequestGet({ env }: Context) {
  return json({
    available: Boolean(
      env.AI && env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET_KEY,
    ),
    turnstileSiteKey: env.TURNSTILE_SITE_KEY || null,
    model: MODEL,
    contract: CONTRACT_SOURCE,
    sources: SOURCE_REGISTRY.sources.map(({ id, name, required, access }) => ({
      id,
      name,
      required,
      access,
    })),
    limits: {
      domainsPerRequest: AGENT_POLICY.limits.domains_per_request,
      requestCharacters: 253,
    },
  });
}

export async function onRequestPost({ request, env }: Context) {
  const requestStartedAt = Date.now();
  const requestId = crypto.randomUUID();
  const origin = request.headers.get('origin');
  const testMode =
    env.TURNSTILE_SECRET_KEY === '1x0000000000000000000000000000000AA';
  const localTestOrigin =
    testMode &&
    (origin === 'http://localhost:8788' || origin === 'http://127.0.0.1:8788');
  if (!origin || (!ALLOWED_ORIGINS.has(origin) && !localTestOrigin)) {
    return json({ error: 'Request origin is not allowed.', requestId }, 403);
  }
  if (!request.headers.get('content-type')?.includes('application/json')) {
    return json({ error: 'Expected a JSON request.', requestId }, 415);
  }
  if (Number(request.headers.get('content-length') || 0) > 8192) {
    return json({ error: 'Request is too large.', requestId }, 413);
  }
  if (!env.AI || !env.TURNSTILE_SITE_KEY || !env.TURNSTILE_SECRET_KEY) {
    return json(
      { error: 'The research agent is not configured.', requestId },
      503,
    );
  }

  let body: ResearchRequest;
  try {
    body = (await request.json()) as ResearchRequest;
  } catch {
    return json({ error: 'Invalid JSON.', requestId }, 400);
  }
  if (typeof body.website === 'string' && body.website.trim()) {
    return json({ error: 'Request rejected.', requestId }, 400);
  }
  const domain = normalizeDomain(body.domain);
  const token =
    typeof body.turnstileToken === 'string' ? body.turnstileToken.trim() : '';
  const sessionId =
    typeof body.sessionId === 'string' &&
    /^[a-zA-Z0-9_-]{16,80}$/.test(body.sessionId)
      ? body.sessionId
      : '';
  const apiKey =
    typeof body.virustotalApiKey === 'string'
      ? body.virustotalApiKey.trim().slice(0, 256)
      : '';
  if (!domain) {
    return json(
      {
        error: 'Enter one bare public domain, such as example.com.',
        requestId,
      },
      400,
    );
  }
  if (!token || !sessionId) {
    return json({ error: 'Verification is required.', requestId }, 400);
  }
  const verified = await verifyTurnstile(
    token,
    env.TURNSTILE_SECRET_KEY,
    request.headers.get('cf-connecting-ip') || '',
  );
  if (!verified) {
    return json(
      {
        error: 'Verification failed. Please refresh and try again.',
        requestId,
      },
      403,
    );
  }
  if (env.CHAT_GLOBAL_LIMITER) {
    const result = await env.CHAT_GLOBAL_LIMITER.limit({
      key: 'domain-research',
    });
    if (!result.success) {
      return json(
        { error: 'The agent is busy. Please try later.', requestId },
        429,
      );
    }
  }
  if (env.CHAT_RATE_LIMITER) {
    const result = await env.CHAT_RATE_LIMITER.limit({
      key: `domain:${sessionId}`,
    });
    if (!result.success) {
      return json(
        { error: 'Please wait before researching another domain.', requestId },
        429,
      );
    }
  }

  const [dns, rdap, certificates, virustotal] = await Promise.all([
    lookupDns(domain),
    lookupRdap(domain),
    lookupCertificates(domain),
    lookupVirusTotal(domain, apiKey),
  ]);
  const sources = [dns, rdap, certificates, virustotal];
  const lexical = lexicalFacts(domain);
  const synthesis = await synthesizeVerdict(env, domain, sources, lexical);

  return json({
    requestId,
    domain,
    contract: CONTRACT_SOURCE,
    model: MODEL,
    verdict: synthesis.verdict,
    agentWarning: synthesis.error,
    sources,
    lexicalFacts: lexical,
    safeguards: [
      'Passive, read-only connectors only',
      'One validated public domain per request',
      'No scans, submissions, arbitrary URLs, or credential storage',
      'Every unavailable source remains visible in the report',
    ],
    durationMs: Date.now() - requestStartedAt,
  });
}
