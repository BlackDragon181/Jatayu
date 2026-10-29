# Threat Intelligence Feed Integration Architecture
## Open-Source Feed Ingestion, De-Duplication & Big4 Report Formatting

**Scope:** Ingest threat intel from open-source feeds, deduplicate similar intelligence, and generate executive-ready PDF reports in Big 4 consulting format.

---

## 1. THREAT INTELLIGENCE FEED SOURCES

### Primary Feeds (Open-Source)

| Source | URL | Format | Update Frequency | Key Data |
|--------|-----|--------|------------------|----------|
| **Obstracts** | https://app.obstracts.com/feeds | JSON API | Real-time (15min) | CVE, APT campaigns, IoCs, threat actor profiles |
| **FortiGuard** | https://www.fortiguard.com/rss-feeds | RSS | Daily | Threat alerts, malware, vulnerability advisories |
| **CISA ADP** | https://www.cisa.gov/feeds/advisories.json | JSON | Real-time | Known exploited CVEs, CISA advisories |
| **NVD Feed** | https://services.nvd.nist.gov/rest/json/cves/2.0 | JSON API | Real-time | CVE database, CVSS scores, descriptions |
| **Shodan Vulns** | Shodan API (free tier) | JSON | Daily | Exposed services, known vulnerabilities |
| **URLhaus** | https://urlhaus-api.abuse.ch/v1/urls/ | JSON API | Real-time | Malicious URLs, malware distribution |
| **YARA Rules** | https://github.com/Yara-Rules/rules | Git repo | Weekly | Detection signatures (clone periodically) |

### Secondary Feeds (Opt-in)
- **AlienVault OTX:** https://otx.alienvault.com/api/ (requires free account)
- **Darktrace:** community threat reports (Twitter/RSS)
- **SecurityTrails:** DNS history (API, limited free tier)

---

## 2. DATABASE SCHEMA EXTENSIONS

### New Tables for Threat Intel

#### `threat_intelligence_feeds`
Metadata about subscribed feeds.
```sql
CREATE TABLE threat_intelligence_feeds (
  id UUID PRIMARY KEY,
  org_id UUID REFERENCES organizations(id),
  feed_name VARCHAR(255), -- 'Obstracts', 'FortiGuard', 'CISA ADP', etc.
  feed_url VARCHAR(500) NOT NULL,
  feed_type VARCHAR(50), -- 'rss', 'json_api', 'git_repo'
  api_key VARCHAR(255), -- encrypted if needed
  last_fetched TIMESTAMP,
  next_scheduled_fetch TIMESTAMP,
  fetch_interval_minutes INTEGER DEFAULT 60,
  enabled BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_feeds_org ON threat_intelligence_feeds(org_id, enabled);
```

#### `threat_intelligence`
Raw intelligence entries from all feeds.
```sql
CREATE TABLE threat_intelligence (
  id UUID PRIMARY KEY,
  org_id UUID REFERENCES organizations(id),
  feed_id UUID REFERENCES threat_intelligence_feeds(id),
  
  -- Normalization layer
  intel_type VARCHAR(100), -- 'cve', 'malware', 'apt_campaign', 'ioc', 'advisory', 'phishing', 'ransomware'
  title VARCHAR(500) NOT NULL,
  description TEXT,
  
  -- Identifiers
  cve_id VARCHAR(50), -- CVE-2025-XXXXX (if applicable)
  threat_actor VARCHAR(255), -- APT group name
  malware_name VARCHAR(255),
  url_hash VARCHAR(255), -- SHA256 of malicious URL
  
  -- Risk/Impact
  severity VARCHAR(50), -- 'critical', 'high', 'medium', 'low', 'info'
  cvss_score DECIMAL(3,1),
  affected_products TEXT[], -- ["Windows 10", "Windows 11", ...]
  affected_industries TEXT[], -- ["healthcare", "finance", ...]
  
  -- Temporal
  published_date DATE,
  disclosure_date DATE,
  first_seen DATE,
  last_seen DATE,
  
  -- Tracking
  source_url VARCHAR(500),
  source_reference_id VARCHAR(255), -- original feed ID
  relevance_score DECIMAL(3,2), -- 0.0-1.0, computed for your org context
  
  -- De-duplication
  duplicate_group_id UUID, -- links to canonical intel entry
  is_duplicate BOOLEAN DEFAULT FALSE,
  
  -- Raw data
  raw_data JSONB, -- full feed entry for reference
  
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_intel_org_date ON threat_intelligence(org_id, published_date DESC);
CREATE INDEX idx_intel_type ON threat_intelligence(org_id, intel_type);
CREATE INDEX idx_intel_cve ON threat_intelligence(cve_id);
CREATE INDEX idx_intel_actor ON threat_intelligence(threat_actor);
CREATE INDEX idx_intel_duplicate ON threat_intelligence(duplicate_group_id);
```

#### `threat_intelligence_relationships`
Link related intel entries (e.g., CVE + malware + APT actor).
```sql
CREATE TABLE threat_intelligence_relationships (
  id UUID PRIMARY KEY,
  intel_id_1 UUID REFERENCES threat_intelligence(id),
  intel_id_2 UUID REFERENCES threat_intelligence(id),
  relationship_type VARCHAR(100), -- 'exploits', 'attributed_to', 'related_to', 'variant_of'
  confidence_score DECIMAL(3,2), -- 0.0-1.0
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_relationships ON threat_intelligence_relationships(intel_id_1, intel_id_2);
```

#### `threat_intelligence_reports`
User-generated reports (audit trail + PDF storage).
```sql
CREATE TABLE threat_intelligence_reports (
  id UUID PRIMARY KEY,
  org_id UUID REFERENCES organizations(id),
  user_id UUID REFERENCES users(id),
  intel_id UUID REFERENCES threat_intelligence(id),
  
  report_title VARCHAR(500),
  report_format VARCHAR(50), -- 'executive_brief', 'technical_deep_dive', 'ir_playbook'
  format_style VARCHAR(50), -- 'big4_deloitte', 'big4_pwc', 'standard'
  
  -- Content
  executive_summary TEXT,
  threat_analysis TEXT,
  impact_assessment TEXT,
  remediation_steps TEXT,
  iocs TEXT[], -- indicators of compromise
  mitre_mapping JSONB, -- { "techniques": [...], "tactics": [...] }
  
  pdf_file_path VARCHAR(500),
  pdf_generated_at TIMESTAMP,
  
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_reports_org ON threat_intelligence_reports(org_id, created_at DESC);
CREATE INDEX idx_reports_intel ON threat_intelligence_reports(intel_id);
```

---

## 3. FEED INGESTION ARCHITECTURE

### Scheduled Feed Fetch Job (Backend)

**Location:** `server/jobs/threatIntelFetchJob.ts`

```typescript
import axios from 'axios';
import { db } from '../config/database';
import { deduplicateIntel } from '../services/deduplicationService';
import { normalizeIntel } from '../services/threatIntelService';

export async function fetchAllFeeds(orgId: string) {
  const feeds = await db.query(
    'SELECT * FROM threat_intelligence_feeds WHERE org_id = $1 AND enabled = TRUE',
    [orgId]
  );

  for (const feed of feeds) {
    try {
      console.log(`Fetching ${feed.feed_name}...`);
      
      let entries = [];
      if (feed.feed_type === 'rss') {
        entries = await fetchRSSFeed(feed.feed_url);
      } else if (feed.feed_type === 'json_api') {
        entries = await fetchJSONAPI(feed.feed_url, feed.api_key);
      } else if (feed.feed_type === 'git_repo') {
        entries = await fetchGitRepo(feed.feed_url);
      }

      // Normalize entries to common schema
      const normalized = entries.map(entry => normalizeIntel(entry, feed));

      // De-duplicate against existing intelligence
      const deduplicated = await deduplicateIntel(normalized, orgId);

      // Insert new intelligence
      for (const intel of deduplicated) {
        await db.query(
          `INSERT INTO threat_intelligence 
           (id, org_id, feed_id, intel_type, title, description, cve_id, severity, 
            published_date, source_url, raw_data, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())`,
          [
            generateUUID(),
            orgId,
            feed.id,
            intel.type,
            intel.title,
            intel.description,
            intel.cveId,
            intel.severity,
            intel.publishedDate,
            intel.sourceUrl,
            JSON.stringify(intel.raw),
          ]
        );
      }

      // Update feed last_fetched timestamp
      await db.query(
        'UPDATE threat_intelligence_feeds SET last_fetched = NOW() WHERE id = $1',
        [feed.id]
      );

    } catch (error) {
      console.error(`Error fetching ${feed.feed_name}:`, error);
      // Log error but continue with other feeds
    }
  }

  console.log('Feed fetch completed');
}

async function fetchRSSFeed(url: string) {
  // Use node-fetch + xml2js to parse RSS
  const response = await axios.get(url);
  const parser = new xml2js.Parser();
  const parsed = await parser.parseStringPromise(response.data);
  
  return parsed.rss.channel[0].item.map((item: any) => ({
    title: item.title[0],
    description: item.description[0],
    pubDate: item.pubDate[0],
    link: item.link[0],
    guid: item.guid?.[0] || item.link[0],
  }));
}

async function fetchJSONAPI(url: string, apiKey?: string) {
  const headers = apiKey ? { 'Authorization': `Bearer ${apiKey}` } : {};
  const response = await axios.get(url, { headers, timeout: 10000 });
  
  // Response format depends on API; normalize in the normalizeIntel function
  return Array.isArray(response.data) ? response.data : response.data.results || [];
}

async function fetchGitRepo(repoUrl: string) {
  // Clone/pull repo, parse YARA rules or JSON manifest
  // Example: https://github.com/Yara-Rules/rules
  // Return parsed rules as intel entries
  // (stub: could use git2js or simple file operations)
  return [];
}

// Schedule this job to run every hour
import cron from 'node-cron';
cron.schedule('0 * * * *', () => {
  const orgIds = ['org-123']; // Get all orgs
  orgIds.forEach(fetchAllFeeds);
});
```

### Normalization Service

**Location:** `server/services/threatIntelService.ts`

```typescript
export function normalizeIntel(feedEntry: any, feed: Feed): NormalizedIntel {
  let normalized: NormalizedIntel = {
    type: 'advisory', // default
    title: '',
    description: '',
    severity: 'medium',
    publishedDate: new Date(),
    sourceUrl: '',
    raw: feedEntry,
  };

  // Normalize based on feed source
  switch (feed.feed_name) {
    case 'Obstracts':
      normalized = normalizeObstracts(feedEntry);
      break;
    case 'FortiGuard':
      normalized = normalizeFortiGuard(feedEntry);
      break;
    case 'CISA ADP':
      normalized = normalizeCISA(feedEntry);
      break;
    case 'NVD':
      normalized = normalizeNVD(feedEntry);
      break;
    // ... other feeds
  }

  return normalized;
}

function normalizeObstracts(entry: any): NormalizedIntel {
  return {
    type: entry.type || 'advisory', // 'cve', 'malware', 'apt_campaign', etc.
    title: entry.title || entry.name,
    description: entry.description,
    cveId: entry.cve_id,
    threatActor: entry.threat_actor,
    severity: mapSeverity(entry.severity_level),
    cvssScore: entry.cvss_score,
    affectedProducts: entry.affected_software || [],
    publishedDate: new Date(entry.published_date),
    sourceUrl: entry.url,
    raw: entry,
  };
}

function normalizeFortiGuard(entry: any): NormalizedIntel {
  // RSS entry; extract CVE, malware name from title/description
  const title = entry.title;
  const cveMatch = title.match(/CVE-\d{4}-\d{4,}/);
  
  return {
    type: extractTypeFromTitle(title),
    title: title,
    description: entry.description,
    cveId: cveMatch ? cveMatch[0] : null,
    severity: extractSeverityFromTitle(title),
    publishedDate: new Date(entry.pubDate),
    sourceUrl: entry.link,
    raw: entry,
  };
}

function normalizeCISA(entry: any): NormalizedIntel {
  return {
    type: 'cve',
    title: `CVE-${entry.cve_id}: Known Exploited Vulnerability`,
    description: entry.description,
    cveId: entry.cve_id,
    severity: entry.cvss_v3_severity || 'high',
    cvssScore: entry.cvss_v3_score,
    publishedDate: new Date(entry.date_added),
    sourceUrl: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`,
    affectedProducts: entry.affected_software || [],
    raw: entry,
  };
}

function normalizeNVD(entry: any): NormalizedIntel {
  // NVD REST API response
  return {
    type: 'cve',
    title: `${entry.id}: ${entry.cve.descriptions[0]?.value}`,
    description: entry.cve.descriptions[0]?.value,
    cveId: entry.id,
    severity: entry.cve.metrics?.cvssMetricV31?.[0]?.baseSeverity || 'unknown',
    cvssScore: entry.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore,
    publishedDate: new Date(entry.cve.published),
    sourceUrl: `https://nvd.nist.gov/vuln/detail/${entry.id}`,
    raw: entry,
  };
}

function extractTypeFromTitle(title: string): string {
  if (title.includes('CVE')) return 'cve';
  if (title.includes('malware') || title.includes('trojan')) return 'malware';
  if (title.includes('ransomware')) return 'ransomware';
  if (title.includes('phishing')) return 'phishing';
  if (title.includes('APT') || title.includes('campaign')) return 'apt_campaign';
  return 'advisory';
}

function extractSeverityFromTitle(title: string): string {
  if (title.includes('Critical')) return 'critical';
  if (title.includes('High')) return 'high';
  if (title.includes('Medium')) return 'medium';
  if (title.includes('Low')) return 'low';
  return 'medium';
}

function mapSeverity(level: any): string {
  const map: { [key: string]: string } = {
    'critical': 'critical',
    'high': 'high',
    'medium': 'medium',
    'low': 'low',
    'info': 'info',
    '1': 'critical',
    '2': 'high',
    '3': 'medium',
    '4': 'low',
  };
  return map[String(level).toLowerCase()] || 'medium';
}
```

---

## 4. DE-DUPLICATION LOGIC

### De-Duplication Service

**Location:** `server/services/deduplicationService.ts`

```typescript
interface SimilarityMatch {
  existingId: UUID;
  score: number; // 0.0-1.0
}

/**
 * Compare new intel against existing intelligence in the org.
 * Link duplicates to a canonical entry.
 */
export async function deduplicateIntel(
  newEntries: NormalizedIntel[],
  orgId: string
): Promise<NormalizedIntel[]> {
  
  const deduplicated: NormalizedIntel[] = [];

  for (const entry of newEntries) {
    // First: exact match by CVE or threat actor
    const exactMatch = await findExactMatch(entry, orgId);
    if (exactMatch) {
      // Mark as duplicate, link to canonical
      entry.isDuplicate = true;
      entry.duplicateGroupId = exactMatch.duplicateGroupId || exactMatch.id;
      continue; // Don't insert
    }

    // Second: fuzzy text similarity match
    const similarMatches = await findSimilarMatches(entry, orgId);
    if (similarMatches.length > 0) {
      const bestMatch = similarMatches[0];
      
      if (bestMatch.score > 0.85) {
        // High confidence duplicate
        entry.isDuplicate = true;
        entry.duplicateGroupId = bestMatch.existingId;
        continue; // Don't insert
      } else if (bestMatch.score > 0.65) {
        // Possible duplicate; link relationship but insert anyway
        entry.isDuplicate = false;
        entry.duplicateGroupId = null;
        deduplicated.push(entry);
        
        // Create relationship record
        await db.query(
          `INSERT INTO threat_intelligence_relationships 
           (id, intel_id_1, intel_id_2, relationship_type, confidence_score, created_at)
           VALUES ($1, $2, $3, $4, $5, NOW())`,
          [generateUUID(), entry.id, bestMatch.existingId, 'related_to', bestMatch.score]
        );
      } else {
        // Low similarity; insert as new
        deduplicated.push(entry);
      }
    } else {
      // No similar matches; insert as new
      deduplicated.push(entry);
    }
  }

  return deduplicated;
}

/**
 * Exact match logic:
 * - Same CVE ID
 * - Same threat actor + intel type + published date (within 3 days)
 * - Same malware name
 */
async function findExactMatch(entry: NormalizedIntel, orgId: string): Promise<any> {
  // By CVE
  if (entry.cveId) {
    const result = await db.query(
      `SELECT id, duplicate_group_id 
       FROM threat_intelligence 
       WHERE org_id = $1 AND cve_id = $2 AND intel_type = 'cve'
       ORDER BY created_at DESC LIMIT 1`,
      [orgId, entry.cveId]
    );
    if (result.rows.length > 0) return result.rows[0];
  }

  // By threat actor (APT campaign)
  if (entry.threatActor && entry.type === 'apt_campaign') {
    const result = await db.query(
      `SELECT id, duplicate_group_id 
       FROM threat_intelligence 
       WHERE org_id = $1 AND threat_actor = $2 AND intel_type = 'apt_campaign'
       AND ABS(EXTRACT(DAY FROM (published_date - $3::timestamp))) <= 3
       ORDER BY created_at DESC LIMIT 1`,
      [orgId, entry.threatActor, entry.publishedDate]
    );
    if (result.rows.length > 0) return result.rows[0];
  }

  // By malware name
  if (entry.malwareName) {
    const result = await db.query(
      `SELECT id, duplicate_group_id 
       FROM threat_intelligence 
       WHERE org_id = $1 AND malware_name = $2
       ORDER BY created_at DESC LIMIT 1`,
      [orgId, entry.malwareName]
    );
    if (result.rows.length > 0) return result.rows[0];
  }

  return null;
}

/**
 * Fuzzy text similarity:
 * - Cosine similarity of embeddings (via sentence-transformers or simple TF-IDF)
 * - For MVP: use Levenshtein distance on title
 */
async function findSimilarMatches(entry: NormalizedIntel, orgId: string): Promise<SimilarityMatch[]> {
  // Retrieve similar intel by type + timeframe
  const recentIntel = await db.query(
    `SELECT id, title, description, intel_type, published_date
     FROM threat_intelligence 
     WHERE org_id = $1 
     AND intel_type = $2
     AND published_date >= NOW() - INTERVAL '30 days'
     AND is_duplicate = FALSE
     LIMIT 50`,
    [orgId, entry.type]
  );

  const similarities = recentIntel.rows.map(existing => ({
    existingId: existing.id,
    score: computeTextSimilarity(entry.title, existing.title, entry.description, existing.description),
  }));

  return similarities
    .filter(s => s.score > 0.6)
    .sort((a, b) => b.score - a.score)
    .slice(0, 5); // Top 5 matches
}

/**
 * Simple text similarity: Levenshtein distance normalized
 * For production, use: sentence-transformers (Python) or OpenAI embeddings
 */
function computeTextSimilarity(title1: string, title2: string, desc1: string, desc2: string): number {
  const titleSim = levenshteinSimilarity(title1, title2);
  const descSim = levenshteinSimilarity((desc1 || '').substring(0, 200), (desc2 || '').substring(0, 200));
  
  // Weighted: title is more important
  return (titleSim * 0.7) + (descSim * 0.3);
}

function levenshteinSimilarity(a: string, b: string): number {
  const distance = levenshteinDistance(a.toLowerCase(), b.toLowerCase());
  const maxLen = Math.max(a.length, b.length);
  return 1 - (distance / maxLen);
}

function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = Array.from({ length: b.length + 1 }, () =>
    Array(a.length + 1).fill(0)
  );

  for (let i = 0; i <= a.length; i++) matrix[0][i] = i;
  for (let j = 0; j <= b.length; j++) matrix[j][0] = j;

  for (let j = 1; j <= b.length; j++) {
    for (let i = 1; i <= a.length; i++) {
      const indicator = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j][i - 1] + 1,
        matrix[j - 1][i] + 1,
        matrix[j - 1][i - 1] + indicator
      );
    }
  }

  return matrix[b.length][a.length];
}
```

---

## 5. BIG 4 CONSULTING REPORT FORMAT

### Report Template Structure

**Location:** `server/templates/threat-intel-report.html`

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Threat Intelligence Report - {{THREAT_TITLE}}</title>
  <style>
    body { font-family: Arial, sans-serif; color: #333; line-height: 1.6; }
    .header { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 40px; margin-bottom: 30px; page-break-after: avoid; }
    .header h1 { margin: 0; font-size: 28px; }
    .header .metadata { font-size: 12px; margin-top: 10px; opacity: 0.9; }
    
    .section { margin-bottom: 30px; page-break-inside: avoid; }
    .section h2 { border-bottom: 3px solid #1e3c72; padding-bottom: 8px; font-size: 18px; margin-bottom: 15px; }
    
    .summary-box { background: #f0f4f8; border-left: 4px solid #1e3c72; padding: 15px; margin-bottom: 20px; }
    .summary-box .label { font-weight: bold; color: #1e3c72; }
    
    .risk-indicator { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 12px; }
    .risk-critical { background: #fee; color: #c00; }
    .risk-high { background: #fef3cd; color: #856404; }
    .risk-medium { background: #e7e8f0; color: #383d41; }
    .risk-low { background: #d4edda; color: #155724; }
    
    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
    table th { background: #1e3c72; color: white; padding: 10px; text-align: left; font-weight: bold; }
    table td { padding: 10px; border-bottom: 1px solid #ddd; }
    table tr:nth-child(even) { background: #f9f9f9; }
    
    .mitre-matrix { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 20px; }
    .mitre-cell { background: #f0f4f8; border: 1px solid #ccc; padding: 10px; border-radius: 4px; }
    .mitre-cell .label { font-weight: bold; font-size: 11px; color: #1e3c72; }
    .mitre-cell .value { font-size: 12px; margin-top: 4px; }
    
    .ioc-list { background: #f9f9f9; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
    .ioc-list code { display: block; padding: 4px 0; font-family: 'Courier New', monospace; font-size: 11px; word-break: break-all; }
    
    .footer { margin-top: 50px; padding-top: 20px; border-top: 1px solid #ccc; font-size: 11px; color: #666; text-align: center; }
    .page-break { page-break-after: always; }
  </style>
</head>
<body>

<div class="header">
  <h1>{{THREAT_TITLE}}</h1>
  <div class="metadata">
    <div><strong>Report Date:</strong> {{REPORT_DATE}}</div>
    <div><strong>Organization:</strong> {{ORG_NAME}}</div>
    <div><strong>Classification:</strong> Internal Use Only</div>
  </div>
</div>

<!-- EXECUTIVE SUMMARY -->
<div class="section">
  <h2>Executive Summary</h2>
  
  <div class="summary-box">
    <div><span class="label">Threat Type:</span> {{INTEL_TYPE}}</div>
    <div><span class="label">Severity:</span> <span class="risk-indicator risk-{{SEVERITY_LOWER}}">{{SEVERITY}}</span></div>
    <div><span class="label">Impact Scope:</span> {{IMPACT_SCOPE}}</div>
    <div><span class="label">Industry Focus:</span> {{AFFECTED_INDUSTRIES}}</div>
  </div>

  <p>{{EXECUTIVE_SUMMARY}}</p>

  {{#if CVE_ID}}
  <div class="summary-box">
    <div><span class="label">CVE ID:</span> {{CVE_ID}}</div>
    <div><span class="label">CVSS Score:</span> {{CVSS_SCORE}}/10 ({{CVSS_SEVERITY}})</div>
    <div><span class="label">Disclosed:</span> {{DISCLOSURE_DATE}}</div>
  </div>
  {{/if}}
</div>

<!-- THREAT ANALYSIS -->
<div class="section">
  <h2>Threat Analysis</h2>
  
  {{#if THREAT_ACTOR}}
  <div class="summary-box">
    <div><span class="label">Threat Actor:</span> {{THREAT_ACTOR}}</div>
    <div><span class="label">Alias:</span> {{THREAT_ACTOR_ALIASES}}</div>
    <div><span class="label">Attribution Confidence:</span> {{CONFIDENCE_LEVEL}}</div>
    <div><span class="label">Last Activity:</span> {{LAST_ACTIVITY}}</div>
  </div>
  {{/if}}

  <h3>Technical Details</h3>
  <p>{{TECHNICAL_ANALYSIS}}</p>

  {{#if AFFECTED_PRODUCTS}}
  <h3>Affected Products & Versions</h3>
  <table>
    <thead>
      <tr>
        <th>Product</th>
        <th>Affected Versions</th>
        <th>Patch Available</th>
      </tr>
    </thead>
    <tbody>
      {{#each AFFECTED_PRODUCTS}}
      <tr>
        <td>{{this.name}}</td>
        <td>{{this.versions}}</td>
        <td>{{this.patch_available}}</td>
      </tr>
      {{/each}}
    </tbody>
  </table>
  {{/if}}

  {{#if ATTACK_VECTORS}}
  <h3>Attack Vectors & Tactics</h3>
  <p><strong>Primary Vector:</strong> {{PRIMARY_ATTACK_VECTOR}}</p>
  <p><strong>Complexity:</strong> {{ATTACK_COMPLEXITY}}</p>
  <p><strong>Prerequisites:</strong> {{ATTACK_PREREQUISITES}}</p>
  {{/if}}
</div>

<!-- IMPACT ASSESSMENT -->
<div class="section">
  <h2>Impact Assessment</h2>

  <h3>Business Impact</h3>
  <ul>
    <li>{{#each BUSINESS_IMPACTS}}{{this}}<br>{{/each}}</li>
  </ul>

  <h3>Risk to Your Organization</h3>
  <div class="summary-box">
    <div><span class="label">Relevance Score:</span> {{RELEVANCE_SCORE}}/100</div>
    <div><span class="label">Your Industry Match:</span> {{INDUSTRY_MATCH}}</div>
    <div><span class="label">Estimated Exploitability:</span> {{EXPLOITABILITY}}</div>
    <div><span class="label">Time to Exploit (Days):</span> {{TIME_TO_EXPLOIT}}</div>
  </div>

  <p>{{RISK_NARRATIVE}}</p>
</div>

<!-- MITRE ATT&CK FRAMEWORK -->
<div class="section">
  <h2>MITRE ATT&CK Framework</h2>

  <h3>Tactics</h3>
  <div class="mitre-matrix">
    {{#each MITRE_TACTICS}}
    <div class="mitre-cell">
      <div class="label">{{this.tactic}}</div>
      <div class="value">{{this.techniques_count}} techniques</div>
    </div>
    {{/each}}
  </div>

  <h3>Techniques</h3>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Technique</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      {{#each MITRE_TECHNIQUES}}
      <tr>
        <td>{{this.id}}</td>
        <td>{{this.name}}</td>
        <td>{{this.description}}</td>
      </tr>
      {{/each}}
    </tbody>
  </table>
</div>

<!-- INDICATORS OF COMPROMISE -->
{{#if IOCs}}
<div class="section">
  <h2>Indicators of Compromise (IoCs)</h2>

  {{#if IOCs.ips}}
  <h3>Malicious IP Addresses</h3>
  <div class="ioc-list">
    {{#each IOCs.ips}}<code>{{this}} ({{this.metadata.country}})</code>{{/each}}
  </div>
  {{/if}}

  {{#if IOCs.domains}}
  <h3>Malicious Domains</h3>
  <div class="ioc-list">
    {{#each IOCs.domains}}<code>{{this}} ({{this.metadata.first_seen}})</code>{{/each}}
  </div>
  {{/if}}

  {{#if IOCs.hashes}}
  <h3>File Hashes (MD5, SHA1, SHA256)</h3>
  <div class="ioc-list">
    {{#each IOCs.hashes}}<code>{{this.hash}} ({{this.type}} - {{this.filename}})</code>{{/each}}
  </div>
  {{/if}}

  {{#if IOCs.urls}}
  <h3>Malicious URLs</h3>
  <div class="ioc-list">
    {{#each IOCs.urls}}<code>{{this}}</code>{{/each}}
  </div>
  {{/if}}

  <p><em>Use these indicators with your SIEM, IDS/IPS, and endpoint detection tools to hunt for evidence of compromise.</em></p>
</div>
{{/if}}

<!-- REMEDIATION & DETECTION -->
<div class="section">
  <h2>Remediation & Detection Recommendations</h2>

  <h3>Immediate Actions (0–24 hours)</h3>
  <ol>
    {{#each REMEDIATION_IMMEDIATE}}
    <li>{{this}}</li>
    {{/each}}
  </ol>

  <h3>Short-term Mitigation (1–7 days)</h3>
  <ol>
    {{#each REMEDIATION_SHORT_TERM}}
    <li>{{this}}</li>
    {{/each}}
  </ol>

  <h3>Long-term Hardening (1–30 days)</h3>
  <ol>
    {{#each REMEDIATION_LONG_TERM}}
    <li>{{this}}</li>
    {{/each}}
  </ol>

  <h3>Detection Rules</h3>
  <p><strong>YARA Rule:</strong></p>
  <pre><code>{{DETECTION_YARA}}</code></pre>

  <p><strong>Sigma Rule (SIEM):</strong></p>
  <pre><code>{{DETECTION_SIGMA}}</code></pre>

  <p><strong>Hunting Queries (your SIEM):</strong></p>
  <pre><code>{{DETECTION_QUERIES}}</code></pre>
</div>

<!-- INDUSTRY CONTEXT -->
{{#if INDUSTRY_DATA}}
<div class="section page-break">
  <h2>Industry Context & Benchmarking</h2>

  <div class="summary-box">
    <div><span class="label">Industry:</span> {{INDUSTRY}}</div>
    <div><span class="label">Incidents (Last 90 Days):</span> {{INDUSTRY_INCIDENTS}}</div>
    <div><span class="label">Avg MTTR (Your Industry):</span> {{INDUSTRY_MTTR}} days</div>
    <div><span class="label">Your Org vs Industry:</span> {{RELATIVE_RISK}}</div>
  </div>

  <h3>Comparable Threats in {{INDUSTRY}}</h3>
  <table>
    <thead>
      <tr>
        <th>Date</th>
        <th>Threat</th>
        <th>Severity</th>
        <th>Outcome</th>
      </tr>
    </thead>
    <tbody>
      {{#each SIMILAR_PAST_INCIDENTS}}
      <tr>
        <td>{{this.date}}</td>
        <td>{{this.name}}</td>
        <td><span class="risk-indicator risk-{{this.severity_lower}}">{{this.severity}}</span></td>
        <td>{{this.outcome}}</td>
      </tr>
      {{/each}}
    </tbody>
  </table>
</div>
{{/if}}

<!-- REFERENCES -->
<div class="section">
  <h2>References & Sources</h2>
  <ul>
    {{#each REFERENCES}}
    <li><a href="{{this.url}}">{{this.title}}</a> — {{this.source}}</li>
    {{/each}}
  </ul>
  
  <h3>Intelligence Feeds Used</h3>
  <ul>
    {{#each FEEDS_USED}}
    <li>{{this.name}} (Retrieved: {{this.timestamp}})</li>
    {{/each}}
  </ul>
</div>

<!-- FOOTER -->
<div class="footer">
  <p>This report is confidential and intended for authorized recipients only. 
  De-identification markers: [REDACTED]. Generated by ASM Threat Intelligence Platform.</p>
  <p>For questions or escalations, contact: {{CONTACT_EMAIL}}</p>
</div>

</body>
</html>
```

### Report Generation Service

**Location:** `server/services/reportGenerationService.ts`

```typescript
import Handlebars from 'handlebars';
import puppeteer from 'puppeteer';
import { db } from '../config/database';
import { getIntelDetails } from './threatIntelService';
import { getMITREMapping } from './mitreService';
import { getIOCs } from './iocService';
import { getIndustryContext } from './threatLandscapeService';

export async function generateThreatIntelReport(
  intelId: string,
  orgId: string,
  userId: string,
  format: 'pdf' | 'html' = 'pdf'
): Promise<{ filePath: string; fileSize: number }> {
  
  // Fetch threat intelligence details
  const intel = await getIntelDetails(intelId, orgId);
  
  // Fetch related data
  const mitre = await getMITREMapping(intelId);
  const iocs = await getIOCs(intelId);
  const industryContext = await getIndustryContext(intel.affected_industries);
  
  // Compile report template
  const templatePath = './templates/threat-intel-report.html';
  const templateHtml = fs.readFileSync(templatePath, 'utf-8');
  const template = Handlebars.compile(templateHtml);
  
  const reportData = {
    THREAT_TITLE: intel.title,
    REPORT_DATE: new Date().toLocaleDateString(),
    ORG_NAME: await getOrgName(orgId),
    INTEL_TYPE: intel.intel_type,
    SEVERITY: intel.severity.toUpperCase(),
    SEVERITY_LOWER: intel.severity.toLowerCase(),
    IMPACT_SCOPE: intel.affected_industries?.join(', ') || 'General',
    AFFECTED_INDUSTRIES: intel.affected_industries?.join(', ') || 'N/A',
    CVE_ID: intel.cve_id || null,
    CVSS_SCORE: intel.cvss_score || null,
    CVSS_SEVERITY: mapCVSStoSeverity(intel.cvss_score),
    DISCLOSURE_DATE: intel.published_date?.toLocaleDateString(),
    EXECUTIVE_SUMMARY: await synthesizeExecutiveSummary(intel),
    THREAT_ACTOR: intel.threat_actor || null,
    THREAT_ACTOR_ALIASES: intel.raw_data?.aliases?.join(', ') || 'Unknown',
    CONFIDENCE_LEVEL: intel.raw_data?.attribution_confidence || 'Medium',
    LAST_ACTIVITY: intel.last_seen?.toLocaleDateString(),
    TECHNICAL_ANALYSIS: await generateTechnicalAnalysis(intel),
    AFFECTED_PRODUCTS: intel.raw_data?.affected_products || [],
    PRIMARY_ATTACK_VECTOR: intel.raw_data?.attack_vector || 'Unknown',
    ATTACK_COMPLEXITY: intel.raw_data?.attack_complexity || 'Unknown',
    ATTACK_PREREQUISITES: intel.raw_data?.prerequisites?.join(', ') || 'None',
    BUSINESS_IMPACTS: await generateBusinessImpacts(intel),
    RELEVANCE_SCORE: await computeRelevanceScore(intel, orgId),
    INDUSTRY_MATCH: intel.affected_industries?.includes(await getOrgIndustry(orgId)) ? 'HIGH' : 'LOW',
    EXPLOITABILITY: intel.raw_data?.exploitability_score || 'Medium',
    TIME_TO_EXPLOIT: intel.raw_data?.time_to_exploit_days || 'Unknown',
    RISK_NARRATIVE: await generateRiskNarrative(intel, orgId),
    MITRE_TACTICS: mitre.tactics,
    MITRE_TECHNIQUES: mitre.techniques,
    IOCs: iocs,
    REMEDIATION_IMMEDIATE: await getRemediationSteps(intel, 'immediate'),
    REMEDIATION_SHORT_TERM: await getRemediationSteps(intel, 'short_term'),
    REMEDIATION_LONG_TERM: await getRemediationSteps(intel, 'long_term'),
    DETECTION_YARA: intel.raw_data?.yara_rule || '# No YARA rule available',
    DETECTION_SIGMA: intel.raw_data?.sigma_rule || '# No Sigma rule available',
    DETECTION_QUERIES: intel.raw_data?.hunting_queries?.join('\n\n') || '# No queries available',
    INDUSTRY: await getOrgIndustry(orgId),
    INDUSTRY_INCIDENTS: industryContext.incidents_90d,
    INDUSTRY_MTTR: industryContext.avg_mttr,
    RELATIVE_RISK: industryContext.relative_risk,
    SIMILAR_PAST_INCIDENTS: industryContext.similar_incidents,
    REFERENCES: intel.raw_data?.references || [],
    FEEDS_USED: [
      { name: intel.feed_name, timestamp: intel.created_at.toISOString() }
    ],
    CONTACT_EMAIL: 'security@company.com',
  };
  
  const html = template(reportData);
  
  if (format === 'html') {
    const filePath = `/tmp/threat-intel-${intelId}.html`;
    fs.writeFileSync(filePath, html);
    return { filePath, fileSize: html.length };
  }
  
  // Generate PDF via Puppeteer
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: 'networkidle0' });
  
  const pdfPath = `/tmp/threat-intel-${intelId}.pdf`;
  await page.pdf({
    path: pdfPath,
    format: 'A4',
    margin: { top: '10mm', right: '10mm', bottom: '10mm', left: '10mm' },
    printBackground: true,
  });
  
  await browser.close();
  
  const fileSize = fs.statSync(pdfPath).size;
  
  // Move to persistent storage (S3 or /uploads)
  const finalPath = await uploadToStorage(pdfPath, `threat-intel/${intelId}.pdf`);
  
  // Record in database
  await db.query(
    `INSERT INTO threat_intelligence_reports 
     (id, org_id, user_id, intel_id, report_format, format_style, pdf_file_path, pdf_generated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
    [generateUUID(), orgId, userId, intelId, 'big4_deloitte', 'big4_deloitte', finalPath]
  );
  
  return { filePath: finalPath, fileSize };
}

async function synthesizeExecutiveSummary(intel: any): Promise<string> {
  // Use Claude API to generate executive summary
  const response = await anthropic.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 300,
    messages: [
      {
        role: 'user',
        content: `Write a concise 3-4 sentence executive summary of this threat for a security decision-maker. 
        
Threat Title: ${intel.title}
Type: ${intel.intel_type}
Severity: ${intel.severity}
Description: ${intel.description}`,
      },
    ],
  });
  
  return response.content[0].type === 'text' ? response.content[0].text : '';
}

async function generateTechnicalAnalysis(intel: any): Promise<string> {
  if (intel.raw_data?.technical_details) return intel.raw_data.technical_details;
  
  // Fallback: use Claude to generate analysis from description
  const response = await anthropic.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 500,
    messages: [
      {
        role: 'user',
        content: `Provide a technical analysis of this threat for a security engineer. Focus on attack vectors, exploitation methods, and technical indicators.
        
${intel.description}`,
      },
    ],
  });
  
  return response.content[0].type === 'text' ? response.content[0].text : '';
}

async function generateBusinessImpacts(intel: any): Promise<string[]> {
  const impacts: string[] = [];
  
  if (intel.type === 'ransomware') {
    impacts.push('Operational disruption and system downtime');
    impacts.push('Financial loss from ransom demands and recovery costs');
    impacts.push('Reputational damage and customer trust erosion');
  } else if (intel.type === 'data_breach') {
    impacts.push('Loss of sensitive customer/business data');
    impacts.push('Regulatory fines (GDPR, CCPA, etc.)');
    impacts.push('Legal liability and litigation risk');
  }
  
  return impacts;
}

async function computeRelevanceScore(intel: any, orgId: string): Promise<number> {
  const org = await getOrgContext(orgId);
  let score = 0;
  
  // Industry match: +40 points
  if (intel.affected_industries?.includes(org.industry)) score += 40;
  
  // Severity: +30 points (critical = 30, high = 20, medium = 10)
  if (intel.severity === 'critical') score += 30;
  else if (intel.severity === 'high') score += 20;
  else if (intel.severity === 'medium') score += 10;
  
  // Recency: +20 points
  const daysOld = Math.floor((Date.now() - intel.published_date.getTime()) / (1000 * 60 * 60 * 24));
  if (daysOld < 7) score += 20;
  else if (daysOld < 30) score += 15;
  else if (daysOld < 90) score += 10;
  
  // Your assets match: +10 points
  if (intel.affected_products?.some((p: string) => org.products.includes(p))) score += 10;
  
  return Math.min(score, 100);
}
```

---

## 6. FRONTEND: THREAT INTEL LISTING & DETAIL PAGES

### Threat Intelligence List Page

**Location:** `frontend/pages/ThreatIntelligence.tsx`

```typescript
import React, { useState, useEffect } from 'react';
import { useFetch } from '../hooks/useFetch';
import { FilterPanel } from '../components/Common/FilterPanel';
import { Table } from '../components/Common/Table';
import { Badge } from '../components/Common/Badge';
import { Button } from '../components/Common/Button';

export function ThreatIntelligencePage() {
  const [filters, setFilters] = useState({
    type: '', // cve, malware, apt_campaign, etc.
    severity: [],
    dateRange: { start: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), end: new Date() },
    searchQuery: '',
  });

  const { data: intelList, isLoading } = useFetch(
    `/api/threat-intelligence?${new URLSearchParams({
      type: filters.type,
      severity: filters.severity.join(','),
      dateFrom: filters.dateRange.start.toISOString(),
      dateTo: filters.dateRange.end.toISOString(),
      search: filters.searchQuery,
    })}`
  );

  const handleViewDetail = (intelId: string) => {
    window.location.href = `/threat-intel/${intelId}`;
  };

  return (
    <div className="container mx-auto p-6">
      <h1 className="text-3xl font-bold mb-6">Threat Intelligence Feed</h1>

      {/* Filter Panel */}
      <FilterPanel onFilter={setFilters} />

      {/* Intel Table */}
      <Table
        data={intelList?.data || []}
        columns={[
          { key: 'title', label: 'Threat Title', render: (title) => <span className="font-semibold">{title}</span> },
          {
            key: 'intel_type',
            label: 'Type',
            render: (type) => (
              <Badge variant={type === 'cve' ? 'info' : type === 'ransomware' ? 'danger' : 'default'}>
                {type}
              </Badge>
            ),
          },
          {
            key: 'severity',
            label: 'Severity',
            render: (severity) => (
              <Badge variant={severity === 'critical' ? 'danger' : severity === 'high' ? 'warning' : 'info'}>
                {severity.toUpperCase()}
              </Badge>
            ),
          },
          { key: 'cve_id', label: 'CVE ID', render: (cve) => cve || '—' },
          { key: 'threat_actor', label: 'Threat Actor', render: (actor) => actor || '—' },
          { key: 'published_date', label: 'Published', render: (date) => new Date(date).toLocaleDateString() },
          {
            key: 'relevance_score',
            label: 'Relevance',
            render: (score) => <span className="text-sm font-semibold">{score}%</span>,
          },
          {
            key: 'id',
            label: 'Action',
            render: (id) => (
              <Button size="sm" variant="secondary" onClick={() => handleViewDetail(id)}>
                View Details
              </Button>
            ),
          },
        ]}
        isLoading={isLoading}
      />
    </div>
  );
}
```

### Threat Intel Detail Page (with PDF Download)

**Location:** `frontend/pages/ThreatIntelDetail.tsx`

```typescript
import React, { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useFetch } from '../hooks/useFetch';
import { Button } from '../components/Common/Button';
import { Card } from '../components/Common/Card';
import { Badge } from '../components/Common/Badge';
import { Spinner } from '../components/Common/Spinner';

export function ThreatIntelDetailPage() {
  const { intelId } = useParams<{ intelId: string }>();
  const [reportGenerating, setReportGenerating] = useState(false);
  const [downloadUrl, setDownloadUrl] = useState<string | null>(null);

  const { data: intel, isLoading } = useFetch(`/api/threat-intelligence/${intelId}`);

  const handleGenerateReport = async () => {
    setReportGenerating(true);
    try {
      const response = await fetch('/api/threat-intelligence/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          intelId,
          format: 'pdf',
          style: 'big4_deloitte',
        }),
      });

      if (response.ok) {
        const { downloadUrl } = await response.json();
        setDownloadUrl(downloadUrl);
      }
    } catch (error) {
      console.error('Error generating report:', error);
    } finally {
      setReportGenerating(false);
    }
  };

  if (isLoading) return <Spinner />;
  if (!intel) return <div>Threat intelligence not found</div>;

  return (
    <div className="container mx-auto p-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-3xl font-bold mb-2">{intel.title}</h1>
        <div className="flex gap-3">
          <Badge variant={intel.severity === 'critical' ? 'danger' : 'warning'}>
            {intel.severity.toUpperCase()}
          </Badge>
          <Badge variant="info">{intel.intel_type.toUpperCase()}</Badge>
          {intel.cve_id && <Badge variant="secondary">{intel.cve_id}</Badge>}
        </div>
      </div>

      {/* Summary */}
      <Card className="mb-6 p-6">
        <div className="grid grid-cols-4 gap-4">
          <div>
            <div className="text-xs text-gray-500 font-semibold">RELEVANCE SCORE</div>
            <div className="text-2xl font-bold">{intel.relevance_score}%</div>
          </div>
          <div>
            <div className="text-xs text-gray-500 font-semibold">PUBLISHED</div>
            <div className="text-lg">{new Date(intel.published_date).toLocaleDateString()}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500 font-semibold">THREAT ACTOR</div>
            <div className="text-lg">{intel.threat_actor || '—'}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500 font-semibold">CVSS SCORE</div>
            <div className="text-lg">{intel.cvss_score || '—'}</div>
          </div>
        </div>
      </Card>

      {/* Description */}
      <Card className="mb-6 p-6">
        <h2 className="text-xl font-bold mb-3">Overview</h2>
        <p className="text-gray-700 leading-relaxed">{intel.description}</p>
      </Card>

      {/* Affected Industries */}
      {intel.affected_industries?.length > 0 && (
        <Card className="mb-6 p-6">
          <h2 className="text-xl font-bold mb-3">Affected Industries</h2>
          <div className="flex flex-wrap gap-2">
            {intel.affected_industries.map((industry: string) => (
              <Badge key={industry} variant="default">
                {industry}
              </Badge>
            ))}
          </div>
        </Card>
      )}

      {/* Indicators of Compromise */}
      {intel.iocs?.length > 0 && (
        <Card className="mb-6 p-6">
          <h2 className="text-xl font-bold mb-3">Indicators of Compromise</h2>
          <div className="space-y-2">
            {intel.iocs.map((ioc: string, idx: number) => (
              <div key={idx} className="bg-gray-100 p-3 rounded font-mono text-sm break-all">
                {ioc}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Report Generation */}
      <Card className="p-6 bg-blue-50 border-blue-200">
        <h2 className="text-xl font-bold mb-3">Generate Big 4 Consulting Report</h2>
        <p className="text-gray-700 mb-4">
          Download a comprehensive threat analysis report in Big 4 consulting format with executive summary,
          technical analysis, MITRE ATT&CK mapping, remediation steps, and industry context.
        </p>
        <div className="flex gap-3">
          <Button
            onClick={handleGenerateReport}
            disabled={reportGenerating}
            variant="primary"
          >
            {reportGenerating ? 'Generating PDF...' : 'Generate & Download PDF Report'}
          </Button>
          {downloadUrl && (
            <a href={downloadUrl} download className="inline-block">
              <Button variant="secondary">Download PDF</Button>
            </a>
          )}
        </div>
      </Card>
    </div>
  );
}
```

---

## 7. API ENDPOINTS (New/Updated)

### Threat Intelligence Feed Management
```
GET    /api/threat-intelligence/feeds           → list subscribed feeds
POST   /api/threat-intelligence/feeds           → add new feed source
PUT    /api/threat-intelligence/feeds/{id}     → update feed config
DELETE /api/threat-intelligence/feeds/{id}     → unsubscribe feed
POST   /api/threat-intelligence/feeds/{id}/sync → manually trigger feed sync
```

### Threat Intelligence Listing & Search
```
GET    /api/threat-intelligence                 → list intel (paginated, filterable)
     ?type=cve&severity=critical&dateFrom=&dateTo=&search=
GET    /api/threat-intelligence/{id}            → detailed intel view
GET    /api/threat-intelligence/{id}/relationships → linked/related intel
GET    /api/threat-intelligence/{id}/duplicates    → duplicate entries
```

### Report Generation
```
POST   /api/threat-intelligence/report          → generate PDF/HTML report
     { intelId, format: 'pdf'|'html', style: 'big4_deloitte' }
GET    /api/threat-intelligence/reports         → list generated reports
GET    /api/threat-intelligence/reports/{id}   → retrieve report metadata
```

---

## 8. IMPLEMENTATION ROADMAP

### Phase 1: Feed Ingestion (Week 1)
- [ ] Set up scheduled feed fetch job (cron-based)
- [ ] Implement feed fetch for Obstracts, FortiGuard, CISA ADP
- [ ] Test normalization logic for 3+ feed formats
- [ ] Store raw feed data in `threat_intelligence` table

### Phase 2: De-Duplication (Week 2)
- [ ] Implement exact match detection (CVE ID, threat actor)
- [ ] Implement fuzzy text similarity (Levenshtein distance)
- [ ] Test de-duplication with real feed data
- [ ] Create relationship records for related intel

### Phase 3: Report Generation (Week 3)
- [ ] Build report template (HTML → PDF via Puppeteer)
- [ ] Implement Big 4 formatting (styling, sections, TOC)
- [ ] Integrate Claude API for summary/analysis synthesis
- [ ] Generate MITRE ATT&CK mapping
- [ ] Extract IoCs and format for detection tools

### Phase 4: Frontend Pages (Week 4)
- [ ] Build Threat Intelligence list page
- [ ] Build detail page with drill-down
- [ ] Implement PDF generation + download
- [ ] Add filters (type, severity, date range, search)

### Phase 5: Integration (Week 5)
- [ ] Wire threat intel feed data to "Ask AI" feature (provide context)
- [ ] Link threat intel to Cyber Attacks page (show related events)
- [ ] Link to ASM/vulnerability findings (affected products matching)
- [ ] Dashboard widget: "Latest Critical Threats"

---

## 9. SECURITY & COMPLIANCE

- **API Rate Limiting:** 10 req/min on `/api/threat-intelligence/report` (PDF generation is CPU-intensive)
- **Access Control:** Only authenticated users can view intel; role-based if needed (analyst vs. manager)
- **Audit Logging:** Log all report downloads, feed syncs, and de-duplication actions
- **Data Retention:** Keep raw feed data for 90 days; aggregated intelligence indefinitely
- **TLP Marking:** Add TLP (Traffic Light Protocol) colors to each intel (white/green/amber/red)

---

## 10. MOCK FEED DATA FOR TESTING

```json
{
  "obstracts": {
    "title": "APT28 Campaign Targeting Financial Institutions",
    "type": "apt_campaign",
    "threat_actor": "APT28 (Fancy Bear)",
    "severity": "high",
    "affected_industries": ["finance", "technology"],
    "description": "...",
    "iocs": {
      "ips": ["192.0.2.1", "198.51.100.2"],
      "domains": ["malware.com", "c2.attacker.com"],
      "hashes": ["a1b2c3d4e5f6...", "..."]
    }
  }
}
```

---

## DELIVERABLES

1. ✅ Automated threat intel feed ingestion (Obstracts, FortiGuard, CISA, NVD)
2. ✅ De-duplication engine (exact match + fuzzy similarity)
3. ✅ Big 4 consulting report format (HTML template + PDF generation)
4. ✅ CLI/API to generate reports on demand
5. ✅ Frontend pages for intel listing, detail, report download
6. ✅ Database schema for historical tracking + relationships
7. ✅ Integration with "Ask AI" for threat analysis synthesis
