/**
 * domainReputation.ts
 * ────────────────────
 * Pluggable domain reputation layer.
 *
 * This module defines the interface contract that any reputation provider
 * must implement, and ships a NullReputationProvider that is used until a
 * real provider is configured.
 *
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │  How to plug in a real provider (e.g. Google Safe Browsing):        │
 * │                                                                       │
 * │  1. Create a new class that implements IReputationProvider.          │
 * │  2. In scan.service.ts, swap `new NullReputationProvider()` for      │
 * │     `new GoogleSafeBrowsingProvider(config.SAFE_BROWSING_API_KEY)`.  │
 * │  3. Add the API key to .env and config/env.ts.                        │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Supported future providers:
 *   - Google Safe Browsing  https://developers.google.com/safe-browsing
 *   - VirusTotal API v3     https://developers.virustotal.com/reference
 *   - PhishTank             https://www.phishtank.com/api_info.php
 *   - URLScan.io            https://urlscan.io/docs/api/
 */

import type { ReputationResult } from '../models/scan.model';

// ─────────────────────────────────────────────────────────────────────────────
// Provider interface
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Contract that every reputation provider must implement.
 *
 * The method is async because all real providers involve an HTTP request.
 */
export interface IReputationProvider {
  /**
   * Look up the reputation of a URL.
   *
   * @param url  The fully-qualified URL to check (already validated).
   * @returns    A ReputationResult describing the verdict.
   */
  checkUrl(url: string): Promise<ReputationResult>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Null provider (default — no external API)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * NullReputationProvider is a no-op that always returns 'unknown'.
 *
 * It is the default provider when no API key is configured.
 * The scoring engine treats 'unknown' as a zero-point contribution.
 */
export class NullReputationProvider implements IReputationProvider {
  async checkUrl(_url: string): Promise<ReputationResult> {
    return {
      status: 'unknown',
      source: null,
      detail: 'No reputation provider configured. Plug in Google Safe Browsing or VirusTotal.',
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stub: Google Safe Browsing  (not implemented — shows the contract)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Skeleton for a future Google Safe Browsing integration.
 *
 * Uncomment, install node-fetch / axios, add your API key in .env, then
 * wire it up in scan.service.ts.
 */
/*
import axios from 'axios';

export class GoogleSafeBrowsingProvider implements IReputationProvider {
  private readonly apiKey: string;
  private static readonly ENDPOINT =
    'https://safebrowsing.googleapis.com/v4/threatMatches:find';

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  async checkUrl(url: string): Promise<ReputationResult> {
    try {
      const body = {
        client: { clientId: 'secureai', clientVersion: '1.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      };

      const response = await axios.post(
        `${GoogleSafeBrowsingProvider.ENDPOINT}?key=${this.apiKey}`,
        body,
      );

      const matches = response.data?.matches ?? [];
      if (matches.length > 0) {
        return {
          status: 'malicious',
          source: 'google-safe-browsing',
          detail: matches[0].threatType ?? 'Threat detected',
        };
      }

      return { status: 'clean', source: 'google-safe-browsing', detail: null };
    } catch {
      return { status: 'unknown', source: 'google-safe-browsing', detail: 'API request failed' };
    }
  }
}
*/

// ─────────────────────────────────────────────────────────────────────────────
// Stub: VirusTotal  (not implemented — shows the contract)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Skeleton for a future VirusTotal integration.
 */
/*
export class VirusTotalProvider implements IReputationProvider {
  private readonly apiKey: string;

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  async checkUrl(url: string): Promise<ReputationResult> {
    // POST https://www.virustotal.com/api/v3/urls
    // then GET the analysis report
    // map response.data.attributes.stats to ReputationResult
    throw new Error('Not implemented yet — see VirusTotal API v3 docs.');
  }
}
*/

// ─────────────────────────────────────────────────────────────────────────────
// Factory (selects the right provider based on config)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns the appropriate provider based on available credentials.
 *
 * When SAFE_BROWSING_API_KEY is set, GoogleSafeBrowsingProvider would be used.
 * Until then, returns the NullReputationProvider.
 *
 * Extend this function as new providers are implemented.
 */
export function getReputationProvider(): IReputationProvider {
  // Future: if (config.SAFE_BROWSING_API_KEY) return new GoogleSafeBrowsingProvider(config.SAFE_BROWSING_API_KEY);
  // Future: if (config.VIRUSTOTAL_API_KEY) return new VirusTotalProvider(config.VIRUSTOTAL_API_KEY);
  return new NullReputationProvider();
}
