/**
 * Phishy try-it CLI implementation
 * Analyze a .eml file locally — no AWS account, no deployment, no database.
 *
 *   npx phishy-try examples/sample-phish.eml
 *
 * Without ANTHROPIC_API_KEY it runs a dry run: parses the email exactly as
 * the Lambda would (MIME, canonicalization, link unwrapping, attachment
 * metadata) and prints the labeled facts. With a key set, it also runs the
 * real Claude analysis and prints the verdict.
 */

import { readFile } from 'fs/promises';
import { resolve } from 'path';
import { EmailParserService } from '../services/email/parser.service';
import { AnthropicProvider } from '../services/ai/anthropic.provider';
import { SESRecord } from '../types';
import type { S3Service } from '../services/storage/s3.service';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';

export async function main(): Promise<void> {
  const emlPath = process.argv[2];
  if (!emlPath || emlPath === '--help' || emlPath === '-h') {
    console.log(`Usage: phishy-try <path-to-email.eml>

Parses the email exactly as the deployed Lambda would and prints the
labeled facts. Set ANTHROPIC_API_KEY to also run the Claude analysis.

Try the bundled sample: npx phishy-try examples/sample-phish.eml`);
    process.exit(emlPath ? 0 : 1);
  }

  const raw = await readFile(resolve(emlPath), 'utf8');

  // The parser only touches S3 when the event lacks inline content
  const s3Stub = {
    getObject: () => Promise.reject(new Error('S3 not used in local mode')),
  } as unknown as S3Service;

  const parser = new EmailParserService(s3Stub, ['example.com'], 'local');
  const record = {
    ses: {
      mail: {
        source: 'reporter@example.com',
        messageId: 'local-try-run',
        commonHeaders: {
          subject: raw.match(/^Subject:\s*(.+)$/im)?.[1]?.trim() ?? '(no subject)',
          from: ['reporter@example.com'],
        },
        headers: [],
        destination: ['phishy@example.com'],
      },
      receipt: { action: { type: 'Lambda' } },
      content: raw,
    },
  } as unknown as SESRecord;

  const events = await parser.parseSESRecords([record]);
  if (events.length === 0) {
    console.error('Could not parse that file as an email.');
    process.exit(1);
  }

  const emailData = parser.extractEmailData(events[0].msg);

  console.log(`\n${BOLD}=== PARSED (what the Lambda would see) ===${RESET}`);
  console.log(`Subject:    ${emailData.subject}`);
  console.log(`From:       ${emailData.from_email}`);
  if (Object.keys(emailData.forwardedHeaders).length > 0) {
    console.log(`Forwarded:  ${JSON.stringify(emailData.forwardedHeaders)}`);
  }

  if (emailData.contentFlags?.length) {
    console.log(`\n${BOLD}Content integrity flags (obfuscation found):${RESET}`);
    for (const flag of emailData.contentFlags) console.log(`  ${YELLOW}!${RESET} ${flag}`);
  }

  if (emailData.linkFacts?.length) {
    console.log(`\n${BOLD}Links (raw -> true destination):${RESET}`);
    for (const fact of emailData.linkFacts.slice(0, 15)) {
      const arrow =
        fact.raw === fact.canonical ? fact.raw : `${fact.raw}\n      -> ${fact.canonical}`;
      console.log(`  ${arrow}`);
      for (const flag of fact.flags) console.log(`      ${YELLOW}! ${flag}${RESET}`);
    }
  }

  if (emailData.attachments.length > 0) {
    console.log(`\n${BOLD}Attachments (metadata only):${RESET}`);
    for (const a of emailData.attachments) {
      console.log(`  ${a.filename} (${a.contentType}, ${a.size} bytes)`);
      console.log(`      ${DIM}sha256:${a.sha256}${RESET}`);
    }
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.log(
      `\n${DIM}Dry run complete. Set ANTHROPIC_API_KEY to run the Claude analysis.${RESET}\n`
    );
    return;
  }

  console.log(`\n${BOLD}=== ANALYZING with Claude... ===${RESET}`);
  const provider = new AnthropicProvider({ apiKey }, headers => headers);
  const result = await provider.analyzeEmail(emailData);

  const verdictColor = result.isPhishing ? RED : GREEN;
  if (result.assessment) {
    console.log(
      `\nVerdict:    ${verdictColor}${BOLD}${result.assessment.verdict.toUpperCase()}${RESET}  (risk ${result.assessment.riskScore}/100, confidence ${(result.assessment.verdictConfidence * 100).toFixed(0)}%)`
    );
    if (result.assessment.threatVectors.length > 0) {
      console.log(`Vectors:    ${result.assessment.threatVectors.join(', ')}`);
    }
  } else {
    console.log(
      `\nVerdict:    ${verdictColor}${BOLD}${result.isPhishing ? 'PHISHING' : 'NOT PHISHING'}${RESET}  (confidence: ${result.confidence})`
    );
  }
  console.log(`\n${result.summary}\n`);
  if (result.indicators.length > 0) {
    console.log(`${BOLD}Indicators:${RESET}`);
    for (const i of result.indicators) console.log(`  ${YELLOW}*${RESET} ${i}`);
  }
  if (result.recommendations.length > 0) {
    console.log(`\n${BOLD}Recommendations:${RESET}`);
    for (const r of result.recommendations) console.log(`  - ${r}`);
  }
  if (result.tokenUsage) {
    console.log(
      `\n${DIM}${result.tokenUsage.totalTokens} tokens, ${result.processingTimeMs}ms, model ${result.model}${RESET}\n`
    );
  }
}
