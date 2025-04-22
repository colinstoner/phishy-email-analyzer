/**
 * Phishy Email Analyzer
 * 
 * An AI-powered phishing email analysis tool that uses Claude to
 * evaluate suspicious emails and provide detailed security reports.
 * 
 * @license MIT
 */

'use strict';

const { parse } = require('querystring');
const { SES } = require('@aws-sdk/client-ses');
const axios = require('axios');
const { S3 } = require('@aws-sdk/client-s3');

/**
 * CONFIGURATION SETTINGS
 */

// AWS region configuration
const AWS_REGION = process.env.PHISHY_AWS_REGION || process.env.AWS_LAMBDA_FUNCTION_REGION || 'us-west-1';

// Configure AWS clients
const ses = new SES({ region: AWS_REGION });
const s3 = new S3({ region: AWS_REGION });

// S3 bucket configuration
const S3_BUCKET_NAME = process.env.S3_BUCKET_NAME || 'phishy-emails';

// Anthropic API Configuration
const CLAUDE_MODEL = process.env.CLAUDE_MODEL || 'claude-3-sonnet-20240229';

// Security Configuration - domains and email addresses considered trusted
const SAFE_DOMAINS = process.env.SAFE_DOMAINS ? 
  process.env.SAFE_DOMAINS.split(',').map(domain => domain.trim().toLowerCase()) : 
  ['example.com'];

const SAFE_SENDERS = process.env.SAFE_SENDERS ? 
  process.env.SAFE_SENDERS.split(',').map(email => email.trim().toLowerCase()) : 
  ['trusted-sender@example.com'];

// Security team distribution list for CC on all analysis emails
const SECURITY_TEAM_DISTRIBUTION = process.env.SECURITY_TEAM_DISTRIBUTION ?
  process.env.SECURITY_TEAM_DISTRIBUTION.split(',').map(email => email.trim()) :
  [];

// Whether to delete emails from S3 after processing
const DELETE_EMAILS_AFTER_PROCESSING = process.env.DELETE_EMAILS_AFTER_PROCESSING === 'true' ? true : false;

/**
 * EMAIL HEADER DEFINITIONS
 * Define which headers are important for security analysis
 */

// Essential email headers for security analysis
const ESSENTIAL_HEADER_NAMES = [
  // Identity headers
  'From', 'Return-Path', 'Reply-To', 'X-Sender',
  
  // IP tracking headers
  'X-Originating-IP', 'X-Forwarded-For',
  
  // Message ID and threading headers
  'Message-ID', 'In-Reply-To', 'References',
];

// Headers that might contain original sender information in forwarded emails
const ORIGINAL_SENDER_HEADERS = [
  'X-Original-From', 
  'X-Sender', 
  'Original-From', 
  'X-Envelope-From'
];

// Log configuration settings at startup
console.log('Phishy configuration:', {
  model: CLAUDE_MODEL,
  region: process.env.PHISHY_AWS_REGION || 'default region',
  safeDomainsCount: SAFE_DOMAINS.length,
  safeSendersCount: SAFE_SENDERS.length,
  securityTeamCount: SECURITY_TEAM_DISTRIBUTION.length
});

/**
 * RUNTIME CACHE
 * Simple in-memory cache for request deduplication during Lambda container reuse.
 * Lambda containers can be reused between invocations, allowing us to 
 * maintain state for performance optimizations.
 */
const processedEmails = new Set();
const CACHE_MAX_SIZE = 100; // Prevent unbounded growth for long-running containers

/**
 * Main Lambda handler function
 * Processes incoming email events from SES or API Gateway.
 * 
 * @param {Object} event - Lambda event object containing email payload
 * @param {Object} context - Lambda context object
 * @returns {Object} HTTP response object
 */
exports.handler = async (event, context) => {
  console.log('=== PHISHY STARTING ===');
  
  try {
    // Log the full event for debugging
    console.log('Received event:', JSON.stringify(event, null, 2));

    // Extract email events from the input (SES or API Gateway)
    // IMPORTANT: await the parseEmailEvents call since it's now async
    const emailEvents = await parseEmailEvents(event.body || event);
    
    if (!emailEvents || emailEvents.length === 0) {
      console.log('No email events to process');
      return createResponse(200, { success: true, message: 'No email events to process' });
    }
    
    console.log(`Processing ${emailEvents.length} email events`);
    
    // Process each email event
    const processingResults = [];
    for (const emailEvent of emailEvents) {
      if (!emailEvent?.msg) {
        console.log('Invalid email event format, missing msg property');
        processingResults.push({ success: false, error: 'Invalid email event format' });
        continue;
      }
      
      try {
        const result = await processEmailEvent(emailEvent.msg);
        processingResults.push({ success: true, details: result });
      } catch (eventError) {
        console.error('Error processing event:', eventError);
        processingResults.push({ success: false, error: eventError.message });
      }
    }
    
    // Limit cache size to prevent memory leaks in long-running containers
    if (processedEmails.size > CACHE_MAX_SIZE) {
      const toRemove = processedEmails.size - CACHE_MAX_SIZE;
      const iterator = processedEmails.values();
      for (let i = 0; i < toRemove; i++) {
        processedEmails.delete(iterator.next().value);
      }
    }
    
    console.log(`Successfully processed ${processingResults.length} email events`);
    return createResponse(200, { success: true, processed: processingResults.length });
  } catch (error) {
    console.error('Error in handler:', error);
    return createResponse(200, { success: false, error: error.message });
  }
};

/**
 * Creates a standardized API response
 * Used to maintain consistent response format across all endpoints
 * 
 * @param {number} statusCode - HTTP status code
 * @param {object|string} body - Response body
 * @returns {object} Formatted API Gateway response object
 */
function createResponse(statusCode, body) {
  return {
    statusCode,
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Methods': 'OPTIONS,POST'
    },
    body: typeof body === 'string' ? body : JSON.stringify(body)
  };
}

/**
 * Parse email events from various input formats
 * Handles SES records, JSON, URL-encoded form data
 * 
 * @param {any} rawHTTPBody - Input data from API Gateway, SES, etc.
 * @returns {Promise<array>} Array of parsed email events
 */
async function parseEmailEvents(rawHTTPBody) {
  try {
    console.log('Parsing email event payload:', typeof rawHTTPBody);
    
    // If null or undefined, return empty array
    if (!rawHTTPBody) return [];
    
    // CASE 1: Direct SES invocation (SES to Lambda format)
    if (rawHTTPBody.Records && Array.isArray(rawHTTPBody.Records)) {
      const result = await parseSESRecords(rawHTTPBody.Records);
      console.log(`Parsed ${result.length} SES records`);
      return result;
    }
    
    // CASE 2: Handle string/buffer data from API Gateway or other sources
    const bodyStr = convertToString(rawHTTPBody);
    
    // If API Gateway wrapped our content
    if (typeof bodyStr === 'object' && bodyStr.body) {
      return await parseEmailEvents(bodyStr.body);
    }
    
    // CASE 3: URL-encoded form data
    const parsedBody = parse(bodyStr);
    if (parsedBody.email_events) {
      try {
        const events = JSON.parse(parsedBody.email_events);
        return Array.isArray(events) ? events : [];
      } catch (parseError) {
        console.warn('Failed to parse email_events from form data:', parseError.message);
      }
    }
    
    // CASE 4: JSON data
    try {
      const jsonBody = JSON.parse(bodyStr);
      
      if (Array.isArray(jsonBody)) {
        return jsonBody;
      } else if (jsonBody.email_events) {
        const events = Array.isArray(jsonBody.email_events) ? 
          jsonBody.email_events : 
          JSON.parse(jsonBody.email_events);
        return Array.isArray(events) ? events : [];
      }
    } catch (jsonError) {
      console.log('Not a JSON payload or parse error:', jsonError.message);
    }
    
    console.log('No parseable email events found in payload');
    return [];
  } catch (error) {
    console.error('Error parsing payload:', error);
    return [];
  }
}

/**
 * Converts various input types to strings
 * 
 * @param {any} input - The input to convert to string
 * @returns {string} String representation of the input
 */
function convertToString(input) {
  if (typeof input === 'string') return input;
  if (Buffer.isBuffer(input)) return input.toString('utf8');
  if (typeof input === 'object') return JSON.stringify(input);
  return String(input);
}

/**
 * Parses SES Records format emails
 * 
 * @param {array} records - SES Records array
 * @returns {Promise<array>} Array of processed email events
 */
async function parseSESRecords(records) {
  console.log('Processing SES records format');
  
  // Log full record structure for first email to help debug
  if (records.length > 0 && records[0].ses) {
    console.log('SES record structure sample (keys only):',
      Object.keys(records[0].ses).join(', '),
      records[0].ses.mail ? `mail keys: ${Object.keys(records[0].ses.mail).join(', ')}` : '',
      records[0].ses.receipt ? `receipt keys: ${Object.keys(records[0].ses.receipt).join(', ')}` : ''
    );
    
    // Also log S3 action details if present
    if (records[0].ses.receipt?.action) {
      console.log('S3 action details:', {
        type: records[0].ses.receipt.action.type,
        bucketName: records[0].ses.receipt.action.bucketName || 'none',
        objectKey: records[0].ses.receipt.action.objectKey || 'none'
      });
    }
    
    // Log full content types to help debug
    const contentTypeHeader = records[0].ses.mail.headers?.find(h => h.name === 'Content-Type')?.value;
    console.log('Content-Type header:', contentTypeHeader);
    
    // Log message ID for easier tracking
    console.log('Message ID:', records[0].ses.mail.messageId);
  }
  
  // Look for the raw content in the SES event
  if (records.length > 0) {
    const rawContent = checkForRawEmailContent(records[0].ses);
    if (rawContent) {
      console.log(`Found raw email content (${rawContent.length} chars)`);
    } else {
      console.log('No raw email content found in the SES event');
    }
  }
  
  return await Promise.all(records.map(async record => {
    if (record.ses && record.ses.mail) {
      try {
        // Get the raw email content - critical for analysis
        // This will now come from S3 if configured correctly
        const { content: emailContent, s3Location } = await extractEmailContent(record);
        
        if (!emailContent || emailContent.length < 10) {
          console.log('WARNING: Empty or very short email content received');
        } else {
          console.log(`Processing email content (${emailContent.length} chars)`);
        }
        
        // Extract forwarded content from raw email content
        // Parse it differently based on whether it's a raw email format or already processed
        let forwarded = {
          text: '',
          html: null,
          isRaw: false
        };
        
        // Check if it's a raw email format (containing standard email headers)
        const isRawEmail = emailContent.includes('From:') && 
                          (emailContent.includes('Content-Type:') || 
                           emailContent.includes('MIME-Version:'));
        
        if (isRawEmail) {
          console.log('Raw email format detected, extracting content');
          forwarded.isRaw = true;
          
          // Extract body from raw email
          // Look for HTML content
          const htmlMatch = emailContent.match(/<html[\s\S]*?<\/html>/i);
          if (htmlMatch) {
            forwarded.html = htmlMatch[0];
            console.log('HTML content found in raw email');
          }
          
          // For text content, look after headers
          const bodyStart = emailContent.indexOf('\r\n\r\n');
          if (bodyStart > 0) {
            forwarded.text = emailContent.substring(bodyStart + 4);
            // Clean up the text if it contains HTML
            if (forwarded.text.includes('<html') || forwarded.text.includes('<body')) {
              forwarded.text = forwarded.text.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
            }
            console.log(`Text content extracted from raw email (${forwarded.text.length} chars)`);
          }
        } else {
          // Treat as pre-processed content
          console.log('Pre-processed email content detected');
          forwarded.text = emailContent;
          
          // Check if it contains HTML
          if (emailContent.includes('<html') || emailContent.includes('<body') || emailContent.includes('<div')) {
            forwarded.html = emailContent;
            console.log('HTML content detected in pre-processed email');
          }
        }
        
        // If we found HTML content but no text, extract a plain text version
        if (forwarded.html && (!forwarded.text || forwarded.text.length < 10)) {
          forwarded.text = forwarded.html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
          console.log(`Generated text content from HTML (${forwarded.text.length} chars)`);
        }
        
        // Transform SES mail object to our expected format
        const msg = {
          from_email: record.ses.mail.source,
          subject: record.ses.mail.commonHeaders?.subject || 'No Subject',
          headers: extractHeaders(record.ses.mail.headers),
          text: forwarded.text || record.ses.mail.commonHeaders?.subject || 'No email content',
          html: forwarded.html || `<p>${record.ses.mail.commonHeaders?.subject || 'No subject'}</p>`,
          to: record.ses.mail.destination?.join(', ') || '',
          // Add original sender from commonHeaders
          original_sender: record.ses.mail.commonHeaders?.from?.[0] || '',
          // Store SES message ID for deduplication
          messageId: record.ses.mail.messageId || '',
          sesMailTimestamp: record.ses.mail.timestamp || '',
          // Include S3 reference for traceability
          s3Reference: s3Location ? 
            `s3://${s3Location.bucket}/${s3Location.key}` : null,
          // Store S3 location for cleanup after processing
          s3Location: s3Location,
          // Add raw content snippet for debugging (limited to prevent excessive logging)
          rawContentSnippet: emailContent.length > 0 ? 
            `${emailContent.substring(0, 500)}... (${emailContent.length} total chars)` : 'Empty content'
        };
        
        console.log(`Processed email: subject='${msg.subject}', content length=${msg.text.length}`);
        console.log('Text content preview:', msg.text.substring(0, 100) + '...');
        
        return { msg };
      } catch (error) {
        console.error('Error processing SES record:', error);
        // Return null to filter out this record
        return null;
      }
    }
    return null;
  }).filter(item => item !== null));
}

/**
 * Check for raw email content in the SES event
 * 
 * @param {object} ses - SES event data
 * @returns {string|null} Raw email content or null if not found
 */
function checkForRawEmailContent(ses) {
  // Places to check for raw content
  if (ses.content) {
    console.log('Found raw content in ses.content');
    return ses.content;
  }
  
  if (ses.mail?.content) {
    console.log('Found raw content in ses.mail.content');
    return ses.mail.content;
  }
  
  if (ses.receipt?.content) {
    console.log('Found raw content in ses.receipt.content');
    return ses.receipt.content;
  }
  
  if (ses.receipt?.action?.content) {
    console.log('Found raw content in ses.receipt.action.content');
    return ses.receipt.action.content;
  }
  
  // Check if there's a raw message field
  if (ses.rawMessage) {
    console.log('Found raw content in ses.rawMessage');
    return ses.rawMessage;
  }
  
  // Check if there's a base64 encoded version
  if (ses.base64) {
    try {
      console.log('Found base64 encoded content');
      return Buffer.from(ses.base64, 'base64').toString('utf8');
    } catch (error) {
      console.error('Error decoding base64 content:', error.message);
    }
  }
  
  return null;
}

/**
 * Extract email content from SES record
 * Tries multiple strategies to extract the forwarded email content
 * 
 * @param {object} record - SES record object
 * @returns {Promise<string>} Email content
 */
async function extractEmailContent(record) {
  // Debug log the available content sources and structure
  console.log('Content extraction - checking available sources:', {
    hasRawContent: !!record.ses.content,
    hasBody: !!record.ses.mail.body,
    hasBodyHtml: !!(record.ses.mail.body?.html),
    hasBodyText: !!(record.ses.mail.body?.text),
    hasS3Action: !!(record.ses.receipt?.action),
    s3ObjectKey: record.ses.receipt?.action?.objectKey || 'none',
    s3BucketName: record.ses.receipt?.action?.bucketName || 'none',
    contentSize: record.ses.content?.length || 0,
    sesKeys: Object.keys(record.ses).join(', ')
  });
  
  // Log full mail record structure
  console.log('Full mail structure keys:', Object.keys(record.ses.mail));
  
  // Log action details
  console.log('Full action details:', JSON.stringify(record.ses.receipt?.action || {}, null, 2));
  
  let emailContent = '';
  let s3Location = null;
  
  // Check if we have direct content
  if (record.ses.content) {
    console.log('Found direct content in SES event');
    return { content: record.ses.content, s3Location: null };
  }
  
  // CRITICALLY IMPORTANT: Look for raw message in mail.content or receipt.content
  // This is specific to how SES actually provides raw content
  if (record.ses.mail.content) {
    console.log('Found content in mail.content field');
    return { content: record.ses.mail.content, s3Location: null };
  }
  
  if (record.ses.receipt?.content) {
    console.log('Found content in receipt.content field');
    return { content: record.ses.receipt.content, s3Location: null };
  }
  
  // Check the SES headers for Content-Type and extract content based on MIME boundaries
  const contentTypeHeader = record.ses.mail.headers?.find(h => h.name === 'Content-Type')?.value;
  if (contentTypeHeader && contentTypeHeader.includes('multipart/')) {
    console.log('Found multipart content type:', contentTypeHeader);
    
    // Extract boundary
    const boundaryMatch = contentTypeHeader.match(/boundary="([^"]+)"/);
    if (boundaryMatch && boundaryMatch[1]) {
      console.log('Found boundary:', boundaryMatch[1]);
      
      // Look for content in the SES response
      if (record.ses.base64) {
        console.log('Found base64 encoded content');
        try {
          const decodedContent = Buffer.from(record.ses.base64, 'base64').toString('utf8');
          return { content: decodedContent, s3Location: null };
        } catch (error) {
          console.error('Error decoding base64 content:', error.message);
        }
      }
    }
  }
  
  // Next, try to get from S3 if configured
  if (record.ses.receipt?.action?.objectKey && record.ses.receipt?.action?.bucketName) {
    const bucket = record.ses.receipt.action.bucketName;
    const key = record.ses.receipt.action.objectKey;
    s3Location = { bucket, key };
    
    console.log(`Email content found in S3: s3://${bucket}/${key}`);
    
    try {
      emailContent = await getEmailFromS3(bucket, key);
      
      if (emailContent && emailContent.length > 0) {
        console.log(`Retrieved email content from S3 (${emailContent.length} chars)`);
        return { content: emailContent, s3Location };
      } else {
        console.log('S3 content was empty, trying fallback strategies');
      }
    } catch (error) {
      console.error('Error retrieving email from S3:', error.message);
      console.log('Trying fallback content extraction strategies...');
    }
  } else {
    console.log('No S3 information found in action object');
    
    // Instead of giving up, let's try to construct the S3 path ourselves
    // Sometimes SES doesn't include this info but we know our standard path
    try {
      // Standard S3 path pattern for SES stored emails
      const messageId = record.ses.mail.messageId;
      if (messageId) {
        // Common SES S3 bucket structure - adjust this to your actual structure
        const bucket = S3_BUCKET_NAME;
        const key = `emails/${messageId}`;
        s3Location = { bucket, key };
        
        console.log(`Trying standard S3 path: s3://${bucket}/${key}`);
        
        emailContent = await getEmailFromS3(bucket, key);
        
        if (emailContent && emailContent.length > 0) {
          console.log(`Retrieved email content from standard S3 path (${emailContent.length} chars)`);
          return { content: emailContent, s3Location };
        }
      }
    } catch (error) {
      console.error('Error retrieving from standard S3 path:', error.message);
    }
  }
  
  // Try to use the mail body fields if available
  if (record.ses.mail.body) {
    if (record.ses.mail.body.html) {
      console.log('Using mail.body.html field');
      return { content: record.ses.mail.body.html, s3Location };
    } else if (record.ses.mail.body.text) {
      console.log('Using mail.body.text field');
      return { content: record.ses.mail.body.text, s3Location };
    }
  }
  
  // SIMPLIFIED FALLBACK: Extract content from original headers
  // This is drastically simplified but more robust than trying many complex strategies
  try {
    let extractedText = '';
    
    // Add subject
    if (record.ses.mail.commonHeaders?.subject) {
      extractedText += `Subject: ${record.ses.mail.commonHeaders.subject}\n\n`;
    }
    
    // Add from
    if (record.ses.mail.source) {
      extractedText += `From: ${record.ses.mail.source}\n`;
    }
    
    // Add basic headers that might be useful
    const headers = record.ses.mail.headers || [];
    const usefulHeaders = ['Date', 'Message-ID'];
    
    usefulHeaders.forEach(headerName => {
      const header = headers.find(h => h.name === headerName);
      if (header) {
        extractedText += `${header.name}: ${header.value}\n`;
      }
    });
    
    // Add a note indicating this is minimal content
    extractedText += '\n[Note: Full message content could not be retrieved. Only headers are shown.]\n';
    
    console.log('Created minimal content from headers');
    return { content: extractedText, s3Location };
  } catch (error) {
    console.error('Error creating minimal content:', error.message);
    
    // Absolute last resort
    return { 
      content: `Subject: ${record.ses.mail.commonHeaders?.subject || 'Unknown'}\n` +
               `Message-ID: ${record.ses.mail.messageId || 'Unknown'}\n` +
               `Timestamp: ${record.ses.mail.timestamp || 'Unknown'}\n` +
               `[Note: Full message content could not be retrieved]`,
      s3Location 
    };
  }
}

/**
 * Extract headers from SES mail headers
 * 
 * @param {array} headers - SES mail headers array
 * @returns {object} Headers as key-value pairs
 */
function extractHeaders(headers) {
  if (!headers) return {};
  
  return headers.reduce((acc, header) => {
    acc[header.name] = header.value;
    return acc;
  }, {});
}

/**
 * Process a single email event
 * Handles deduplication, validation, analysis, and reporting
 *
 * @param {object} msg - Email message data
 * @returns {object} Processing result with status
 */
async function processEmailEvent(msg) {
  // Extract and normalize email data
  const emailData = extractEmailData(msg);
  
  console.log('Extracted email data:', {
    from: emailData.from_email,
    subject: emailData.subject,
    originalForwarder: emailData.originalForwarder,
    body: emailData.text
  });
  
  // STEP 1: Check for duplicate email (deduplication)
  const processingStatus = checkForDuplicate(msg, emailData);
  if (processingStatus) {
    return processingStatus;
  }
  
  // STEP 2: Validate the email for processing
  const validationResult = validateEmail(emailData);
  if (validationResult.status !== 'valid') {
    return validationResult;
  }
  
  console.log(`Processing validated email from ${emailData.from_email}`);
  
  // STEP 3: Analyze the email using Claude AI
  const analysis = await analyzeEmailWithClaude(emailData);
  
  // STEP 4: Determine recipient for the analysis report
  const recipient = determineRecipient(emailData);
  
  // STEP 5: Send the analysis if we have a valid recipient
  if (isValidEmailRecipient(recipient)) {
    const emailResult = await sendAnalysisEmail(recipient, analysis, emailData.subject, emailData);
    
    // STEP 6: Delete the email from S3 if configured to do so
    if (DELETE_EMAILS_AFTER_PROCESSING && msg.s3Location) {
      console.log('Email processed successfully, cleaning up S3 object');
      await deleteEmailFromS3(msg.s3Location.bucket, msg.s3Location.key);
    }
    
    return { status: 'processed', recipient, messageId: emailResult.messageId };
  } else {
    console.log(`Cannot send analysis - invalid recipient: ${recipient}`);
    return { status: 'incomplete', reason: 'invalid_recipient' };
  }
}

/**
 * Check if an email is a duplicate that we've already processed
 * 
 * @param {object} msg - Email message data
 * @param {object} emailData - Extracted email data
 * @returns {object|null} Processing status if duplicate, null if not
 */
function checkForDuplicate(msg, emailData) {
  const messageId = msg.messageId || emailData.headers?.['Message-ID'] || '';
  const emailFingerprint = `${emailData.from_email}:${emailData.subject}:${messageId}`.trim();
  
  // Check if we've already processed this email in this Lambda execution context
  if (emailFingerprint && processedEmails.has(emailFingerprint)) {
    console.log(`Skipping duplicate email: ${emailFingerprint}`);
    return { status: 'duplicate' };
  }
  
  // Remember this email to prevent duplicate processing
  if (emailFingerprint) {
    processedEmails.add(emailFingerprint);
    console.log(`Added email to processed cache: ${emailFingerprint}`);
  }
  
  return null;
}

/**
 * Validate the email to determine if it should be processed
 * 
 * @param {object} emailData - Extracted email data
 * @returns {object} Validation result with status
 */
function validateEmail(emailData) {
  // Skip if this is already a "Phishing Analysis" email
  if (emailData.subject?.includes('Phishy Analysis')) {
    console.log('Skipping email with "Phishy Analysis" in subject');
    return { status: 'skipped', reason: 'already_analyzed' };
  }
  
  // Skip if not from a trusted source
  if (!isFromTrustedSource(emailData.from_email)) {
    console.log(`Skipping email from untrusted source: ${emailData.from_email}`);
    return { status: 'skipped', reason: 'untrusted_source' };
  }
  
  return { status: 'valid' };
}

/**
 * Determine the recipient for the analysis report
 * 
 * @param {object} emailData - Extracted email data
 * @returns {string} Recipient email address
 */
function determineRecipient(emailData) {
  // Try to use the original sender from commonHeaders.from
  let recipient = '';
  
  if (emailData.original_sender) {
    // Extract email address if it's in the format 'Name <email@example.com>'
    const emailMatch = emailData.original_sender.match(/<([^>]+)>/);
    if (emailMatch && emailMatch[1]) {
      recipient = emailMatch[1];
    } else {
      // Assume it's just an email address
      recipient = emailData.original_sender;
    }
    console.log(`Using original sender as recipient: ${recipient}`);
  }
  
  // Fall back to originalForwarder if available
  if (!recipient) {
    recipient = emailData.originalForwarder;
    if (recipient) {
      console.log(`Using original forwarder as recipient: ${recipient}`);
    }
  }
  
  // Log if we don't have a recipient
  if (!recipient) {
    console.log('No recipient found in original_sender or originalForwarder');
  }
  
  return recipient;
}

/**
 * Check if an email address is valid for receiving analysis reports
 * 
 * @param {string} email - Email address to check
 * @returns {boolean} Whether the email is valid
 */
function isValidEmailRecipient(email) {
  return email && 
    !email.includes('phishing') && 
    !email.includes('noreply') &&
    !email.includes('no-reply');
}

/**
 * Extract relevant email data from email payload
 * Normalizes the data structure for consistent processing
 *
 * @param {object} msg - Raw email message data
 * @returns {object} Normalized email data object
 */
function extractEmailData(msg) {
  // Extract basic email fields with defaults for missing data
  const emailData = {
    from_email: msg.from_email || msg.sender || '',
    subject: msg.subject || 'No Subject',
    text: msg.text || '',
    html: msg.html || '',
    headers: msg.headers || {},
    attachments: Array.isArray(msg.attachments) ? msg.attachments : [],
    sender: msg.sender || '',
    to: normalizeRecipients(msg.to),
    original_sender: msg.original_sender || ''
  };
  
  // Enhance with derived data
  emailData.originalForwarder = findOriginalForwarder(msg, emailData.headers);
  emailData.links = extractLinks(emailData.html || emailData.text);
  
  return emailData;
}

/**
 * Normalize recipient data to a string format
 * 
 * @param {string|array|object} recipients - Raw recipient data
 * @returns {string} Normalized recipient string
 */
function normalizeRecipients(recipients) {
  if (!recipients) return '';
  
  if (typeof recipients === 'string') return recipients;
  
  if (Array.isArray(recipients)) {
    return recipients
      .map(recipient => typeof recipient === 'object' ? (recipient.email || '') : recipient)
      .filter(Boolean)
      .join(', ');
  }
  
  return '';
}

// Find the original forwarder from various sources
function findOriginalForwarder(msg, headers) {
  // Check in X-Forwarded-For header
  if (headers['X-Forwarded-For']) {
    return headers['X-Forwarded-For'];
  }
  
  // Parse from From header
  if (headers?.From) {
    const fromHeaderRegex = /<([^>]+)>/;
    const match = headers.From.match(fromHeaderRegex);
    if (match?.[1] && SAFE_DOMAINS.some(domain => match[1].includes(`@${domain}`)) && !match[1].includes('phishing')) {
      return match[1];
    }
  }
  
  // Check original_recipients
  if (msg.original_recipients) {
    const validRecipient = Array.isArray(msg.original_recipients) ?
      msg.original_recipients.find(email => 
        SAFE_DOMAINS.some(domain => email.includes(`@${domain}`)) && !email.includes('phishing')
      ) : null;
    if (validRecipient) {
      return validRecipient;
    }
  }
  
  // Check the to field
  if (typeof msg.to === 'string' && 
      SAFE_DOMAINS.some(domain => msg.to.includes(`@${domain}`)) && 
      !msg.to.includes('phishing')) {
    return msg.to;
  } else if (Array.isArray(msg.to)) {
    const validEmail = msg.to.find(recipient => {
      const email = typeof recipient === 'string' ? recipient : recipient.email;
      return email && 
             SAFE_DOMAINS.some(domain => email.includes(`@${domain}`)) && 
             !email.includes('phishing');
    });
    if (validEmail) {
      return typeof validEmail === 'string' ? validEmail : validEmail.email;
    }
  }
  
  return '';
}

// Extract the original sender from email headers
function extractOriginalSender(headers) {
  if (!headers) return null;
  
  for (const header of ORIGINAL_SENDER_HEADERS) {
    if (headers[header]) {
      return headers[header];
    }
  }
  
  if (headers['Return-Path']) {
    const returnPathMatch = headers['Return-Path'].match(/<([^>]+)>/);
    if (returnPathMatch?.[1]) {
      return returnPathMatch[1];
    }
    return headers['Return-Path'];
  }
  
  if (headers['Received']) {
    const receivedHeaders = Array.isArray(headers['Received']) 
      ? headers['Received'] 
      : [headers['Received']];
    
    if (receivedHeaders.length > 0) {
      const fromMatch = receivedHeaders[0].match(/from ([^\s]+)/);
      if (fromMatch?.[1]) {
        return fromMatch[1];
      }
    }
  }
  
  return null;
}

// Extract links from email content
function extractLinks(content) {
  if (!content) return [];
  
  const links = [];
  
  // Extract href links from HTML
  if (content.includes('<a href=')) {
    const hrefRegex = /<a\s+(?:[^>]*?\s+)?href="([^"]*)"[^>]*>/gi;
    let match;
    while ((match = hrefRegex.exec(content)) !== null) {
      links.push(match[1]);
    }
  }
  
  // Extract raw URLs
  const urlRegex = /(https?:\/\/[^\s<>"]+)/gi;
  let match;
  while ((match = urlRegex.exec(content)) !== null) {
    if (!links.includes(match[1])) {
      links.push(match[1]);
    }
  }
  
  return links;
}

// Normalize confidence values to a readable format
function normalizeConfidence(confidenceValue) {
  if (typeof confidenceValue === 'string') {
    return confidenceValue;
  }
  
  if (typeof confidenceValue === 'number') {
    const percentage = Math.round(confidenceValue * 100);
    
    if (percentage >= 90) return 'Very High';
    if (percentage >= 70) return 'High';
    if (percentage >= 50) return 'Medium';
    if (percentage >= 30) return 'Low';
    return 'Very Low';
  }
  
  return 'Unknown';
}

// Check if email is from a trusted source
function isFromTrustedSource(emailAddress) {
  if (!emailAddress) return false;
  
  // Check trusted senders list
  if (SAFE_SENDERS.includes(emailAddress.toLowerCase())) {
    return true;
  }
  
  // Check trusted domains
  const domain = emailAddress.split('@')[1]?.toLowerCase();
  if (domain && SAFE_DOMAINS.some(safeDomain => domain === safeDomain || domain.endsWith('.' + safeDomain))) {
    return true;
  }
  
  return false;
}

// Analyze the email using Claude AI
async function analyzeEmailWithClaude(emailData) {
  console.log('Starting Claude analysis');
  
  try {
    const isFromOrganizationForwarder = emailData.originalForwarder && 
      SAFE_DOMAINS.some(domain => emailData.originalForwarder.includes(`@${domain}`));
    
    console.log(`Processing email from ${isFromOrganizationForwarder ? 'organization' : 'external source'}`);
    
    const prompt = constructPhishingAnalysisPrompt(emailData);
    const responseText = await callAnthropicAPI(prompt);
    
    try {
      // Log the first 200 chars of the response for debugging
      console.log(`Claude response preview: ${responseText.substring(0, 200)}...`);
      
      // Extract JSON from response in case there's surrounding text
      let jsonText = responseText;
      
      // Try to find JSON object within the text if not already parseable
      if (!jsonText.trim().startsWith('{')) {
        const jsonMatch = responseText.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          jsonText = jsonMatch[0];
          console.log('Extracted JSON object from response text');
        }
      }
      
      // Clean up any possible markdown code block formatting
      jsonText = jsonText.replace(/```json|```/g, '').trim();
      
      // Parse the JSON
      const analysisData = JSON.parse(jsonText);
      console.log('Successfully parsed JSON response');
      return formatAnalysisToHtml(analysisData);
    } catch (parseError) {
      console.error('Error parsing response as JSON:', parseError.message);
      console.log('Raw response text:', responseText);
      
      // If the response looks like valid JSON but failed to parse,
      // try to create a simpler object with essential fields
      if (responseText.includes('"summary"') && 
          (responseText.includes('"isPhishing"') || responseText.includes('"isPhishing":'))) {
        try {
          // Create a simplified object from the response text
          const analysis = {
            summary: responseText.match(/"summary"\s*:\s*"([^"]+)"/)?.[1] || "Analysis completed",
            isPhishing: responseText.includes('"isPhishing"\s*:\s*true') || responseText.includes('"isPhishing":true'),
            confidence: responseText.match(/"confidence"\s*:\s*"([^"]+)"/)?.[1] || "Medium"
          };
          
          console.log('Created simplified analysis object');
          return formatAnalysisToHtml(analysis);
        } catch (fallbackError) {
          console.error('Fallback parsing also failed:', fallbackError.message);
        }
      }
      
      return `<h2>Email Analysis</h2>
              <p>Note: Analysis couldn't be parsed as JSON.</p>
              <pre>${responseText}</pre>`;
    }
  } catch (error) {
    console.error('Error analyzing email with Claude:', error);
    return `<h2>Email Analysis Error</h2>
            <p>Sorry, there was an error analyzing this email.</p>`;
  }
}

// Call the Anthropic API with a given prompt
async function callAnthropicAPI(prompt) {
  const API_ENDPOINT = 'https://api.anthropic.com/v1/messages';
  const MAX_RETRIES = 3;
  const TIMEOUT_MS = 60000; // 60 seconds (allowing buffer for Lambda's max 60s timeout)
  
  // Log prompt length to help debug timeout issues
  console.log(`Sending prompt to Claude (length: ${prompt.length} chars)`);
  
  try {
    if (!process.env.ANTHROPIC_API_KEY) {
      throw new Error('ANTHROPIC_API_KEY environment variable is not set');
    }
    
    const requestBody = {
      model: CLAUDE_MODEL,
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 4096
    };
    
    console.log('Sending request to Anthropic API with model:', CLAUDE_MODEL);
    
    // Implement retry logic
    let lastError;
    let hadOverloadError = false;
    
    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        console.log(`API attempt ${attempt} of ${MAX_RETRIES}`);
        
        const response = await axios.post(API_ENDPOINT, requestBody, {
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': process.env.ANTHROPIC_API_KEY,
            'anthropic-version': '2023-06-01'
          },
          timeout: TIMEOUT_MS // Set timeout to 60 seconds
        });
        
        if (!response.data?.content?.[0]?.text) {
          throw new Error('Unexpected response format from Anthropic API');
        }
        
        console.log('Successfully received response from Anthropic API');
        return response.data.content[0].text;
      } catch (error) {
        lastError = error;
        console.error(`Anthropic API attempt ${attempt} failed:`, error.message);
        
        // Check for 529 status code (service overloaded)
        if (error.response && error.response.status === 529) {
          console.log('Claude API is currently overloaded (status 529)');
          hadOverloadError = true;
        }
        
        // Don't retry if it's an authorization error or other client errors
        if (error.response && (error.response.status === 401 || error.response.status === 400)) {
          throw error;
        }
        
        // Only retry if we haven't reached max retries
        if (attempt < MAX_RETRIES) {
          // Exponential backoff: 1s, 2s, 4s, etc.
          const backoffTime = Math.pow(2, attempt - 1) * 1000;
          console.log(`Retrying in ${backoffTime}ms...`);
          await new Promise(resolve => setTimeout(resolve, backoffTime));
        }
      }
    }
    
    // If we got here, all retries failed
    if (hadOverloadError) {
      // Special handling for service overload
      return JSON.stringify({
        summary: "Claude's API is currently experiencing high demand and is overloaded. Please try again later.",
        isPhishing: false,
        confidence: "N/A",
        indicators: ["Analysis could not be completed due to Claude API overload (status 529)"],
        recommendations: ["Please wait a few minutes and try forwarding your email again."]
      });
    }
    
    throw lastError || new Error('All API attempts failed');
  } catch (error) {
    console.error('Error calling Anthropic API:', error.message);
    throw error;
  }
}

// Log a preview of the Anthropic response
function logAnthropicResponse(responseText, isFromOrganizationForwarder, originalForwarder) {
  const previewText = responseText.slice(0, 100) + (responseText.length > 100 ? '...' : '');
  console.log('Claude response:', previewText);
}

/**
 * Construct a comprehensive prompt for Claude
 * Creates a detailed prompt with email data for analysis
 *
 * @param {object} emailData - Extracted and processed email data
 * @returns {string} Formatted prompt for Claude
 */
function constructPhishingAnalysisPrompt(emailData) {
  const essentialHeaders = extractEssentialHeaders(emailData.headers);
  
  const isFromOrganizationForwarder = emailData.originalForwarder && 
    SAFE_DOMAINS.some(domain => emailData.originalForwarder.includes(`@${domain}`));
  
  const linksSection = emailData.links && emailData.links.length > 0 ? 
    `--- LINKS IN EMAIL ---\n${emailData.links.join('\n')}\n\n` : '';
  
  let prompt = `Analyze this email for phishing or other malicious content. Assume the forwarded email is from a trusted source and perform no analysis on the trusted source, only the forwarded email contents. Do not comment on future dates or times.

--- EMAIL CONTENT ---
From: ${emailData.from_email}
Subject: ${emailData.subject}
Body:
${emailData.text || 'No text content'}

${linksSection}--- HEADERS ---
${JSON.stringify(essentialHeaders, null, 2)}

--- LEGITIMATE SYSTEMS INFORMATION ---
The organization uses the following legitimate systems:
* Email: Microsoft 365, Gmail
* Cloud Storage: OneDrive, Google Drive
* Authentication: SSO solutions like Okta or Azure AD
* Business Software: Microsoft Office, Salesforce, Zoom
* Security: Email security gateways, spam filters

IMPORTANT: The organization uses SSO for authentication to most systems.

--- ANALYSIS INSTRUCTIONS ---
Please analyze this email for signs of phishing, focusing on:
1. Sender legitimacy (check domain, email headers)
2. Links to unexpected domains or IP addresses
3. Urgency or threatening language
4. Poor grammar or formatting
5. Requests for sensitive information
6. Suspicious attachments

Determine if this is likely legitimate or potentially malicious.

Return your analysis as JSON with these keys:
{
  "summary": "One paragraph summary of analysis findings.",
  "isPhishing": true/false,
  "confidence": "High/Medium/Low",
  "indicators": ["List of specific phishing indicators found"],
  "recommendations": ["List of recommended actions"]
}`;

  return prompt;
}

// Extract essential headers for security analysis
function extractEssentialHeaders(headers) {
  if (!headers) return {};
  
  const essentialHeaders = {};
  for (const headerName of ESSENTIAL_HEADER_NAMES) {
    if (headers[headerName]) {
      essentialHeaders[headerName] = headers[headerName];
    }
  }
  return essentialHeaders;
}

// Format the analysis data as HTML
function formatAnalysisToHtml(analysisData) {
  // Start with the main heading and summary
  let html = ``;
  
  // Add the summary
  if (analysisData.summary) {
    html += `<p><strong>Summary:</strong> ${analysisData.summary}</p>`;
  }
  
  // Add the phishing verdict with appropriate styling
  const isPhishing = analysisData.isPhishing === true || analysisData.isPhishing === 'true';
  const verdictColor = isPhishing ? 'red' : 'green';
  const verdictText = isPhishing ? 'POTENTIALLY MALICIOUS' : 'LIKELY LEGITIMATE';
  
  html += `<p><strong>Verdict:</strong> <span style="color: ${verdictColor}; font-weight: bold;">${verdictText}</span></p>`;
  
  // Add the confidence level
  if (analysisData.confidence) {
    html += `<p><strong>Confidence:</strong> ${normalizeConfidence(analysisData.confidence)}</p>`;
  }
  
  // Add indicators section
  if (analysisData.indicators && analysisData.indicators.length > 0) {
    html += `<h3>Suspicious Indicators</h3>`;
    html += formatArrayAsHtml(analysisData.indicators);
  }
  
  // Add recommendations
  if (analysisData.recommendations && analysisData.recommendations.length > 0) {
    html += `<h3>Recommendations</h3>`;
    html += formatArrayAsHtml(analysisData.recommendations);
  }
  
  return html;
}

// Format an array or string as HTML
function formatArrayAsHtml(data) {
  if (Array.isArray(data)) {
    return '<ul>' + data.map(item => `<li>${item}</li>`).join('') + '</ul>';
  } else if (data) {
    return '<p>' + data + '</p>';
  }
  return '';
}

// Send the analysis via email using Amazon SES
async function sendAnalysisEmail(recipientEmail, analysis, originalSubject, emailData) {
  try {
    const isFromOrganizationForwarder = emailData.originalForwarder && 
      SAFE_DOMAINS.some(domain => emailData.originalForwarder.includes(`@${domain}`));
    
    console.log(`Sending analysis email to ${recipientEmail}`);
    
    const params = {
      Source: `"Phishy" <${process.env.SENDER_EMAIL || 'noreply@' + SAFE_DOMAINS[0]}>`,
      Destination: {
        ToAddresses: [recipientEmail],
        CcAddresses: SECURITY_TEAM_DISTRIBUTION.concat(process.env.CC_ADDRESSES ? process.env.CC_ADDRESSES.split(',') : [])
      },
      Message: {
        Subject: {
          Data: `Phishing Analysis: ${originalSubject}`
        },
        Body: {
          Text: {
            Data: analysis.replace(/<[^>]*>/g, '')
          },
          Html: {
            Data: createEmailHtml(analysis, emailData, originalSubject)
          }
        }
      },
      ConfigurationSetName: process.env.SES_CONFIG_SET || undefined
    };
    
    const result = await ses.sendEmail(params);
    console.log(`Analysis email sent, MessageId: ${result.MessageId}`);
    
    return {
      success: true,
      messageId: result.MessageId
    };
  } catch (error) {
    console.error('Error sending analysis email:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

// Create the HTML content for the email
function createEmailHtml(analysis, emailData, originalSubject) {
  const timestamp = new Date().toLocaleString();
  const version = process.env.VERSION || 'v1.0.0';
  
  return `<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Phishy Analysis: ${originalSubject}</title>
        <style>
            body { 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                line-height: 1.5;
                color: #333; 
                margin: 0;
                padding: 20px;
                background-color: #f9f9f9;
            }
            .container {
                max-width: 800px;
                margin: 0 auto;
                background-color: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .header {
                background-color: #2C3E50;
                color: white;
                padding: 20px;
            }
            .header h1 {
                margin: 0;
                font-size: 22px;
            }
            .analysis {
                padding: 20px;
                border-bottom: 1px solid #eee;
            }
            h2 { 
                margin-top: 0;
                color: #2C3E50;
                font-size: 18px;
            }
            h3 { 
                color: #2c3e50;
                margin-top: 20px;
                font-size: 16px;
            }
            ul { 
                margin-top: 10px;
                padding-left: 25px;
            }
            li { 
                margin-bottom: 5px;
            }
            .footer {
                font-size: 12px;
                color: #777;
                padding: 15px 20px;
                background-color: #f5f5f5;
                border-top: 1px solid #eee;
            }
            .email-details {
                padding: 20px;
                background-color: #f5f5f5;
                border-top: 1px solid #eee;
            }
            .email-header {
                margin-bottom: 15px;
                border-bottom: 1px solid #eee;
                padding-bottom: 10px;
            }
            .email-content {
                background-color: white;
                padding: 15px;
                border-radius: 4px;
                border: 1px solid #eee;
                overflow: auto;
                word-break: break-word;
                max-height: 500px;
                overflow-y: auto;
            }
            .email-toggle {
                text-align: center;
                margin-top: 10px;
                font-size: 14px;
            }
            @media only screen and (max-width: 600px) {
                body {
                    padding: 10px;
                }
                .header, .analysis, .email-details, .footer {
                    padding: 15px;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Phishy Analysis</h1>
            </div>
            <div class="analysis">
                ${analysis}
            </div>
            <div class="footer">
                <p>This analysis was performed by Phishy powered by Anthropic's Claude AI.</p>
                <p>Delivered via Amazon SES | Report time: ${timestamp}</p>
            </div>
        </div>
    </body>
</html>`;
}

/**
 * Retrieve raw email content from S3
 * 
 * @param {string} bucket - S3 bucket name
 * @param {string} key - S3 object key
 * @returns {Promise<string>} Raw email content
 */
async function getEmailFromS3(bucket, key) {
  try {
    console.log(`Retrieving email from S3: s3://${bucket}/${key}`);
    
    // Add retry logic for S3 operations which can sometimes fail transiently
    const MAX_RETRIES = 3;
    let lastError;
    
    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        const response = await s3.getObject({
          Bucket: bucket,
          Key: key
        });
        
        console.log('S3 getObject response received, response type:', typeof response);
        if (response) {
          console.log('S3 response keys:', Object.keys(response));
        }
        
        // Convert the response body to text
        let emailContent = '';
        if (response.Body) {
          console.log('S3 Body type:', typeof response.Body);
          
          try {
            if (typeof response.Body.transformToString === 'function') {
              // AWS SDK v3 method
              emailContent = await response.Body.transformToString();
              console.log(`Successfully retrieved email from S3 (${emailContent.length} bytes)`);
            } else if (Buffer.isBuffer(response.Body)) {
              // Handle Buffer
              emailContent = response.Body.toString('utf8');
              console.log(`S3 content retrieved as buffer (${emailContent.length} bytes)`);
            } else if (typeof response.Body === 'string') {
              // Handle string
              emailContent = response.Body;
              console.log(`S3 content retrieved as string (${emailContent.length} bytes)`);
            } else if (response.Body instanceof Uint8Array) {
              // Handle Uint8Array
              emailContent = Buffer.from(response.Body).toString('utf8');
              console.log(`S3 content retrieved as Uint8Array (${emailContent.length} bytes)`);
            } else if (response.Body instanceof Stream || 
                      (typeof response.Body === 'object' && response.Body.pipe)) {
              // Handle Stream objects
              emailContent = await streamToString(response.Body);
              console.log(`S3 content retrieved as Stream (${emailContent.length} bytes)`);
            } else {
              console.log(`S3 returned unknown Body type: ${typeof response.Body}`);
              // Try to convert to string anyway
              emailContent = String(response.Body);
            }
            
            // Process the email content if needed - sometimes raw emails need pre-processing
            if (emailContent.includes('From:') && emailContent.includes('To:')) {
              console.log('Raw email format detected, using as-is');
            } else {
              console.log('Non-standard email format detected, will try to parse');
            }
            
            // If this is MIME content and has boundary markers, extract the text part
            if (emailContent.includes('Content-Type: multipart/')) {
              console.log('MIME multipart content detected, trying to extract text part');
              const textContent = extractTextFromMIME(emailContent);
              if (textContent && textContent.length > 0) {
                console.log(`Extracted text content from MIME (${textContent.length} chars)`);
                return textContent;
              }
            }
            
            return emailContent;
          } catch (contentError) {
            console.error('Error processing S3 response body:', contentError.message);
            // Continue with the raw data if available
            if (typeof response.Body === 'string') {
              return response.Body;
            } else if (Buffer.isBuffer(response.Body)) {
              return response.Body.toString('utf8');
            }
          }
        } else {
          console.log('S3 returned empty response body');
          return '';
        }
      } catch (error) {
        lastError = error;
        console.error(`S3 retrieval attempt ${attempt} failed:`, error.message);
        
        if (attempt < MAX_RETRIES) {
          // Add exponential backoff
          const backoffTime = Math.pow(2, attempt - 1) * 500; // 500ms, 1s, 2s
          console.log(`Retrying S3 retrieval in ${backoffTime}ms...`);
          await new Promise(resolve => setTimeout(resolve, backoffTime));
        }
      }
    }
    
    // If we get here, all retries failed
    throw lastError || new Error('Failed to retrieve email from S3 after multiple attempts');
  } catch (error) {
    console.error(`Error retrieving email from S3: ${error.message}`);
    throw error;
  }
}

/**
 * Convert a stream to a string
 * 
 * @param {Stream} stream - The stream to convert
 * @returns {Promise<string>} The string representation of the stream
 */
function streamToString(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', (chunk) => chunks.push(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

/**
 * Extract text content from MIME formatted email
 * 
 * @param {string} mimeContent - Raw MIME content
 * @returns {string} Extracted text content
 */
function extractTextFromMIME(mimeContent) {
  try {
    // Very simple MIME parser to extract text part
    // Look for the text/plain part
    const textPartMatch = mimeContent.match(/Content-Type: text\/plain[\s\S]*?(?=Content-Type|$)/i);
    if (textPartMatch) {
      // Find the content after the headers
      const partContent = textPartMatch[0];
      const bodyStartIdx = partContent.indexOf('\r\n\r\n');
      if (bodyStartIdx !== -1) {
        return partContent.substring(bodyStartIdx + 4).trim();
      }
    }
    
    // Look for html part if text part wasn't found
    const htmlPartMatch = mimeContent.match(/Content-Type: text\/html[\s\S]*?(?=Content-Type|$)/i);
    if (htmlPartMatch) {
      // Find the content after the headers
      const partContent = htmlPartMatch[0];
      const bodyStartIdx = partContent.indexOf('\r\n\r\n');
      if (bodyStartIdx !== -1) {
        const htmlContent = partContent.substring(bodyStartIdx + 4).trim();
        // Convert HTML to plain text by removing tags
        return htmlContent.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
      }
    }
    
    return '';
  } catch (error) {
    console.error('Error extracting text from MIME:', error.message);
    return '';
  }
}

/**
 * Delete an email object from S3 after processing
 * 
 * @param {string} bucket - S3 bucket name
 * @param {string} key - S3 object key
 * @returns {Promise<boolean>} Success status
 */
async function deleteEmailFromS3(bucket, key) {
  if (!bucket || !key) {
    console.log('Cannot delete email from S3: missing bucket or key');
    return false;
  }
  
  try {
    console.log(`Deleting email from S3: s3://${bucket}/${key}`);
    
    // Add retry logic for S3 operations which can sometimes fail transiently
    const MAX_RETRIES = 3;
    let lastError;
    
    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        await s3.deleteObject({
          Bucket: bucket, 
          Key: key
        });
        
        console.log('Successfully deleted email from S3');
        return true;
      } catch (error) {
        lastError = error;
        console.error(`S3 deletion attempt ${attempt} failed:`, error.message);
        
        if (attempt < MAX_RETRIES) {
          // Add exponential backoff
          const backoffTime = Math.pow(2, attempt - 1) * 500; // 500ms, 1s, 2s
          console.log(`Retrying S3 deletion in ${backoffTime}ms...`);
          await new Promise(resolve => setTimeout(resolve, backoffTime));
        }
      }
    }
    
    // If we get here, all retries failed
    throw lastError || new Error('Failed to delete email from S3 after multiple attempts');
  } catch (error) {
    console.error(`Error deleting email from S3: ${error.message}`);
    return false;
  }
}

/**
 * IAM Policy required for this Lambda function:
 * {
 *   "Version": "2012-10-17",
 *   "Statement": [
 *     {
 *       "Effect": "Allow",
 *       "Action": [
 *         "ses:SendEmail",
 *         "ses:SendRawEmail"
 *       ],
 *       "Resource": "*"
 *     },
 *     {
 *       "Effect": "Allow",
 *       "Action": [
 *         "s3:GetObject",
 *         "s3:DeleteObject"
 *       ],
 *       "Resource": "arn:aws:s3:::phishy-emails/emails/*"
 *     }
 *   ]
 * }
 * Replace YOUR-BUCKET-NAME with your actual S3 bucket name
 */