import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import { pool } from '../db/init.js';
import { simpleParser } from 'mailparser';
import iconv from 'iconv-lite';
import emailMemoryStore from '../services/emailMemoryStore.js';

// Email parsing helper functions
function extractSenderEmail(emailFrom) {
  // If no email provided, return empty string
  if (!emailFrom) return '';

  // Try to extract email from format "Name <email@domain.com>"
  const angleEmailMatch = emailFrom.match(/<(.+?)>/);
  if (angleEmailMatch) {
    return angleEmailMatch[1];
  }

  // Try to extract email from format "email@domain.com"
  const simpleEmailMatch = emailFrom.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/);
  if (simpleEmailMatch) {
    return simpleEmailMatch[1];
  }

  // Handle bounce/system emails
  if (emailFrom.includes('bounce') || emailFrom.includes('mailer-daemon')) {
    // Try to extract original sender from common bounce formats
    const bounceMatch = emailFrom.match(/original-sender:\s*([^\s]+@[^\s]+)/i);
    if (bounceMatch) {
      return bounceMatch[1];
    }
    
    // If it's a bounce but we can't find original sender, mark it clearly
    return 'system@bounced.mail';
  }

  // Return original if no pattern matches
  return emailFrom;
}

function extractSenderName(emailFrom) {
  if (!emailFrom) return 'Unknown Sender';

  // Try to extract name from "Name <email@domain.com>"
  const nameMatch = emailFrom.match(/^"?([^"<]+)"?\s*</);
  if (nameMatch) {
    return nameMatch[1].trim();
  }

  // For bounce messages, return clear system name
  if (emailFrom.includes('bounce') || emailFrom.includes('mailer-daemon')) {
    return 'System Notification';
  }

  // If no name found, use email local part
  const email = extractSenderEmail(emailFrom);
  return email.split('@')[0] || 'Unknown Sender';
}

function cleanSubject(subject) {
  if (!subject) return 'No Subject';

  // Remove common prefixes
  const prefixesToRemove = [
    /^re:\s*/i,
    /^fwd:\s*/i,
    /^fw:\s*/i,
    /^\[SPAM\]\s*/i,
    /^bounce:/i,
    /^auto.*reply:\s*/i,
    /^automatic\s+reply:\s*/i
  ];

  let cleanedSubject = subject;
  prefixesToRemove.forEach(prefix => {
    cleanedSubject = cleanedSubject.replace(prefix, '');
  });

  // Decode HTML entities
  cleanedSubject = cleanedSubject
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#(\d+);/g, (match, dec) => String.fromCharCode(dec));

  // Remove excess whitespace
  cleanedSubject = cleanedSubject.replace(/\s+/g, ' ').trim();

  // Limit length
  if (cleanedSubject.length > 100) {
    cleanedSubject = cleanedSubject.substring(0, 97) + '...';
  }

  return cleanedSubject || 'No Subject';
}

async function parseEmailContent(rawContent) {
  try {
    // Decode content if needed
    let decodedContent = rawContent;
    if (typeof rawContent === 'string') {
      try {
        // Try UTF-8 first
        decodedContent = iconv.decode(Buffer.from(rawContent), 'utf8');
      } catch (err) {
        // Fallback to latin1
        decodedContent = iconv.decode(Buffer.from(rawContent), 'latin1');
      }
    }

    // Parse email using mailparser
    const parsed = await simpleParser(decodedContent);

    return {
      headers: parsed.headers,
      subject: parsed.subject,
      from: parsed.from?.text || '',
      to: parsed.to?.text || '',
      text: parsed.text,
      html: parsed.html,
      attachments: parsed.attachments.map(attachment => ({
        filename: attachment.filename,
        contentType: attachment.contentType,
        size: attachment.size,
        content: attachment.content.toString('base64')
      }))
    };
  } catch (error) {
    console.error('Error parsing email:', error);
    return {
      headers: {},
      subject: 'Unable to parse subject',
      from: '',
      to: '',
      text: rawContent,
      html: '',
      attachments: []
    };
  }
}

const router = express.Router();

router.post('/email/incoming', express.urlencoded({ extended: true }), async (req, res) => {
  console.log('Received webhook request');
  console.log('Content-Type:', req.headers['content-type']);
  
  try {
    const rawContent = req.body.body;
    const parsedEmail = await parseEmailContent(rawContent);
    
    // Extract and clean email data
    const senderEmail = extractSenderEmail(req.body.sender || parsedEmail.from);
    const senderName = extractSenderName(req.body.sender || parsedEmail.from);
    const cleanedSubject = cleanSubject(parsedEmail.subject);
    
    const emailData = {
      recipient: req.body.recipient || parsedEmail.to,
      sender: senderEmail,
      senderName: senderName,
      subject: cleanedSubject,
      body_html: parsedEmail.html || '',
      body_text: parsedEmail.text || '',
      attachments: parsedEmail.attachments || []
    };

    // Clean the recipient email address
    const cleanRecipient = emailData.recipient.includes('<') ? 
      emailData.recipient.match(/<(.+)>/)[1] : 
      emailData.recipient.trim();

    // IMPORTANT: Still check if this email address exists in the database
    // This verifies the recipient is valid without having to load all temp emails into memory
    const [tempEmails] = await pool.query(
      'SELECT id FROM temp_emails WHERE email = ? AND expires_at > NOW()',
      [cleanRecipient]
    );

    if (tempEmails.length === 0) {
      console.error('No active temporary email found for recipient:', cleanRecipient);
      return res.status(404).json({ 
        error: 'Recipient not found',
        message: 'No active temporary email found for the specified recipient'
      });
    }

    const tempEmailId = tempEmails[0].id;
    const emailId = uuidv4();

    // Create the received email object
    const receivedEmail = {
      id: emailId,
      temp_email_id: tempEmailId,
      from_email: emailData.sender,
      from_name: emailData.senderName,
      subject: emailData.subject,
      body_html: emailData.body_html,
      body_text: emailData.body_text,
      received_at: new Date().toISOString(),
      attachments: emailData.attachments
    };
    
    // Store in memory instead of database
    emailMemoryStore.storeEmail(cleanRecipient, receivedEmail);
    
    // Log successful storage
    console.log(`Email stored in memory for recipient: ${cleanRecipient}`);

    // Respond to webhook caller quickly
    res.status(200).json({
      message: 'Email received and stored in memory',
      emailId,
      recipient: cleanRecipient
    });

  } catch (error) {
    console.error('Webhook processing error:', error);
    console.error('Error stack:', error.stack);
    
    res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to process the incoming email'
    });
  }
});

export default router;
