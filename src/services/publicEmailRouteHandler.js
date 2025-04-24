import { pool } from '../db/init.js';
import emailMemoryStore from './emailMemoryStore.js';

/**
 * Handle the public/:email route to fetch emails for a public user
 * Uses memory store first, then falls back to database
 */
export async function handlePublicEmailRoute(req, res) {
  try {
    res.setHeader('Cache-Control', 'public, max-age=5'); // Cache for 5 seconds
    
    const requestedEmail = req.params.email;
    
    // First check memory store for this email
    const memoryEmails = emailMemoryStore.getEmails(requestedEmail);
    
    if (memoryEmails.length > 0) {
      console.log(`Serving ${memoryEmails.length} emails from memory for ${requestedEmail}`);
      return res.json(memoryEmails);
    }
    
    // If no emails in memory, fall back to database
    console.log(`No emails in memory for ${requestedEmail}, checking database...`);
    const [emails] = await pool.query(`
      SELECT re.*, te.email as temp_email
      FROM received_emails re
      JOIN temp_emails te ON re.temp_email_id = te.id
      WHERE te.email = ?
      ORDER BY re.received_at DESC
    `, [requestedEmail]);

    // Return database results
    console.log(`Found ${emails.length} emails in database for ${requestedEmail}`);
    res.json(emails);
  } catch (error) {
    console.error('Failed to fetch public emails:', error);
    res.status(400).json({ error: 'Failed to fetch emails' });
  }
} 