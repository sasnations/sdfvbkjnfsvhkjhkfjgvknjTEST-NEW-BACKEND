import { ImapFlow } from 'imapflow';
import { v4 as uuidv4 } from 'uuid';
import { pool } from '../db/init.js';
import crypto from 'crypto';

// In-memory storage
const emailCache = new Map(); // Cache for fetched emails
const aliasCache = new Map(); // Cache for active aliases during runtime
const activeImapAccounts = new Set(); // Track which accounts are being actively polled
const imapClients = new Map(); // Store active IMAP clients

// Configuration
const MAX_CACHE_SIZE = 10000; // Maximum number of emails to cache
const ALIAS_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds for in-memory cache
const POLLING_INTERVALS = {
  high: 60000,     // 1 minute for high priority accounts
  medium: 180000,  // 3 minutes for medium priority
  low: 300000      // 5 minutes for low priority accounts
};

// Encryption utilities for password security
const encryptionKey = process.env.ENCRYPTION_KEY || 'default-encryption-key';

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryptionKey), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  const textParts = text.split(':');
  const iv = Buffer.from(textParts[0], 'hex');
  const encryptedText = Buffer.from(textParts[1], 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(encryptionKey), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

// Gmail Account Management
export async function addGmailAccount(email, appPassword) {
  try {
    console.log(`Adding Gmail account: ${email}`);
    
    // Encrypt the app password
    const encryptedPassword = encrypt(appPassword);
    
    // Start a transaction
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      
      // Check if account already exists
      const [existingAccounts] = await connection.query(
        'SELECT * FROM gmail_accounts WHERE email = ?',
        [email]
      );
      
      const id = existingAccounts.length > 0 ? existingAccounts[0].id : uuidv4();
      
      if (existingAccounts.length > 0) {
        // Update existing account
        await connection.query(
          `UPDATE gmail_accounts SET 
           app_password = ?,
           status = 'active',
           last_used = NOW(),
           updated_at = NOW()
           WHERE id = ?`,
          [
            encryptedPassword,
            id
          ]
        );
        console.log(`Updated existing Gmail account: ${email}`);
      } else {
        // Insert new account
        await connection.query(
          `INSERT INTO gmail_accounts (
            id, email, app_password, quota_used, alias_count, status, last_used
          ) VALUES (?, ?, ?, 0, 0, 'active', NOW())`,
          [
            id,
            email,
            encryptedPassword
          ]
        );
        console.log(`Added new Gmail account: ${email}`);
      }
      
      await connection.commit();
      
      // Start polling for this account
      if (!activeImapAccounts.has(email)) {
        console.log(`Starting polling for account: ${email}`);
        schedulePolling(email);
        activeImapAccounts.add(email);
      }
      
      return { email, id };
      
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
    
  } catch (error) {
    console.error('Failed to add Gmail account:', error);
    throw new Error('Failed to add Gmail account: ' + error.message);
  }
}

// Create IMAP client for an account
async function createImapClient(accountEmail) {
  try {
    // Get account from database
    const [accounts] = await pool.query(
      'SELECT * FROM gmail_accounts WHERE email = ?',
      [accountEmail]
    );
    
    if (accounts.length === 0) {
      throw new Error(`Gmail account ${accountEmail} not found`);
    }
    
    const account = accounts[0];
    
    if (!account.app_password) {
      throw new Error(`No app password available for ${accountEmail}`);
    }
    
    const appPassword = decrypt(account.app_password);
    
    // Create new IMAP client
    const client = new ImapFlow({
      host: 'imap.gmail.com',
      port: 993,
      secure: true,
      auth: {
        user: accountEmail,
        pass: appPassword
      },
      logger: false, // Set to true for debugging
      emitLogs: false,
      disableAutoIdle: true, // We'll manage IDLE ourselves
      timeoutConnection: 30000, // 30 seconds connection timeout
      timeoutIdle: 540000, // 9 minutes idle timeout (Gmail drops at ~10 min)
      tls: {
        rejectUnauthorized: true
      }
    });
    
    // Store the client
    imapClients.set(accountEmail, client);
    
    return client;
  } catch (error) {
    console.error(`Error creating IMAP client for ${accountEmail}:`, error);
    throw error;
  }
}

// Alias Generation with improved reliability
export async function generateGmailAlias(userId, strategy = 'dot', domain = 'gmail.com') {
  // Get next available account using load balancing from database
  try {
    const account = await getNextAvailableAccount();
    
    if (!account) {
      console.error('No Gmail accounts available. Active accounts:', [...activeImapAccounts]);
      throw new Error('No Gmail accounts available');
    }
    
    console.log(`Generating ${strategy} alias using account: ${account.email} with domain: ${domain}`);
    
    // Generate unique alias based on strategy
    const alias = strategy === 'dot' 
      ? generateDotAlias(account.email, domain)
      : generatePlusAlias(account.email, domain);
    
    console.log(`Generated alias: ${alias}`);
    
    // Update alias count in database
    const connection = await pool.getConnection();
    
    try {
      await connection.beginTransaction();
      
      // Update alias count in gmail_accounts
      await connection.query(
        'UPDATE gmail_accounts SET alias_count = alias_count + 1, last_used = NOW(), updated_at = NOW() WHERE id = ?',
        [account.id]
      );
      
      await connection.commit();
      
      // Store in-memory alias cache
      aliasCache.set(alias, {
        parentAccount: account.email,
        parentAccountId: account.id,
        created: Date.now(),
        lastAccessed: Date.now(),
        userId: userId || null,
        expires: new Date(Date.now() + ALIAS_TTL)
      });
      
      return { alias };
      
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
    
  } catch (error) {
    console.error('Failed to generate Gmail alias:', error);
    throw new Error('Failed to generate alias: ' + error.message);
  }
}

function generateDotAlias(email, domain = 'gmail.com') {
  // Extract username from email
  const username = email.split('@')[0];
  
  // Insert dots randomly in username
  let dotUsername = '';
  for (let i = 0; i < username.length - 1; i++) {
    dotUsername += username[i];
    // Random chance to insert a dot, but ensure no consecutive dots
    if (Math.random() > 0.5 && username[i] !== '.' && username[i+1] !== '.') {
      dotUsername += '.';
    }
  }
  // Add last character
  dotUsername += username[username.length - 1];
  
  // Use the specified domain (gmail.com or googlemail.com)
  return `${dotUsername}@${domain}`;
}

function generatePlusAlias(email, domain = 'gmail.com') {
  // Extract username from email
  const username = email.split('@')[0];
  
  // Add random tag
  const tag = Math.random().toString(36).substring(2, 8);
  
  // Use the specified domain (gmail.com or googlemail.com)
  return `${username}+${tag}@${domain}`;
}

// Email Fetching with improved caching and retrieval
export async function fetchGmailEmails(userId, aliasEmail) {
  console.log(`Fetching emails for ${aliasEmail}, requested by user ${userId || 'anonymous'}`);
  
  try {
    // Check if alias exists in memory cache first
    let parentAccount = null;
    
    if (aliasCache.has(aliasEmail)) {
      const cachedAlias = aliasCache.get(aliasEmail);
      parentAccount = cachedAlias.parentAccount;
      
      // Update last accessed timestamp in memory
      cachedAlias.lastAccessed = Date.now();
      aliasCache.set(aliasEmail, cachedAlias);
      
      console.log(`Found alias ${aliasEmail} in memory cache, parent account: ${parentAccount}`);
    } else {
      console.log(`Alias ${aliasEmail} not found in memory cache, checking user permissions`);
      
      // Modified permission check for aliases not in memory
      // Check if this user has permission to access this alias (only for non-anonymous users)
      if (userId && !userId.startsWith('anon_')) {
        // For authenticated users, we'll be more permissive since we don't have DB records
        // We'll generate a new alias for them instead of failing
        console.log(`Authorized user ${userId} requesting missing alias, will create new one`);
        const result = await generateGmailAlias(userId);
        return fetchGmailEmails(userId, result.alias); // Recursive call with new alias
      }
      
      // For anonymous users with missing alias, also generate a new one
      if (userId && userId.startsWith('anon_')) {
        console.log(`Anonymous user ${userId} requesting missing alias, will create new one`);
        const result = await generateGmailAlias(userId);
        return fetchGmailEmails(userId, result.alias); // Recursive call with new alias
      }
      
      throw new Error('Alias not found');
    }
    
    if (!parentAccount) {
      throw new Error('Parent account not found for alias');
    }
    
    // Check parent account status
    const [accounts] = await pool.query(
      'SELECT * FROM gmail_accounts WHERE email = ?',
      [parentAccount]
    );
    
    if (accounts.length === 0) {
      throw new Error('Gmail account unavailable');
    }
    
    const account = accounts[0];
    
    if (account.status !== 'active') {
      console.error(`Account ${parentAccount} is not active. Current status: ${account.status}`);
      
      // Auto-recovery: Try to reactivate account if it's not in auth-error state
      if (account.status !== 'auth-error') {
        console.log(`Attempting to reactivate account ${parentAccount}`);
        await pool.query(
          'UPDATE gmail_accounts SET status = \'active\', updated_at = NOW() WHERE id = ?',
          [account.id]
        );
        
        // If the account was inactive, reactivate polling for it
        if (!activeImapAccounts.has(parentAccount)) {
          console.log(`Restarting polling for reactivated account ${parentAccount}`);
          schedulePolling(parentAccount);
          activeImapAccounts.add(parentAccount);
        }
      } else {
        throw new Error('Gmail account unavailable - authentication error');
      }
    }
    
    // Get cached emails
    console.log(`Looking for cached emails for alias ${aliasEmail}`);
    const cachedEmails = [];
    for (const [key, email] of emailCache.entries()) {
      if (key.startsWith(`${aliasEmail}:`)) {
        cachedEmails.push(email);
      }
    }
    
    // Return cached emails sorted by date (newest first)
    console.log(`Found ${cachedEmails.length} cached emails for ${aliasEmail}`);
    return cachedEmails.sort((a, b) => 
      new Date(b.internalDate) - new Date(a.internalDate)
    );
  
  } catch (error) {
    console.error(`Error fetching Gmail emails for ${aliasEmail}:`, error);
    throw error;
  }
}

// Only return most recent one
export async function getUserAliases(userId) {
  if (!userId) return [];
  
  try {
    // Get only the most recent alias from memory cache for this user
    const userAliases = [];
    let mostRecentAlias = null;
    let mostRecentTime = 0;
    
    for (const [alias, data] of aliasCache.entries()) {
      if (data.userId === userId && data.created > mostRecentTime) {
        mostRecentAlias = alias;
        mostRecentTime = data.created;
      }
    }
    
    if (mostRecentAlias) {
      userAliases.push(mostRecentAlias);
    }
    
    console.log(`User ${userId} has ${userAliases.length} recent alias in memory cache: ${mostRecentAlias}`);
    return userAliases;
  } catch (error) {
    console.error('Failed to get user aliases from memory:', error);
    return [];
  }
}

export async function rotateUserAlias(userId, strategy = 'dot', domain = 'gmail.com') {
  try {
    // Generate a new alias for the user (will use load balancing)
    return await generateGmailAlias(userId, strategy, domain);
  } catch (error) {
    console.error('Failed to rotate Gmail alias:', error);
    throw error;
  }
}

// Email Polling (Background Task) with improved error handling and frequency
async function pollForNewEmails(accountEmail) {
  let client = null;
  
  try {
    // Get account from database
    const [accounts] = await pool.query(
      'SELECT * FROM gmail_accounts WHERE email = ?',
      [accountEmail]
    );
    
    if (accounts.length === 0) {
      console.log(`Account ${accountEmail} not found, skipping polling`);
      return;
    }
    
    const account = accounts[0];
    
    if (account.status !== 'active') {
      console.log(`Skipping polling for inactive account ${accountEmail} (status: ${account.status})`);
      
      // Only attempt recovery if the account has been inactive for at least 10 minutes
      // (but not if it's in auth-error state)
      if (account.status !== 'auth-error') {
        const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
        if (new Date(account.updated_at) < tenMinutesAgo) {
          console.log(`Attempting to auto-recover account ${accountEmail}`);
          await pool.query(
            'UPDATE gmail_accounts SET status = \'active\', updated_at = NOW() WHERE id = ?',
            [account.id]
          );
        }
      }
      return;
    }
    
    // Get all aliases associated with this account from in-memory cache only
    const accountAliases = [];
    for (const [alias, data] of aliasCache.entries()) {
      if (data.parentAccount === accountEmail) {
        accountAliases.push(alias);
      }
    }
    
    if (accountAliases.length === 0) {
      console.log(`Skipping polling for ${accountEmail}: no aliases in memory cache`);
      return;
    }
    
    console.log(`Polling for new emails for account ${accountEmail} with ${accountAliases.length} aliases...`);
    
    // Get or create IMAP client
    if (imapClients.has(accountEmail) && imapClients.get(accountEmail).usable) {
      client = imapClients.get(accountEmail);
    } else {
      client = await createImapClient(accountEmail);
      await client.connect();
    }
    
    // Select INBOX
    const mailbox = await client.mailboxOpen('INBOX');
    console.log(`Opened INBOX for ${accountEmail}, message count: ${mailbox.exists}`);
    
    // Get the last 20 messages (or fewer if there are fewer)
    const messageCount = Math.min(mailbox.exists, 20);
    
    if (messageCount === 0) {
      console.log(`No messages in INBOX for ${accountEmail}`);
      return;
    }
    
    // Fetch the most recent messages
    const fetchOptions = {
      uid: true,
      envelope: true,
      bodyStructure: true,
      source: true // Get full message source
    };
    
    // Use sequence numbers to get the most recent messages
    const fetchFrom = Math.max(1, mailbox.exists - messageCount + 1);
    const fetchRange = `${fetchFrom}:*`;
    
    console.log(`Fetching messages ${fetchRange} for ${accountEmail}`);
    
    // Process each message
    for await (const message of client.fetch(fetchRange, fetchOptions)) {
      try {
        // Check if this message is addressed to any of our aliases
        const toAddresses = message.envelope.to || [];
        const recipientAlias = toAddresses.find(addr => 
          accountAliases.includes(addr.address.toLowerCase())
        )?.address.toLowerCase();
        
        if (recipientAlias) {
          console.log(`Found message for alias ${recipientAlias}, UID: ${message.uid}`);
          
          // Process the message
          const processedEmail = processImapMessage(message, recipientAlias);
          
          // Add to cache
          const cacheKey = `${recipientAlias}:${message.uid}`;
          if (!emailCache.has(cacheKey)) {
            addToEmailCache(cacheKey, processedEmail);
            console.log(`Added message ${message.uid} to cache for ${recipientAlias}`);
          }
        }
      } catch (messageError) {
        console.error(`Error processing message ${message.uid}:`, messageError);
      }
    }
    
    // Update account metrics in database
    await pool.query(
      'UPDATE gmail_accounts SET quota_used = quota_used + 1, last_used = NOW(), updated_at = NOW() WHERE id = ?',
      [account.id]
    );
    
  } catch (error) {
    console.error(`Error polling Gmail account ${accountEmail}:`, error);
    
    // Update account status in database with more detailed status
    let statusUpdate = 'error';
    if (error.message?.includes('Invalid credentials') || error.message?.includes('authentication failed')) {
      statusUpdate = 'auth-error';
      console.log(`Account ${accountEmail} has invalid credentials - marked as auth-error`);
    } else if (error.message?.includes('quota') || error.message?.includes('rate limit')) {
      statusUpdate = 'rate-limited';
      console.log(`Account ${accountEmail} is rate limited`);
    } else if (error.message?.includes('network') || error.message?.includes('timeout')) {
      statusUpdate = 'network-error';
      console.log(`Network error with account ${accountEmail} - will retry`);
    }
    
    try {
      await pool.query(
        'UPDATE gmail_accounts SET status = ?, updated_at = NOW() WHERE email = ?',
        [statusUpdate, accountEmail]
      );
      
      // Attempt auto-recovery for certain types of errors
      if (statusUpdate !== 'auth-error') {
        // Schedule a retry after a delay
        setTimeout(async () => {
          try {
            console.log(`Attempting auto-recovery for ${accountEmail}...`);
            await pool.query(
              'UPDATE gmail_accounts SET status = \'active\', updated_at = NOW() WHERE email = ?',
              [accountEmail]
            );
            
            // Restart polling for this account
            if (!activeImapAccounts.has(accountEmail)) {
              console.log(`Restarting polling for recovered account ${accountEmail}`);
              schedulePolling(accountEmail);
              activeImapAccounts.add(accountEmail);
            }
          } catch (retryError) {
            console.error(`Failed to auto-recover ${accountEmail}:`, retryError);
          }
        }, 15 * 60 * 1000); // Try to recover after 15 minutes
      } else {
        // Remove from active polling if it's an auth error
        activeImapAccounts.delete(accountEmail);
        console.log(`Removed ${accountEmail} from active polling due to auth error`);
      }
    } catch (dbError) {
      console.error('Error updating account status:', dbError);
    }
  } finally {
    // Close the connection if it's open
    if (client && client.usable) {
      try {
        await client.logout();
      } catch (logoutError) {
        console.error(`Error logging out IMAP client for ${accountEmail}:`, logoutError);
      }
    }
  }
}

function schedulePolling(accountEmail) {
  console.log(`Setting up polling schedule for ${accountEmail}`);
  
  // Check if account is active (in a self-executing async function)
  (async () => {
    try {
      // Get latest account state from database to ensure we have the most current info
      const [accounts] = await pool.query(
        'SELECT * FROM gmail_accounts WHERE email = ?',
        [accountEmail]
      );
      
      if (accounts.length === 0) {
        console.log(`Not scheduling polling for missing account: ${accountEmail}`);
        activeImapAccounts.delete(accountEmail); // Ensure it's removed from active set
        return;
      }
      
      const accountStatus = accounts[0].status;
      if (accountStatus !== 'active') {
        console.log(`Not scheduling polling for inactive account (${accountStatus}): ${accountEmail}`);
        activeImapAccounts.delete(accountEmail); // Ensure it's removed from active set
        return;
      }
      
      console.log(`Scheduling polling for ${accountEmail}`);
      
      // Determine polling interval based on activity
      let interval = POLLING_INTERVALS.medium; // Default to medium priority
      
      if (accounts[0].alias_count > 10) {
        interval = POLLING_INTERVALS.high;
      } else if (accounts[0].alias_count > 5) {
        interval = POLLING_INTERVALS.medium;
      } else {
        interval = POLLING_INTERVALS.low;
      }
      
      console.log(`Using polling interval of ${interval}ms for ${accountEmail}`);
      
      // Only add to active set if it's not already being polled
      if (!activeImapAccounts.has(accountEmail)) {
        activeImapAccounts.add(accountEmail);
        console.log(`Added ${accountEmail} to active polling accounts`);
      }
      
      // Start with an immediate poll, then schedule recurring
      pollForNewEmails(accountEmail).catch(error => 
        console.error(`Initial poll for ${accountEmail} failed:`, error)
      );
      
      // Schedule next poll
      setTimeout(() => {
        // Only schedule next poll if account is still in active set and polling should continue
        if (activeImapAccounts.has(accountEmail)) {
          schedulePolling(accountEmail);
        } else {
          console.log(`Stopped polling for ${accountEmail} as it's no longer in active set`);
        }
      }, interval);
      
    } catch (error) {
      console.error(`Error setting up polling for ${accountEmail}:`, error);
      // Don't remove from active polling on setup error - it may be temporary
    }
  })();
}

// Process IMAP message into standardized format
function processImapMessage(message, recipientAlias) {
  // Extract headers and body from the message source
  const source = message.source.toString();
  
  // Extract basic info from envelope
  const from = message.envelope.from?.[0]?.address || '';
  const fromName = message.envelope.from?.[0]?.name || '';
  const subject = message.envelope.subject || '(No Subject)';
  
  // Extract body parts
  let bodyHtml = '';
  let bodyText = '';
  
  // Simple parsing of multipart messages
  // In a real implementation, you'd use a proper email parser like mailparser
  const boundaryMatch = source.match(/boundary="([^"]+)"/);
  if (boundaryMatch) {
    const boundary = boundaryMatch[1];
    const parts = source.split(`--${boundary}`);
    
    for (const part of parts) {
      if (part.includes('Content-Type: text/html')) {
        const bodyMatch = part.match(/\r\n\r\n([\s\S]*?)(\r\n--|\r\n$)/);
        if (bodyMatch) {
          bodyHtml = bodyMatch[1];
        }
      } else if (part.includes('Content-Type: text/plain')) {
        const bodyMatch = part.match(/\r\n\r\n([\s\S]*?)(\r\n--|\r\n$)/);
        if (bodyMatch) {
          bodyText = bodyMatch[1];
        }
      }
    }
  } else {
    // Simple non-multipart message
    const bodyMatch = source.match(/\r\n\r\n([\s\S]*?)$/);
    if (bodyMatch) {
      bodyText = bodyMatch[1];
    }
  }
  
  // Extract attachments (simplified)
  const attachments = [];
  
  // Format the processed email
  return {
    id: message.uid,
    threadId: message.uid, // IMAP doesn't have thread IDs, so we use UID
    from,
    fromName,
    to: recipientAlias,
    subject,
    bodyHtml,
    bodyText,
    internalDate: message.envelope.date ? new Date(message.envelope.date).toISOString() : new Date().toISOString(),
    timestamp: Date.now(),
    snippet: bodyText.substring(0, 100),
    recipientAlias,
    attachments
  };
}

// Cache Management with improved efficiency
function addToEmailCache(key, email) {
  // If cache is at capacity, remove oldest entries
  if (emailCache.size >= MAX_CACHE_SIZE) {
    const oldestKeys = [...emailCache.keys()]
      .map(k => ({ key: k, timestamp: emailCache.get(k).timestamp }))
      .sort((a, b) => a.timestamp - b.timestamp)
      .slice(0, Math.ceil(MAX_CACHE_SIZE * 0.2)) // Remove oldest 20%
      .map(item => item.key);
    
    oldestKeys.forEach(key => emailCache.delete(key));
  }
  
  // Add new email to cache
  emailCache.set(key, {
    ...email,
    timestamp: Date.now()
  });
}

// Cleanup and maintenance
export async function cleanupInactiveAliases() {
  console.log('Running in-memory alias cleanup...');
  
  // Clean up in-memory cache
  const now = Date.now();
  let inMemoryCleanupCount = 0;
  
  for (const [alias, data] of aliasCache.entries()) {
    if (now - data.lastAccessed > ALIAS_TTL) {
      // Also keep track of account aliases to update count in DB
      if (data.parentAccountId) {
        try {
          // Decrement alias count in the database
          await pool.query(
            'UPDATE gmail_accounts SET alias_count = GREATEST(0, alias_count - 1), updated_at = NOW() WHERE id = ?',
            [data.parentAccountId]
          );
        } catch (error) {
          console.error(`Error updating alias count for account ${data.parentAccountId}:`, error);
        }
      }
      
      aliasCache.delete(alias);
      inMemoryCleanupCount++;
    }
  }
  
  if (inMemoryCleanupCount > 0) {
    console.log(`Cleaned up ${inMemoryCleanupCount} inactive aliases from memory cache`);
  }
}

// Run alias cleanup every hour
setInterval(cleanupInactiveAliases, 60 * 60 * 1000);

// Function to check for Gmail accounts that need polling restart
export async function checkAndRestartPolling() {
  try {
    console.log("Running scheduled check for accounts needing polling restart...");
    
    // Get all active accounts that aren't currently being polled
    const [accounts] = await pool.query(`
      SELECT email FROM gmail_accounts 
      WHERE status = 'active' AND updated_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
    `);
    
    if (!accounts || accounts.length === 0) {
      console.log("No recently active accounts found that need polling restart");
      return;
    }
    
    // Start polling for any active accounts that aren't currently being polled
    let restartCount = 0;
    for (const account of accounts) {
      if (!activeImapAccounts.has(account.email)) {
        console.log(`Restarting polling for active account: ${account.email}`);
        schedulePolling(account.email);
        activeImapAccounts.add(account.email);
        restartCount++;
      }
    }
    
    console.log(`Restarted polling for ${restartCount} accounts`);
  } catch (error) {
    console.error("Error checking for accounts needing polling restart:", error);
  }
}

// Run the polling restart check every 15 minutes
setInterval(checkAndRestartPolling, 15 * 60 * 1000);

// Setup auto-recovery for non-auth-error accounts
setInterval(async () => {
  try {
    const [result] = await pool.query(`
      UPDATE gmail_accounts 
      SET status = 'active', updated_at = NOW() 
      WHERE status NOT IN ('active', 'auth-error') 
      AND updated_at < DATE_SUB(NOW(), INTERVAL 30 MINUTE)
    `);
    
    if (result.affectedRows > 0) {
      console.log(`Auto-recovered ${result.affectedRows} Gmail accounts`);
      
      // Get the list of accounts that were auto-recovered so we can restart polling for them
      const [recoveredAccounts] = await pool.query(`
        SELECT email FROM gmail_accounts 
        WHERE status = 'active'
        AND updated_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)
      `);
      
      // Restart polling for recovered accounts
      for (const account of recoveredAccounts) {
        if (!activeImapAccounts.has(account.email)) {
          console.log(`Restarting polling for auto-recovered account: ${account.email}`);
          schedulePolling(account.email);
          activeImapAccounts.add(account.email);
        }
      }
    }
  } catch (error) {
    console.error('Error in auto-recovery process:', error);
  }
}, 15 * 60 * 1000); // Run every 15 minutes

// Load Balancing with improved account selection
async function getNextAvailableAccount() {
  try {
    // Get available accounts with balancing strategy
    const [accounts] = await pool.query(`
      SELECT * 
      FROM gmail_accounts a
      WHERE a.status = 'active' OR (a.status = 'rate-limited' AND a.updated_at < DATE_SUB(NOW(), INTERVAL 30 MINUTE))
      ORDER BY 
        CASE WHEN a.status = 'active' THEN 0 ELSE 1 END,  -- Active accounts first
        a.alias_count ASC,                                -- Accounts with fewer aliases
        a.quota_used ASC,                                 -- Accounts with less quota usage
        a.last_used ASC                                   -- Least recently used accounts
      LIMIT 1
    `);
    
    if (accounts.length === 0) {
      console.error('No available Gmail accounts');
      
      // Attempt to auto-recover accounts that haven't been updated in a while
      const [recoveryResult] = await pool.query(`
        UPDATE gmail_accounts 
        SET status = 'active', updated_at = NOW() 
        WHERE status != 'auth-error' 
        AND updated_at < DATE_SUB(NOW(), INTERVAL 1 HOUR)
        LIMIT 3
      `);
      
      if (recoveryResult.affectedRows > 0) {
        console.log(`Auto-recovered ${recoveryResult.affectedRows} Gmail accounts`);
        
        // Try again after recovery
        const [recoveredAccounts] = await pool.query(`
          SELECT * FROM gmail_accounts
          WHERE status = 'active'
          ORDER BY alias_count ASC, quota_used ASC, last_used ASC
          LIMIT 1
        `);
        
        if (recoveredAccounts.length > 0) {
          return recoveredAccounts[0];
        }
      }
      
      return null;
    }

    const selectedAccount = accounts[0];
    
    // Auto-recover rate-limited accounts after a cool-down period
    if (selectedAccount.status !== 'active') {
      await pool.query(
        'UPDATE gmail_accounts SET status = \'active\', updated_at = NOW() WHERE id = ?',
        [selectedAccount.id]
      );
    }
    
    console.log(`Selected account for new alias: ${selectedAccount.email} (aliases: ${selectedAccount.alias_count}, quota: ${selectedAccount.quota_used})`);
    
    return selectedAccount;
  } catch (error) {
    console.error('Error selecting next available account:', error);
    return null;
  }
}

// Function to force check and update all accounts
export async function forceCheckAllAccounts() {
  console.log("Performing forced check of all Gmail accounts...");
  
  try {
    // Get all accounts from the database
    const [allAccounts] = await pool.query(`SELECT * FROM gmail_accounts`);
    
    console.log(`Found ${allAccounts.length} Gmail accounts to check`);
    
    for (const account of allAccounts) {
      const accountEmail = account.email;
      
      // If account is active but not being polled, start polling
      if (account.status === 'active' && !activeImapAccounts.has(accountEmail)) {
        console.log(`Starting polling for active account ${accountEmail} that wasn't being polled`);
        schedulePolling(accountEmail);
        activeImapAccounts.add(accountEmail);
      }
      // If account is inactive but being polled, stop polling
      else if (account.status !== 'active' && activeImapAccounts.has(accountEmail)) {
        console.log(`Removing inactive account ${accountEmail} from polling`);
        activeImapAccounts.delete(accountEmail);
      }
    }
    
    // Log account status
    console.log(`After check: ${activeImapAccounts.size} accounts actively polling`);
    return {
      totalAccounts: allAccounts.length,
      activelyPolling: activeImapAccounts.size,
      pollingAccounts: Array.from(activeImapAccounts)
    };
  } catch (error) {
    console.error("Error performing forced account check:", error);
    throw error;
  }
}

// Check all accounts every 30 minutes to catch any polling issues
setInterval(forceCheckAllAccounts, 30 * 60 * 1000);

// Admin functions
export async function getGmailAccountStats() {
  try {
    // Get overall stats
    const [accountsCount] = await pool.query(
      'SELECT COUNT(*) as count FROM gmail_accounts'
    );
    
    // Count aliases from in-memory cache
    const aliasCount = aliasCache.size;
    
    // Count unique users from in-memory cache
    const userIds = new Set();
    for (const data of aliasCache.values()) {
      if (data.userId) {
        userIds.add(data.userId);
      }
    }
    
    // Get account details
    const [accounts] = await pool.query(`
      SELECT id, email, status, quota_used, alias_count, last_used, updated_at
      FROM gmail_accounts
      ORDER BY last_used DESC
    `);
    
    return {
      totalAccounts: accountsCount[0].count,
      totalAliases: aliasCount,
      totalUsers: userIds.size,
      active: accounts.filter(a => a.status === 'active').length,
      auth_error: accounts.filter(a => a.status === 'auth-error').length,
      rate_limited: accounts.filter(a => a.status === 'rate-limited').length,
      accounts: accounts.map(account => ({
        id: account.id,
        email: account.email,
        status: account.status,
        aliasCount: account.alias_count,
        quotaUsed: account.quota_used,
        lastUsed: account.last_used
      }))
    };
  } catch (error) {
    console.error('Failed to get Gmail account stats:', error);
    return {
      totalAccounts: 0,
      totalAliases: 0,
      totalUsers: 0,
      accounts: []
    };
  }
}

export function getEmailCacheStats() {
  return {
    size: emailCache.size,
    maxSize: MAX_CACHE_SIZE
  };
}

// Export for testing and monitoring
export const stores = {
  emailCache,
  aliasCache
};

// Initialize the service by loading accounts from the database
export async function initializeImapService() {
  try {
    console.log('Initializing IMAP service...');
    
    // Get all active accounts from the database
    const [accounts] = await pool.query(`
      SELECT * FROM gmail_accounts WHERE status = 'active'
    `);
    
    console.log(`Found ${accounts.length} active Gmail accounts`);
    
    // Start polling for each active account
    for (const account of accounts) {
      if (!activeImapAccounts.has(account.email)) {
        console.log(`Starting polling for account: ${account.email}`);
        schedulePolling(account.email);
        activeImapAccounts.add(account.email);
      }
    }
    
    console.log('IMAP service initialized successfully');
  } catch (error) {
    console.error('Failed to initialize IMAP service:', error);
  }
}
