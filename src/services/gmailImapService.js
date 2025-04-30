import { ImapFlow } from 'imapflow';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import WebSocket from 'ws';
import http from 'http';
import { simpleParser } from 'mailparser';
import { pool } from '../db/init.js';
import imapConnectionPool from './imapConnectionPool.js';

// In-memory storage
const emailCache = new Map(); // Cache for fetched emails
const aliasCache = new Map(); // Cache for active aliases during runtime
const activePollingJobs = new Map(); // Track polling jobs by account email

// Track WebSocket clients
const wsClients = new Map(); // Maps userId + alias to websocket client

// Configuration
const MAX_CACHE_SIZE = 10000; // Maximum number of emails to cache
const ALIAS_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds for in-memory cache
const POLLING_INTERVALS = {
  high: 10000,     // 10 seconds for high priority accounts (many aliases)
  medium: 20000,   // 20 seconds for medium priority
  low: 30000       // 30 seconds for low priority accounts
};

// Encryption utilities for app passwords
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

/**
 * Set up WebSocket server for real-time email updates
 */
export function setupWebSocketServer(server) {
  const wss = new WebSocket.Server({ server });
  
  wss.on('connection', (ws, req) => {
    // Parse query parameters
    const url = new URL(req.url, 'http://localhost');
    const userId = url.searchParams.get('userId');
    const alias = url.searchParams.get('alias');
    
    if (!userId || !alias) {
      console.error('WebSocket connection attempt without required parameters');
      ws.close(1003, 'Missing required parameters');
      return;
    }
    
    const clientKey = `${userId}:${alias}`;
    console.log(`WebSocket connection established for ${clientKey}`);
    
    // Store the client connection
    wsClients.set(clientKey, ws);
    
    // Handle ping messages to keep connection alive
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        if (data.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        }
      } catch (error) {
        console.error('Error processing WebSocket message:', error);
      }
    });
    
    // Handle connection close
    ws.on('close', () => {
      console.log(`WebSocket connection closed for ${clientKey}`);
      wsClients.delete(clientKey);
    });
    
    // Send initial connection confirmation
    ws.send(JSON.stringify({ 
      type: 'connected', 
      message: 'WebSocket connection established', 
      timestamp: Date.now() 
    }));
  });
  
  console.log('WebSocket server initialized');
  return wss;
}

/**
 * Send email notification to connected WebSocket clients
 * @param {string} userId - User ID
 * @param {string} alias - Email alias
 * @param {Object} email - Email object
 */
function notifyClientOfNewEmail(userId, alias, email) {
  const clientKey = `${userId}:${alias}`;
  const ws = wsClients.get(clientKey);
  
  if (ws && ws.readyState === WebSocket.OPEN) {
    console.log(`Sending email notification to WebSocket client for ${clientKey}`);
    ws.send(JSON.stringify({
      type: 'new_email',
      email,
      timestamp: Date.now()
    }));
  }
}

/**
 * Initialize the IMAP service
 */
export async function initializeImapService() {
  try {
    console.log('Initializing IMAP service...');
    
    // Get all active Gmail accounts
    const [accounts] = await pool.query(
      'SELECT * FROM gmail_accounts WHERE status = ?',
      ['active']
    );
    
    console.log(`Found ${accounts.length} active Gmail accounts`);
    
    // Start polling for each account
    for (const account of accounts) {
      await startPolling(account);
    }
    
    // Set up cleanup on process exit
    process.on('exit', cleanup);
    process.on('SIGINT', () => {
      cleanup();
      process.exit(0);
    });
    
    return true;
  } catch (error) {
    console.error('Failed to initialize IMAP service:', error);
    throw error;
  }
}

/**
 * Clean up all resources
 */
async function cleanup() {
  console.log('Cleaning up IMAP service resources...');
  
  // Stop all polling jobs
  for (const [email, intervalId] of activePollingJobs.entries()) {
    console.log(`Stopping polling job for ${email}`);
    clearInterval(intervalId);
  }
  
  // Clear all caches
  emailCache.clear();
  aliasCache.clear();
  
  try {
    // Set all accounts to inactive
    await pool.query('UPDATE gmail_accounts SET status = ? WHERE status = ?', ['inactive', 'active']);
  } catch (error) {
    console.error('Error updating account status during cleanup:', error);
  }
}

/**
 * Add a new Gmail account
 * @param {string} email - Gmail account email
 * @param {string} appPassword - Gmail app password
 * @returns {Promise<Object>} Account details
 */
export async function addGmailAccount(email, appPassword) {
  try {
    console.log(`Adding new Gmail account: ${email}`);
    
    // Verify the credentials by connecting to IMAP
    const client = await imapConnectionPool.getConnection(email, appPassword);
    
    // Test by getting mailboxes
    await client.list();
    console.log(`Successfully connected to IMAP and verified credentials for ${email}`);
    
    // Release the connection back to pool
    imapConnectionPool.releaseConnection(email);
    
    // Store the account in the database with encrypted app password
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      
      // Check if account already exists
      const [existingAccounts] = await connection.query(
        'SELECT * FROM gmail_accounts WHERE email = ?',
        [email]
      );
      
      const id = existingAccounts.length > 0 ? existingAccounts[0].id : uuidv4();
      const encryptedPassword = encrypt(appPassword);
      
      if (existingAccounts.length > 0) {
        // Update existing account
        await connection.query(
          `UPDATE gmail_accounts SET 
           app_password = ?,
           status = 'active',
           last_used = NOW(),
           updated_at = NOW()
           WHERE id = ?`,
          [encryptedPassword, id]
        );
        console.log(`Updated existing Gmail account: ${email}`);
      } else {
        // Insert new account
        await connection.query(
          `INSERT INTO gmail_accounts (
            id, email, app_password, quota_used, alias_count, status, last_used
          ) VALUES (?, ?, ?, 0, 0, 'active', NOW())`,
          [id, email, encryptedPassword]
        );
        console.log(`Added new Gmail account: ${email}`);
      }
      
      await connection.commit();
      
      // Start polling for the account
      const account = { id, email, app_password: encryptedPassword };
      await startPolling(account);
      
      return { email, id, status: 'active' };
      
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
    
  } catch (error) {
    console.error(`Failed to add Gmail account ${email}:`, error);
    throw new Error(`Failed to add Gmail account: ${error.message}`);
  }
}

/**
 * Generate a Gmail alias
 * @param {string} userId - User ID
 * @param {string} strategy - Alias strategy ('dot' or 'plus')
 * @param {string} domain - Domain ('gmail.com' or 'googlemail.com')
 * @returns {Promise<Object>} The generated alias
 */
export async function generateGmailAlias(userId, strategy = 'dot', domain = 'gmail.com') {
  try {
    // Get next available account using load balancing
    const account = await getNextAvailableAccount();
    
    if (!account) {
      console.error('No Gmail accounts available.');
      throw new Error('No Gmail accounts available');
    }
    
    console.log(`Generating ${strategy} alias using account: ${account.email}`);
    
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

/**
 * Generate a dot-notation alias
 * @param {string} email - The Gmail account email
 * @param {string} domain - The domain to use
 * @returns {string} The generated alias
 */
function generateDotAlias(email, domain = 'gmail.com') {
  // Extract username from email
  const [username] = email.split('@');
  
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
  
  return `${dotUsername}@${domain}`;
}

/**
 * Generate a plus-notation alias
 * @param {string} email - The Gmail account email
 * @param {string} domain - The domain to use
 * @returns {string} The generated alias
 */
function generatePlusAlias(email, domain = 'gmail.com') {
  // Extract username from email
  const [username] = email.split('@');
  
  // Add random tag
  const tag = Math.random().toString(36).substring(2, 8);
  
  return `${username}+${tag}@${domain}`;
}

/**
 * Get the next available Gmail account using load balancing
 * @returns {Promise<Object>} The account to use
 */
async function getNextAvailableAccount() {
  try {
    // Get available accounts with balancing strategy
    const [accounts] = await pool.query(`
      SELECT * 
      FROM gmail_accounts a
      WHERE a.status = 'active'
      ORDER BY 
        a.alias_count ASC,     -- Accounts with fewer aliases
        a.quota_used ASC,      -- Accounts with less quota usage
        a.last_used ASC        -- Least recently used accounts
      LIMIT 1
    `);
    
    if (accounts.length === 0) {
      console.error('No available Gmail accounts');
      return null;
    }

    const selectedAccount = accounts[0];
    console.log(`Selected account for new alias: ${selectedAccount.email} (aliases: ${selectedAccount.alias_count}, quota: ${selectedAccount.quota_used})`);
    
    return selectedAccount;
  } catch (error) {
    console.error('Error selecting next available account:', error);
    return null;
  }
}

/**
 * Fetch emails for a Gmail alias
 * @param {string} userId - User ID
 * @param {string} aliasEmail - The alias email to fetch emails for
 * @returns {Promise<Array>} The emails for this alias
 */
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
      
      // For missing aliases, create a new one
      if (userId) {
        console.log(`User ${userId} requesting missing alias, will create new one`);
        const result = await generateGmailAlias(userId);
        return fetchGmailEmails(userId, result.alias); // Recursive call with new alias
      }
      
      throw new Error('Alias not found');
    }
    
    if (!parentAccount) {
      throw new Error('Parent account not found for alias');
    }
    
    // Check parent account status in the database
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
        
        // Restart polling if needed
        if (!activePollingJobs.has(parentAccount)) {
          console.log(`Restarting polling for reactivated account ${parentAccount}`);
          await startPolling(account);
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
    
    // If we have cached emails, trigger a background refresh
    if (cachedEmails.length > 0) {
      // Trigger background fetch to update cache
      backgroundFetchEmails(account, aliasEmail, userId).catch(error => {
        console.error(`Background fetch failed for ${aliasEmail}:`, error);
      });
    } else {
      // If no cached emails, do immediate fetch
      try {
        await fetchEmailsForAlias(account, aliasEmail, userId);
      } catch (error) {
        console.error(`Error fetching emails for ${aliasEmail}:`, error);
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

/**
 * Background fetch of emails to update cache
 * @param {Object} account - Gmail account
 * @param {string} aliasEmail - Email alias
 * @param {string} userId - User ID
 */
async function backgroundFetchEmails(account, aliasEmail, userId) {
  setTimeout(async () => {
    try {
      await fetchEmailsForAlias(account, aliasEmail, userId);
    } catch (error) {
      console.error(`Background fetch failed for ${aliasEmail}:`, error);
    }
  }, 0);
}

/**
 * Fetch emails for a specific alias
 * @param {Object} account - Gmail account
 * @param {string} aliasEmail - The alias to fetch emails for
 * @param {string} userId - User ID for notifications
 */
async function fetchEmailsForAlias(account, aliasEmail, userId) {
  let client = null;
  
  try {
    // Get the app password
    const appPassword = decrypt(account.app_password);
    
    // Get IMAP client from pool
    client = await imapConnectionPool.getConnection(account.email, appPassword);
    
    // Open inbox
    const mailbox = await client.mailboxOpen('INBOX');
    console.log(`Opened INBOX for ${account.email}, message count: ${mailbox.exists}`);
    
    // Search for emails to this alias
    // Using a date filter to limit the search to recent emails (last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    const query = {
      to: aliasEmail,
      since: sevenDaysAgo
    };
    
    console.log(`Searching INBOX for emails to ${aliasEmail}...`);
    const messages = await client.search(query);
    
    if (messages.length > 0) {
      console.log(`Found ${messages.length} messages for ${aliasEmail} in INBOX`);
      
      // Get the most recent 20 messages
      const recentMessages = messages.slice(-20);
      
      // Fetch messages in batches - get all at once if fewer than 20
      if (recentMessages.length <= 20) {
        await fetchMessageBatch(client, recentMessages, aliasEmail, userId, account);
      } else {
        // Fetch in batches of 10
        const batches = [];
        for (let i = 0; i < recentMessages.length; i += 10) {
          batches.push(recentMessages.slice(i, i + 10));
        }
        
        for (const batch of batches) {
          await fetchMessageBatch(client, batch, aliasEmail, userId, account);
        }
      }
    } else {
      console.log(`No messages found for ${aliasEmail}`);
    }
    
  } catch (error) {
    console.error(`Error fetching emails for alias ${aliasEmail}:`, error);
    throw error;
  } finally {
    // Always release the connection back to the pool
    if (client) {
      imapConnectionPool.releaseConnection(account.email);
    }
  }
}

/**
 * Fetch a batch of messages
 * @param {ImapFlow} client - IMAP client
 * @param {Array} messageIds - Array of message IDs
 * @param {string} aliasEmail - Email alias
 * @param {string} userId - User ID
 * @param {Object} account - Account info for updating quota
 */
async function fetchMessageBatch(client, messageIds, aliasEmail, userId, account) {
  if (messageIds.length === 0) return;
  
  const messages = await client.fetch(messageIds, { source: true, envelope: true });
  
  for (const message of messages) {
    try {
      // Parse the message source
      const parsed = await simpleParser(message.source);
      
      // Process message into standard format
      const processedEmail = {
        id: message.uid || message.id,
        from: parsed.from?.text || '',
        to: parsed.to?.text || '',
        subject: parsed.subject || '(No Subject)',
        bodyHtml: parsed.html || '',
        bodyText: parsed.text || '',
        internalDate: parsed.date?.toISOString() || new Date().toISOString(),
        timestamp: Date.now(),
        snippet: parsed.text?.substring(0, 100) || '',
        recipientAlias: aliasEmail,
        attachments: parsed.attachments || []
      };
      
      // Add to cache
      const cacheKey = `${aliasEmail}:${processedEmail.id}`;
      addToEmailCache(cacheKey, processedEmail);
      
      // Notify connected WebSocket clients about the new email
      notifyClientOfNewEmail(userId, aliasEmail, processedEmail);
      
    } catch (error) {
      console.error(`Error processing message for ${aliasEmail}:`, error);
    }
  }
  
  // Update account quota after fetching
  try {
    await pool.query(
      'UPDATE gmail_accounts SET quota_used = quota_used + 1, last_used = NOW(), updated_at = NOW() WHERE id = ?',
      [account.id]
    );
  } catch (error) {
    console.error(`Error updating quota for account ${account.email}:`, error);
  }
}

/**
 * Add email to cache with LRU policy
 * @param {string} key - Cache key
 * @param {Object} email - Email to cache
 */
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

/**
 * Start polling for a Gmail account
 * @param {Object} account - The Gmail account
 */
async function startPolling(account) {
  // Skip if already polling
  if (activePollingJobs.has(account.email)) {
    console.log(`IMAP polling already active for ${account.email}`);
    return;
  }
  
  console.log(`Starting IMAP polling for ${account.email}`);
  
  // Determine polling interval based on alias count
  let interval = POLLING_INTERVALS.medium;
  
  if (account.alias_count > 10) {
    interval = POLLING_INTERVALS.high;
  } else if (account.alias_count > 5) {
    interval = POLLING_INTERVALS.medium;
  } else {
    interval = POLLING_INTERVALS.low;
  }
  
  console.log(`Using polling interval of ${interval}ms for ${account.email}`);
  
  // Initial poll immediately
  await pollAccountEmails(account);
  
  // Set up recurring polling
  const intervalId = setInterval(() => pollAccountEmails(account), interval);
  activePollingJobs.set(account.email, intervalId);
}

/**
 * Poll for new emails for a Gmail account
 * @param {Object} account - The Gmail account to poll
 */
async function pollAccountEmails(account) {
  // Get all aliases for this account
  const accountAliases = [];
  for (const [alias, data] of aliasCache.entries()) {
    if (data.parentAccount === account.email) {
      accountAliases.push({
        alias,
        userId: data.userId
      });
    }
  }
  
  // Skip if no aliases for this account
  if (accountAliases.length === 0) {
    // console.log(`Skipping polling for ${account.email}: no aliases in memory cache`);
    return;
  }
  
  console.log(`Polling for emails for ${account.email} with ${accountAliases.length} aliases...`);
  
  let client = null;
  try {
    // Get app password
    const appPassword = decrypt(account.app_password);
    
    // Get IMAP client from pool
    client = await imapConnectionPool.getConnection(account.email, appPassword);
    
    // Poll for each alias
    for (const { alias, userId } of accountAliases) {
      try {
        await fetchEmailsForAlias(account, alias, userId);
      } catch (error) {
        console.error(`Error polling for alias ${alias}:`, error);
      }
    }
    
    // Update account status in database
    await pool.query(
      'UPDATE gmail_accounts SET status = \'active\', last_used = NOW(), updated_at = NOW() WHERE id = ?',
      [account.id]
    );
    
  } catch (error) {
    console.error(`Error polling Gmail account ${account.email}:`, error);
    
    // Update account status if there's a persistent error
    let errorStatus = 'error';
    
    // Try to detect authentication errors
    if (error.message?.includes('invalid credentials') || 
        error.message?.includes('authentication failed')) {
      errorStatus = 'auth-error';
      
      // Stop polling for auth errors
      if (activePollingJobs.has(account.email)) {
        clearInterval(activePollingJobs.get(account.email));
        activePollingJobs.delete(account.email);
      }
    }
    
    try {
      await pool.query(
        'UPDATE gmail_accounts SET status = ?, updated_at = NOW() WHERE id = ?',
        [errorStatus, account.id]
      );
    } catch (dbError) {
      console.error('Error updating account status:', dbError);
    }
  } finally {
    // Always release the connection back to the pool
    if (client) {
      imapConnectionPool.releaseConnection(account.email);
    }
  }
}

/**
 * Get all aliases for a user
 * @param {string} userId - User ID
 * @returns {Promise<Array>} The user's aliases
 */
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

/**
 * Rotate to a new alias for a user
 * @param {string} userId - User ID
 * @param {string} strategy - Alias strategy ('dot' or 'plus')
 * @param {string} domain - Domain ('gmail.com' or 'googlemail.com')
 * @returns {Promise<Object>} The new alias
 */
export async function rotateUserAlias(userId, strategy = 'dot', domain = 'gmail.com') {
  try {
    // Generate a new alias for the user (will use load balancing)
    return await generateGmailAlias(userId, strategy, domain);
  } catch (error) {
    console.error('Failed to rotate Gmail alias:', error);
    throw error;
  }
}

/**
 * Clean up inactive aliases
 */
export async function cleanupInactiveAliases() {
  console.log('Running in-memory alias cleanup...');
  
  // Clean up in-memory cache
  const now = Date.now();
  let inMemoryCleanupCount = 0;
  
  for (const [alias, data] of aliasCache.entries()) {
    if (now - data.lastAccessed > ALIAS_TTL) {
      // Update alias count in DB
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

/**
 * Get Gmail account statistics
 * @returns {Promise<Object>} Statistics about Gmail accounts
 */
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

/**
 * Get email cache statistics
 * @returns {Object} Cache statistics
 */
export function getEmailCacheStats() {
  return {
    size: emailCache.size,
    maxSize: MAX_CACHE_SIZE,
    aliasCount: aliasCache.size,
    activePollingCount: activePollingJobs.size,
    websocketClientCount: wsClients.size
  };
}

// Clean up inactive aliases every hour
setInterval(cleanupInactiveAliases, 60 * 60 * 1000);
