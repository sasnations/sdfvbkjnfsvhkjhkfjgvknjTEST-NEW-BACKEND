import { ImapFlow } from 'imapflow';
import { v4 as uuidv4 } from 'uuid';
import { pool } from '../db/init.js';
import crypto from 'crypto';
import WebSocket from 'ws';
import http from 'http';

// In-memory storage
const emailCache = new Map(); // Cache for fetched emails
const aliasCache = new Map(); // Cache for active aliases during runtime
const activeImapClients = new Map(); // Track active IMAP clients
const imapClientLocks = new Map(); // Track which clients are being used
const webSocketClients = new Map(); // Track WebSocket clients by alias
const userAliasMap = new Map(); // Map users to their aliases

// Configuration
const MAX_CACHE_SIZE = 10000; // Maximum number of emails to cache
const ALIAS_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds for in-memory cache
const IMAP_CONNECTION_TTL = 10 * 60 * 1000; // 10 minutes in milliseconds
const IMAP_RECONNECT_DELAY = 5000; // 5 seconds delay before reconnecting
const MAX_RECONNECT_ATTEMPTS = 5; // Maximum number of reconnection attempts

// Encryption utilities for app password security
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

// Initialize WebSocket server
export function setupWebSocketServer(server) {
  const wss = new WebSocket.Server({ server });
  
  wss.on('connection', (ws, req) => {
    // Parse URL parameters
    const url = new URL(req.url, 'http://localhost');
    const userId = url.searchParams.get('userId');
    const alias = url.searchParams.get('alias');
    
    if (!userId || !alias) {
      ws.close(1008, 'Missing userId or alias parameter');
      return;
    }
    
    console.log(`WebSocket connection established for user ${userId}, alias ${alias}`);
    
    // Store the WebSocket connection
    if (!webSocketClients.has(alias)) {
      webSocketClients.set(alias, new Map());
    }
    const aliasClients = webSocketClients.get(alias);
    aliasClients.set(userId, ws);
    
    // Handle messages from client
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        
        // Handle ping messages
        if (data.type === 'ping') {
          ws.send(JSON.stringify({
            type: 'pong',
            timestamp: Date.now()
          }));
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    });
    
    // Handle connection close
    ws.on('close', () => {
      console.log(`WebSocket connection closed for user ${userId}, alias ${alias}`);
      
      // Remove the WebSocket connection
      if (webSocketClients.has(alias)) {
        const aliasClients = webSocketClients.get(alias);
        aliasClients.delete(userId);
        
        // Remove the alias entry if no clients are left
        if (aliasClients.size === 0) {
          webSocketClients.delete(alias);
        }
      }
    });
    
    // Send initial connection confirmation
    ws.send(JSON.stringify({
      type: 'connected',
      timestamp: Date.now(),
      alias
    }));
  });
  
  console.log('WebSocket server initialized');
}

// Notify WebSocket clients about new emails
function notifyWebSocketClients(alias, email) {
  if (webSocketClients.has(alias)) {
    const aliasClients = webSocketClients.get(alias);
    
    aliasClients.forEach((ws, userId) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: 'new_email',
          timestamp: Date.now(),
          email
        }));
      }
    });
  }
}

// Create or get IMAP client with connection pooling
async function getImapClient(accountEmail, appPassword) {
  // Check if there's an active client for this account
  if (activeImapClients.has(accountEmail)) {
    const clientInfo = activeImapClients.get(accountEmail);
    
    // Check if the client is locked (being used by another operation)
    if (imapClientLocks.get(accountEmail)) {
      console.log(`IMAP client for ${accountEmail} is locked, waiting...`);
      // Wait for the lock to be released
      await new Promise(resolve => setTimeout(resolve, 1000));
      return getImapClient(accountEmail, appPassword);
    }
    
    // Check if the client is still connected and not expired
    if (clientInfo.client && 
        clientInfo.client.usable && 
        Date.now() - clientInfo.lastUsed < IMAP_CONNECTION_TTL) {
      
      // Update last used timestamp
      clientInfo.lastUsed = Date.now();
      activeImapClients.set(accountEmail, clientInfo);
      
      console.log(`Reusing existing IMAP client for ${accountEmail}`);
      return clientInfo.client;
    }
    
    // Close the expired client
    try {
      await clientInfo.client.logout();
    } catch (error) {
      console.error(`Error closing expired IMAP client for ${accountEmail}:`, error);
    }
  }
  
  // Create a new client
  console.log(`Creating new IMAP client for ${accountEmail}`);
  
  // Set lock while creating the client
  imapClientLocks.set(accountEmail, true);
  
  try {
    const client = new ImapFlow({
      host: 'imap.gmail.com',
      port: 993,
      secure: true,
      auth: {
        user: accountEmail,
        pass: appPassword
      },
      logger: false,
      emitLogs: false,
      timeoutConnection: 10000 // 10 seconds connection timeout
    });
    
    // Connect to the server
    await client.connect();
    
    // Store the client in the cache
    activeImapClients.set(accountEmail, {
      client,
      lastUsed: Date.now()
    });
    
    console.log(`IMAP client connected for ${accountEmail}`);
    return client;
  } catch (error) {
    console.error(`Error connecting IMAP client for ${accountEmail}:`, error);
    throw error;
  } finally {
    // Release the lock
    imapClientLocks.set(accountEmail, false);
  }
}

// Close idle IMAP connections periodically
setInterval(async () => {
  const now = Date.now();
  
  for (const [accountEmail, clientInfo] of activeImapClients.entries()) {
    // Skip if the client is locked
    if (imapClientLocks.get(accountEmail)) {
      continue;
    }
    
    // Close connections that haven't been used for the TTL period
    if (now - clientInfo.lastUsed > IMAP_CONNECTION_TTL) {
      try {
        console.log(`Closing idle IMAP connection for ${accountEmail}`);
        await clientInfo.client.logout();
        activeImapClients.delete(accountEmail);
      } catch (error) {
        console.error(`Error closing idle IMAP connection for ${accountEmail}:`, error);
        // Remove from active clients even if logout fails
        activeImapClients.delete(accountEmail);
      }
    }
  }
}, 60000); // Check every minute

// Gmail Account Management
export async function addGmailAccount(email, appPassword) {
  try {
    console.log(`Adding Gmail account: ${email}`);
    
    // Verify credentials by attempting to connect
    const client = new ImapFlow({
      host: 'imap.gmail.com',
      port: 993,
      secure: true,
      auth: {
        user: email,
        pass: appPassword
      },
      logger: false,
      emitLogs: false,
      timeoutConnection: 10000
    });
    
    try {
      await client.connect();
      console.log(`Successfully connected to ${email} with provided app password`);
      
      // Open the INBOX to verify permissions
      const mailbox = await client.mailboxOpen('INBOX');
      console.log(`Opened INBOX for ${email}, message count: ${mailbox.exists}`);
      
      // Close the connection
      await client.logout();
    } catch (error) {
      console.error(`Failed to verify credentials for ${email}:`, error);
      throw new Error(`Invalid credentials: ${error.message}`);
    }
    
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

// Alias Generation with improved reliability
export async function generateGmailAlias(userId, strategy = 'dot', domain = 'gmail.com') {
  // Get next available account using load balancing from database
  try {
    const account = await getNextAvailableAccount();
    
    if (!account) {
      console.error('No Gmail accounts available');
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
      
      // Map user to alias
      if (userId) {
        if (!userAliasMap.has(userId)) {
          userAliasMap.set(userId, new Set());
        }
        userAliasMap.get(userId).add(alias);
      }
      
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

function generateDotAlias(email, domain) {
  // Extract username and domain parts
  const [username, originalDomain] = email.split('@');
  
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

function generatePlusAlias(email, domain) {
  // Extract username and original domain
  const [username, originalDomain] = email.split('@');
  
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
    
    // If we have cached emails, return them
    if (cachedEmails.length > 0) {
      console.log(`Found ${cachedEmails.length} cached emails for ${aliasEmail}`);
      
      // Also trigger a background fetch to update the cache
      backgroundFetchEmails(userId, aliasEmail, parentAccount, account.app_password)
        .catch(error => {
          console.error(`Background fetch failed for ${aliasEmail}:`, error);
        });
      
      // Return cached emails sorted by date (newest first)
      return cachedEmails.sort((a, b) => 
        new Date(b.internalDate) - new Date(a.internalDate)
      );
    }
    
    // If no cached emails, do a direct fetch
    console.log(`No cached emails found for ${aliasEmail}, fetching directly`);
    return await fetchEmailsFromImap(aliasEmail, parentAccount, account.app_password);
  
  } catch (error) {
    console.error(`Error fetching Gmail emails for ${aliasEmail}:`, error);
    throw error;
  }
}

// Background fetch to update cache without blocking the response
async function backgroundFetchEmails(userId, aliasEmail, parentAccount, encryptedPassword) {
  try {
    // Decrypt the app password
    const appPassword = decrypt(encryptedPassword);
    
    // Fetch emails from IMAP
    await fetchEmailsFromImap(aliasEmail, parentAccount, appPassword);
  } catch (error) {
    console.error(`Background fetch failed for ${aliasEmail}:`, error);
  }
}

// Fetch emails from IMAP server
async function fetchEmailsFromImap(aliasEmail, parentAccount, appPassword) {
  let client;
  let attempts = 0;
  
  while (attempts < MAX_RECONNECT_ATTEMPTS) {
    try {
      // Get or create IMAP client
      client = await getImapClient(parentAccount, appPassword);
      
      // Set lock while using the client
      imapClientLocks.set(parentAccount, true);
      
      // Open the INBOX
      const mailbox = await client.mailboxOpen('INBOX');
      console.log(`Opened INBOX for ${parentAccount}, message count: ${mailbox.exists}`);
      
      // Search for emails to this alias
      // Use a broader search to ensure we find all relevant emails
      // This includes emails that might be in spam or other folders
      console.log(`Searching INBOX for emails to ${aliasEmail}...`);
      
      // Calculate a reasonable range to search (last 50 messages or all if less)
      const from = Math.max(1, mailbox.exists - 50);
      const to = mailbox.exists;
      
      // Only fetch if there are messages
      if (mailbox.exists > 0) {
        console.log(`Fetching messages ${from}:${to} from INBOX for ${parentAccount}`);
        
        // Search for messages to this alias
        const messages = await client.search({
          to: aliasEmail
        }, { uid: true });
        
        console.log(`Found ${messages.length} messages for ${aliasEmail} in INBOX`);
        
        // Fetch message details
        const fetchedEmails = [];
        
        for (const msg of messages) {
          // Check if already in cache
          const cacheKey = `${aliasEmail}:${msg}`;
          
          if (!emailCache.has(cacheKey)) {
            try {
              // Fetch the message
              const fetchedMsg = await client.fetchOne(msg, {
                source: true,
                envelope: true,
                bodyStructure: true
              });
              
              if (fetchedMsg) {
                // Process the message
                const email = processImapMessage(fetchedMsg, aliasEmail);
                
                // Add to cache
                addToEmailCache(cacheKey, email);
                
                // Add to results
                fetchedEmails.push(email);
                
                // Notify WebSocket clients
                notifyWebSocketClients(aliasEmail, email);
              }
            } catch (fetchError) {
              console.error(`Error fetching message ${msg} for ${aliasEmail}:`, fetchError);
            }
          } else {
            // Add cached email to results
            fetchedEmails.push(emailCache.get(cacheKey));
          }
        }
        
        // Release the lock
        imapClientLocks.set(parentAccount, false);
        
        // Return fetched emails sorted by date (newest first)
        return fetchedEmails.sort((a, b) => 
          new Date(b.internalDate) - new Date(a.internalDate)
        );
      } else {
        // No messages in mailbox
        console.log(`No messages in INBOX for ${parentAccount}`);
        
        // Release the lock
        imapClientLocks.set(parentAccount, false);
        
        return [];
      }
    } catch (error) {
      // Release the lock
      imapClientLocks.set(parentAccount, false);
      
      console.error(`IMAP client creation error for ${parentAccount} (attempt ${attempts + 1}). Retry in ${IMAP_RECONNECT_DELAY / 1000} seconds:`, error);
      
      // Remove the client from active clients
      activeImapClients.delete(parentAccount);
      
      // Increment attempts
      attempts++;
      
      // Wait before retrying
      if (attempts < MAX_RECONNECT_ATTEMPTS) {
        console.log(`Will retry IMAP connection for ${parentAccount} in ${IMAP_RECONNECT_DELAY / 1000} seconds`);
        await new Promise(resolve => setTimeout(resolve, IMAP_RECONNECT_DELAY));
      } else {
        throw new Error(`Failed to connect to IMAP server after ${MAX_RECONNECT_ATTEMPTS} attempts`);
      }
    }
  }
  
  // If we get here, all attempts failed
  throw new Error(`Failed to fetch emails after ${MAX_RECONNECT_ATTEMPTS} attempts`);
}

// Process IMAP message into standardized format
function processImapMessage(message, recipientAlias) {
  // Extract headers and content
  const from = message.envelope.from?.[0] ? 
    `${message.envelope.from[0].name || ''} <${message.envelope.from[0].address}>`.trim() : 
    'Unknown Sender';
  
  const subject = message.envelope.subject || '(No Subject)';
  const date = message.envelope.date || new Date();
  
  // Extract body content (simplified for now)
  let bodyHtml = '';
  let bodyText = '';
  
  // This is a simplified approach - in a real implementation,
  // you would parse the message source to extract HTML and text parts
  if (message.source) {
    // Very basic extraction - in production you'd use a proper email parser
    const source = message.source.toString();
    
    // Extract HTML content (very basic approach)
    const htmlMatch = source.match(/<html[\s\S]*?<\/html>/i);
    if (htmlMatch) {
      bodyHtml = htmlMatch[0];
    }
    
    // If no HTML, use the source as text
    if (!bodyHtml) {
      bodyText = source;
    }
  }
  
  // Format the processed email
  return {
    id: message.uid || uuidv4(),
    threadId: message.uid || uuidv4(),
    from: from,
    to: recipientAlias,
    subject: subject,
    bodyHtml: bodyHtml,
    bodyText: bodyText,
    internalDate: date.toISOString(),
    timestamp: Date.now(),
    snippet: bodyText.substring(0, 100) || 'No preview available',
    recipientAlias: recipientAlias,
    attachments: [] // Simplified - would extract attachments in production
  };
}

// Only return most recent one
export async function getUserAliases(userId) {
  if (!userId) return [];
  
  try {
    // Get only the most recent alias from memory cache for this user
    const userAliases = [];
    
    // Check if user has aliases in the user-alias map
    if (userAliasMap.has(userId)) {
      const aliases = Array.from(userAliasMap.get(userId));
      
      // Find the most recent alias
      let mostRecentAlias = null;
      let mostRecentTime = 0;
      
      for (const alias of aliases) {
        if (aliasCache.has(alias)) {
          const data = aliasCache.get(alias);
          if (data.created > mostRecentTime) {
            mostRecentAlias = alias;
            mostRecentTime = data.created;
          }
        }
      }
      
      if (mostRecentAlias) {
        userAliases.push(mostRecentAlias);
      }
    } else {
      // Fallback to scanning all aliases if user not in map
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
    }
    
    console.log(`User ${userId} has ${userAliases.length} recent alias in memory cache: ${userAliases[0] || 'none'}`);
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
      
      // Remove from user-alias map
      if (data.userId && userAliasMap.has(data.userId)) {
        userAliasMap.get(data.userId).delete(alias);
        
        // Remove user from map if they have no aliases left
        if (userAliasMap.get(data.userId).size === 0) {
          userAliasMap.delete(data.userId);
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

// Initialize IMAP service
export async function initializeImapService() {
  try {
    console.log('Initializing IMAP service...');
    
    // Get all active Gmail accounts
    const [accounts] = await pool.query(`
      SELECT * FROM gmail_accounts
      WHERE status = 'active'
    `);
    
    console.log(`Found ${accounts.length} active Gmail accounts`);
    
    // Initialize IMAP clients for each account
    for (const account of accounts) {
      try {
        // Decrypt the app password
        const appPassword = decrypt(account.app_password);
        
        // Test the connection
        const client = new ImapFlow({
          host: 'imap.gmail.com',
          port: 993,
          secure: true,
          auth: {
            user: account.email,
            pass: appPassword
          },
          logger: false,
          emitLogs: false,
          timeoutConnection: 10000
        });
        
        await client.connect();
        console.log(`Successfully connected to ${account.email}`);
        
        // Close the connection
        await client.logout();
        
        // Store the account info for later use
        activeImapClients.set(account.email, {
          client: null, // We'll create clients on demand
          lastUsed: Date.now()
        });
        
      } catch (error) {
        console.error(`Failed to initialize IMAP client for ${account.email}:`, error);
        
        // Update account status in database
        await pool.query(
          'UPDATE gmail_accounts SET status = ?, updated_at = NOW() WHERE id = ?',
          ['auth-error', account.id]
        );
      }
    }
    
    console.log('IMAP service initialized successfully');
  } catch (error) {
    console.error('Failed to initialize IMAP service:', error);
    throw error;
  }
}

// Export for testing and monitoring
export const stores = {
  emailCache,
  aliasCache,
  activeImapClients,
  webSocketClients,
  userAliasMap
};
