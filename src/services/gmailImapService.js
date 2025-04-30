import { ImapFlow } from 'imapflow';
import { v4 as uuidv4 } from 'uuid';
import { pool } from '../db/init.js';
import crypto from 'crypto';
import { WebSocketServer } from 'ws';

// In-memory storage
const emailCache = new Map(); // Cache for fetched emails
const aliasCache = new Map(); // Cache for active aliases during runtime
const activeImapAccounts = new Set(); // Track which accounts are being actively polled
const imapClients = new Map(); // Store active IMAP clients
const connectedClients = new Map(); // Map of userId:alias -> Set of websocket connections
const reconnectionAttempts = new Map(); // Track reconnection attempts for exponential backoff

// Configuration
const MAX_CACHE_SIZE = 10000; // Maximum number of emails to cache
const ALIAS_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds for in-memory cache
const MAX_RECONNECTION_ATTEMPTS = 10; // Maximum number of reconnection attempts
const BASE_RECONNECTION_DELAY = 5000; // Base delay for reconnection (5 seconds)
const MAX_RECONNECTION_DELAY = 30 * 60 * 1000; // Maximum delay (30 minutes)
const POLLING_INTERVALS = {
  high: 30000,     // 30 seconds for high priority accounts
  medium: 60000,   // 1 minute for medium priority
  low: 180000      // 3 minutes for low priority accounts
};
const CONNECTION_TIMEOUT = 60000; // 1 minute timeout for IMAP connections
const IDLE_TIMEOUT = 540000; // 9 minutes idle timeout (Gmail drops at ~10 min)

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

// Setup WebSocket Server
export function setupWebSocketServer(server) {
  const wss = new WebSocketServer({ 
    server,
    perMessageDeflate: {
      zlibDeflateOptions: {
        // See zlib defaults.
        chunkSize: 1024,
        memLevel: 7,
        level: 3
      },
      zlibInflateOptions: {
        chunkSize: 10 * 1024
      },
      // Below options specified as default values.
      clientNoContextTakeover: true, // Defaults to negotiated value.
      serverNoContextTakeover: true, // Defaults to negotiated value.
      clientMaxWindowBits: 10, // Defaults to negotiated value.
      serverMaxWindowBits: 10, // Defaults to negotiated value.
      // Below options specified as default values.
      concurrencyLimit: 10, // Limits zlib concurrency for perf.
      threshold: 1024 // Size (in bytes) below which messages should not be compressed.
    }
  });
  
  console.log('WebSocket server created for real-time email updates');
  
  wss.on('connection', (ws, req) => {
    // Extract userId and alias from URL parameters
    const url = new URL(req.url, `http://${req.headers.host}`);
    const userId = url.searchParams.get('userId');
    const alias = url.searchParams.get('alias');
    
    if (!userId || !alias) {
      console.log('WebSocket connection rejected: missing userId or alias');
      ws.close();
      return;
    }
    
    const clientKey = `${userId}:${alias}`;
    console.log(`WebSocket client connected: ${clientKey}`);
    
    // Add to connected clients
    if (!connectedClients.has(clientKey)) {
      connectedClients.set(clientKey, new Set());
    }
    connectedClients.get(clientKey).add(ws);
    
    // Send initial message
    ws.send(JSON.stringify({
      type: 'connected',
      message: 'Connected successfully to real-time email updates',
      timestamp: new Date().toISOString(),
      alias
    }));
    
    // Handle client disconnect
    ws.on('close', () => {
      console.log(`WebSocket client disconnected: ${clientKey}`);
      if (connectedClients.has(clientKey)) {
        connectedClients.get(clientKey).delete(ws);
        if (connectedClients.get(clientKey).size === 0) {
          connectedClients.delete(clientKey);
        }
      }
    });
    
    // Handle client messages
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message.toString());
        
        // Handle ping message to keep connection alive
        if (data.type === 'ping') {
          ws.send(JSON.stringify({
            type: 'pong',
            timestamp: new Date().toISOString()
          }));
        }
      } catch (err) {
        console.error('Invalid WebSocket message:', err);
      }
    });
    
    // Handle errors
    ws.on('error', (err) => {
      console.error(`WebSocket error for client ${clientKey}:`, err);
      try {
        ws.close();
      } catch (closeErr) {
        console.error(`Error closing WebSocket for ${clientKey}:`, closeErr);
      }
    });
  });
  
  // Handle server errors
  wss.on('error', (err) => {
    console.error('WebSocket server error:', err);
  });
  
  // Log websocket stats every 5 minutes
  setInterval(() => {
    console.log(`WebSocket stats: ${connectedClients.size} unique aliases connected`);
    let totalConnections = 0;
    for (const clients of connectedClients.values()) {
      totalConnections += clients.size;
    }
    console.log(`Total WebSocket connections: ${totalConnections}`);
  }, 5 * 60 * 1000);
  
  return wss;
}

// Utility function to notify all connected clients for an alias
function notifyClients(alias, email) {
  for (const [clientKey, clients] of connectedClients.entries()) {
    const [userId, clientAlias] = clientKey.split(':');
    
    if (clientAlias === alias) {
      const notification = {
        type: 'new_email',
        email,
        alias,
        timestamp: new Date().toISOString()
      };
      
      const payload = JSON.stringify(notification);
      
      for (const client of clients) {
        if (client.readyState === 1) { // OPEN
          try {
            client.send(payload);
            console.log(`Notified client ${clientKey} about new email`);
          } catch (err) {
            console.error(`Error notifying client ${clientKey}:`, err);
          }
        }
      }
    }
  }
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
      
      // Test the IMAP connection to verify credentials
      try {
        await testImapConnection(email, appPassword);
        console.log(`Successfully verified IMAP connection for ${email}`);
        
        // Reset reconnection attempts counter for this account
        reconnectionAttempts.delete(email);
      } catch (imapError) {
        console.error(`IMAP connection test failed for ${email}:`, imapError);
        throw new Error(`Failed to connect to IMAP server: ${imapError.message}`);
      }
      
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

// Test IMAP connection for an account
async function testImapConnection(email, appPassword) {
  // Create a temporary client for testing
  const testClient = new ImapFlow({
    host: 'imap.gmail.com',
    port: 993,
    secure: true,
    auth: {
      user: email,
      pass: appPassword
    },
    logger: false,
    emitLogs: false,
    timeoutConnection: 30000, // 30 seconds timeout
    tls: {
      rejectUnauthorized: true,
      enableTrace: false
    }
  });
  
  try {
    console.log(`Testing IMAP connection for ${email}...`);
    await testClient.connect();
    
    // List mailboxes to verify connection works
    const mailboxes = await testClient.list();
    console.log(`IMAP connection test successful for ${email}, found ${mailboxes.length} mailboxes`);
    
    // Clean logout
    await testClient.logout();
    return true;
  } catch (error) {
    console.error(`IMAP connection test failed for ${email}:`, error);
    // Ensure client is properly closed on error
    try {
      if (testClient.authenticated || testClient.usable) {
        await testClient.logout();
      } else if (testClient._socket && testClient._socket.writable) {
        await testClient.close();
      }
    } catch (closeError) {
      console.warn(`Error closing IMAP test client for ${email}:`, closeError);
    }
    throw error;
  }
}

// Create and get IMAP client for an account
async function getImapClient(accountEmail) {
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
    
    // Check if we have an existing client that's usable
    if (imapClients.has(accountEmail)) {
      const existingClient = imapClients.get(accountEmail);
      
      if (existingClient.usable) {
        console.log(`Using existing IMAP client for ${accountEmail}`);
        return existingClient;
      }
      
      // Existing client not usable, close it if needed
      try {
        if (existingClient._socket && existingClient._socket.writable) {
          await existingClient.close();
        }
      } catch (closeError) {
        console.warn(`Error closing unusable IMAP client for ${accountEmail}:`, closeError);
      }
    }
    
    console.log(`Creating new IMAP client for ${accountEmail}`);
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
      logger: false,
      emitLogs: false,
      disableAutoIdle: true,
      timeoutConnection: CONNECTION_TIMEOUT,
      timeoutIdle: IDLE_TIMEOUT,
      tls: {
        rejectUnauthorized: true,
        enableTrace: false,
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3'
      }
    });
    
    // Setup event listeners for connection monitoring
    client.on('error', err => {
      console.error(`IMAP client error for ${accountEmail}:`, err);
    });
    
    client.on('close', () => {
      console.log(`IMAP connection closed for ${accountEmail}`);
    });
    
    client.on('end', () => {
      console.log(`IMAP connection ended for ${accountEmail}`);
    });
    
    // Connect to the server
    try {
      await client.connect();
      console.log(`IMAP client connected for ${accountEmail}`);
      
      // Store the client
      imapClients.set(accountEmail, client);
      
      // Reset reconnection counter on successful connection
      reconnectionAttempts.delete(accountEmail);
      
      return client;
    } catch (connectError) {
      console.error(`Error connecting IMAP client for ${accountEmail}:`, connectError);
      throw connectError;
    }
  } catch (error) {
    // Implement exponential backoff for reconnection
    const attempts = reconnectionAttempts.get(accountEmail) || 0;
    reconnectionAttempts.set(accountEmail, attempts + 1);
    
    const backoffDelay = Math.min(
      MAX_RECONNECTION_DELAY, 
      BASE_RECONNECTION_DELAY * Math.pow(2, attempts)
    );
    
    console.error(`IMAP client creation error for ${accountEmail} (attempt ${attempts + 1}). Retry in ${backoffDelay/1000} seconds:`, error);
    
    if (attempts < MAX_RECONNECTION_ATTEMPTS) {
      // Schedule retry with backoff
      console.log(`Will retry IMAP connection for ${accountEmail} in ${backoffDelay/1000} seconds`);
    } else {
      console.error(`Max reconnection attempts (${MAX_RECONNECTION_ATTEMPTS}) reached for ${accountEmail}. Marking as auth-error.`);
      
      try {
        await pool.query(
          'UPDATE gmail_accounts SET status = ?, updated_at = NOW() WHERE email = ?',
          ['auth-error', accountEmail]
        );
      } catch (dbError) {
        console.error(`Error updating status for ${accountEmail}:`, dbError);
      }
    }
    
    throw error;
  }
}

// Safe way to close IMAP client
async function safelyCloseImapClient(accountEmail) {
  if (imapClients.has(accountEmail)) {
    const client = imapClients.get(accountEmail);
    
    try {
      if (client.usable) {
        await client.logout();
        console.log(`IMAP client safely logged out for ${accountEmail}`);
      } else if (client._socket && client._socket.writable) {
        await client.close();
        console.log(`IMAP client safely closed for ${accountEmail}`);
      }
    } catch (error) {
      console.warn(`Error closing IMAP client for ${accountEmail}:`, error);
    } finally {
      imapClients.delete(accountEmail);
    }
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
  let hasLock = false;
  
  try {
    // Get a database connection to acquire a lock
    // This prevents multiple instances from polling the same account simultaneously
    const connection = await pool.getConnection();
    
    try {
      // Try to acquire a lock
      const lockQuery = "SELECT GET_LOCK(?, 10) as lockResult";
      const lockName = `gmail_poll_lock_${accountEmail.replace(/[@.]/g, '_')}`;
      const [lockResult] = await connection.query(lockQuery, [lockName]);
      
      if (!lockResult || !lockResult[0] || lockResult[0].lockResult !== 1) {
        console.log(`Could not acquire lock for polling ${accountEmail}, another process may be polling`);
        return;
      }
      
      hasLock = true;
      console.log(`Acquired polling lock for ${accountEmail}`);
      
      // Get account status from database first
      const [accounts] = await connection.query(
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
      
      // Get IMAP client with retry logic built-in
      client = await getImapClient(accountEmail);
      
      // Select INBOX with maxRetries
      const maxRetries = 3;
      const mailbox = await withRetries(
        async () => await client.mailboxOpen('INBOX'),
        maxRetries,
        `Error opening INBOX for ${accountEmail}`
      );
      
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
        source: {
          startFrom: 0,
          maxLength: 1024 * 1024 // Limit source size to 1MB
        } 
      };
      
      // Use sequence numbers to get the most recent messages
      const fetchFrom = Math.max(1, mailbox.exists - messageCount + 1);
      const fetchRange = `${fetchFrom}:*`;
      
      console.log(`Fetching messages ${fetchRange} for ${accountEmail}`);
      
      let processedCount = 0;
      let newEmailsFound = 0;
      
      try {
        // Process each message
        for await (const message of client.fetch(fetchRange, fetchOptions)) {
          try {
            processedCount++;
            
            // Check if this message is addressed to any of our aliases
            const toAddresses = message.envelope.to || [];
            const recipientAliases = [];
            
            for (const to of toAddresses) {
              const toAddress = to.address.toLowerCase();
              if (accountAliases.includes(toAddress)) {
                recipientAliases.push(toAddress);
              }
            }
            
            if (recipientAliases.length > 0) {
              // Process for each matching alias
              for (const recipientAlias of recipientAliases) {
                console.log(`Found message for alias ${recipientAlias}, UID: ${message.uid}`);
                
                // Process the message
                const processedEmail = processImapMessage(message, recipientAlias);
                
                // Add to cache
                const cacheKey = `${recipientAlias}:${message.uid}`;
                if (!emailCache.has(cacheKey)) {
                  addToEmailCache(cacheKey, processedEmail);
                  console.log(`Added message ${message.uid} to cache for ${recipientAlias}`);
                  newEmailsFound++;
                  
                  // Notify connected clients about the new email (WebSocket)
                  notifyClients(recipientAlias, processedEmail);
                }
              }
            }
          } catch (messageError) {
            console.error(`Error processing message ${message.uid}:`, messageError);
          }
        }
      } catch (fetchError) {
        console.error(`Error during fetch for ${accountEmail}:`, fetchError);
      }
      
      console.log(`Processed ${processedCount} messages for ${accountEmail}, found ${newEmailsFound} new emails`);
      
      // Update account metrics in database
      await connection.query(
        'UPDATE gmail_accounts SET quota_used = quota_used + 1, last_used = NOW(), updated_at = NOW() WHERE id = ?',
        [account.id]
      );
      
    } finally {
      // Release the lock regardless of outcome
      if (hasLock) {
        const releaseLockQuery = "SELECT RELEASE_LOCK(?) as releaseResult";
        const lockName = `gmail_poll_lock_${accountEmail.replace(/[@.]/g, '_')}`;
        const [releaseResult] = await connection.query(releaseLockQuery, [lockName]);
        
        if (releaseResult && releaseResult[0] && releaseResult[0].releaseResult === 1) {
          console.log(`Released polling lock for ${accountEmail}`);
        } else {
          console.warn(`Failed to release polling lock for ${accountEmail}`);
        }
      }
      
      // Release the connection
      connection.release();
    }
  } catch (error) {
    console.error(`Error polling Gmail account ${accountEmail}:`, error);
    
    // Update account status in database with more detailed status
    let statusUpdate = 'error';
    if (error.message?.includes('Invalid credentials') || 
        error.message?.includes('authentication failed') ||
        error.message?.includes('[AUTH]')) {
      statusUpdate = 'auth-error';
      console.log(`Account ${accountEmail} has invalid credentials - marked as auth-error`);
      
      // Remove from active polling immediately
      activeImapAccounts.delete(accountEmail);
    } else if (error.message?.includes('quota') || error.message?.includes('rate limit')) {
      statusUpdate = 'rate-limited';
      console.log(`Account ${accountEmail} is rate limited`);
    } else if (error.message?.includes('network') || 
               error.message?.includes('timeout') || 
               error.message?.includes('connection')) {
      statusUpdate = 'network-error';
      console.log(`Network error with account ${accountEmail} - will retry with backoff`);
    }
    
    try {
      await pool.query(
        'UPDATE gmail_accounts SET status = ?, updated_at = NOW() WHERE email = ?',
        [statusUpdate, accountEmail]
      );
      
      // Implement exponential backoff for reconnection
      handlePollingError(accountEmail, statusUpdate);
      
    } catch (dbError) {
      console.error('Error updating account status:', dbError);
    }
  } finally {
    // Close the IMAP connection properly if it's still open
    if (client) {
      try {
        // Close connection with max wait of 5 seconds to avoid hanging
        const closePromise = client.logout();
        const timeoutPromise = new Promise((_, reject) => 
          setTimeout(() => reject(new Error('IMAP logout timeout')), 5000)
        );
        
        await Promise.race([closePromise, timeoutPromise]);
      } catch (logoutError) {
        console.warn(`Error during IMAP logout for ${accountEmail}:`, logoutError);
        
        // Force close if logout fails
        try {
          if (client._socket && client._socket.writable) {
            await client.close();
          }
        } catch (forceCloseError) {
          console.warn(`Error force closing IMAP connection for ${accountEmail}:`, forceCloseError);
        }
      } finally {
        // Remove client from map if it's the current one
        if (imapClients.get(accountEmail) === client) {
          imapClients.delete(accountEmail);
        }
      }
    }
  }
}

// Error handling with exponential backoff
function handlePollingError(accountEmail, statusType) {
  if (statusType === 'auth-error') {
    // Remove from active polling completely for auth errors
    activeImapAccounts.delete(accountEmail);
    console.log(`Removed ${accountEmail} from active polling due to auth error`);
    return;
  }
  
  // Get current attempt count or start at 0
  const attempts = reconnectionAttempts.get(accountEmail) || 0;
  
  // Increment attempt counter
  reconnectionAttempts.set(accountEmail, attempts + 1);
  
  // Calculate delay with exponential backoff and jitter
  // Base delay * 2^attempts + random jitter of up to 30%
  const baseDelay = BASE_RECONNECTION_DELAY * Math.pow(2, Math.min(attempts, 8));
  const jitter = Math.random() * 0.3 * baseDelay;
  const delay = Math.min(MAX_RECONNECTION_DELAY, baseDelay + jitter);
  
  console.log(`Scheduling retry #${attempts + 1} for ${accountEmail} in ${Math.round(delay / 1000)} seconds`);
  
  setTimeout(() => {
    if (activeImapAccounts.has(accountEmail)) {
      console.log(`Attempting retry #${attempts + 1} for ${accountEmail}`);
      
      // If we're at max attempts, mark account as inactive but keep trying at a slow rate
      if (attempts >= MAX_RECONNECTION_ATTEMPTS) {
        console.log(`Max retry attempts (${MAX_RECONNECTION_ATTEMPTS}) reached for ${accountEmail}, reducing frequency`);
        
        // Don't give up entirely, just slow down dramatically
        setTimeout(() => {
          // Reset attempt counter after a long break
          reconnectionAttempts.set(accountEmail, Math.floor(MAX_RECONNECTION_ATTEMPTS / 2));
          
          if (activeImapAccounts.has(accountEmail)) {
            console.log(`Attempting recovery polling for ${accountEmail} after cooling off`);
            pollForNewEmails(accountEmail).catch(error => 
              console.error(`Recovery polling attempt for ${accountEmail} failed:`, error)
            );
          }
        }, MAX_RECONNECTION_DELAY); // Try again after max delay
      } else {
        // Normal retry
        pollForNewEmails(accountEmail).catch(error => 
          console.error(`Retry attempt for ${accountEmail} failed:`, error)
        );
      }
    }
  }, delay);
}

// Function to retry an operation with exponential backoff
async function withRetries(operation, maxRetries = 3, errorMsg = 'Operation failed') {
  let lastError;
  
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      
      if (attempt < maxRetries) {
        const delay = BASE_RECONNECTION_DELAY * Math.pow(2, attempt);
        console.log(`${errorMsg}. Retrying in ${delay/1000}s (attempt ${attempt + 1}/${maxRetries})`);
        
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  
  // If we get here, all retries failed
  throw new Error(`${errorMsg} after ${maxRetries} attempts: ${lastError?.message}`);
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
      
      // Handle existing retries
      const runPollingNow = !reconnectionAttempts.has(accountEmail) || 
                          reconnectionAttempts.get(accountEmail) < 3;
      
      if (runPollingNow) {
        // Start with an immediate poll, then schedule recurring
        pollForNewEmails(accountEmail).catch(error => {
          console.error(`Initial poll for ${accountEmail} failed:`, error);
          // Error handled in pollForNewEmails
        });
      }
      
      // Schedule next poll
      setTimeout(() => {
        // Only schedule next poll if account is still in active set
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
  const source = message.source ? message.source.toString() : '';
  
  // Extract basic info from envelope
  const from = message.envelope.from?.[0]?.address || '';
  const fromName = message.envelope.from?.[0]?.name || from.split('@')[0] || '';
  const subject = message.envelope.subject || '(No Subject)';
  
  // Extract body parts - using a more efficient approach
  let bodyHtml = '';
  let bodyText = '';
  
  // Simplified extraction for demo purposes
  // In production, use mailparser for robust parsing
  if (source) {
    // Try to extract HTML body
    const htmlMatch = source.match(/<html[\s\S]*?<\/html>/i);
    if (htmlMatch) {
      bodyHtml = htmlMatch[0];
    }
    
    // If no HTML, try to get plain text
    if (!bodyHtml) {
      // Find content after headers
      const bodyMatch = source.match(/\r\n\r\n([\s\S]*?)$/);
      if (bodyMatch) {
        bodyText = bodyMatch[1];
      }
    }
  }
  
  // Extract attachments (simplified)
  const attachments = [];
  
  // Ensure we have at least some content
  if (!bodyHtml && !bodyText) {
    bodyText = "No content available.";
  }
  
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
    snippet: bodyText.substring(0, 100).replace(/\s+/g, ' ').trim(),
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
    
    // Set up a cleanup interval for IMAP clients
    setInterval(async () => {
      try {
        // Clean up any stale IMAP clients
        for (const [email, client] of imapClients.entries()) {
          // Check if account is still active
          if (!activeImapAccounts.has(email)) {
            console.log(`Cleaning up IMAP client for inactive account ${email}`);
            await safelyCloseImapClient(email);
          } else if (client._connectionTimeout) {
            // Client has a connection timeout, try to clean it up
            console.log(`Cleaning up IMAP client with connection timeout for ${email}`);
            await safelyCloseImapClient(email);
          }
        }
      } catch (error) {
        console.error('Error during IMAP client cleanup:', error);
      }
    }, 10 * 60 * 1000); // Run every 10 minutes
    
    console.log('IMAP service initialized successfully');
    return true;
  } catch (error) {
    console.error('Failed to initialize IMAP service:', error);
    return false;
  }
}
