import { ImapFlow } from 'imapflow';
import { v4 as uuidv4 } from 'uuid';
import { pool } from '../db/init.js';
import crypto from 'crypto';
import { WebSocketServer } from 'ws';
import { simpleParser } from 'mailparser';

// In-memory storage
const emailCache = new Map(); // Cache for fetched emails
const aliasCache = new Map(); // Cache for active aliases during runtime
const activeImapAccounts = new Set(); // Track which accounts are being actively polled
const imapClients = new Map(); // Store active IMAP clients
const connectedClients = new Map(); // Map of userId:alias -> Set of websocket connections
const reconnectionAttempts = new Map(); // Track reconnection attempts for exponential backoff

// User-based account rotation tracking
const userAccountAssignments = new Map(); // Track which account is assigned to which user
const accountUserCounts = new Map(); // Track how many users are assigned to each account
const pendingDbUpdates = new Map(); // Track pending database updates to batch them

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
const MAX_EMAILS_PER_FETCH = 50; // Maximum number of emails to fetch at once

// Set the interval for batch DB updates
const DB_UPDATE_INTERVAL = 10 * 60 * 1000; // 10 minutes

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
        chunkSize: 1024,
        memLevel: 7,
        level: 3
      },
      zlibInflateOptions: {
        chunkSize: 10 * 1024
      },
      clientNoContextTakeover: true,
      serverNoContextTakeover: true,
      clientMaxWindowBits: 10,
      serverMaxWindowBits: 10,
      concurrencyLimit: 10,
      threshold: 1024
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
  
  // Log websocket stats every 15 minutes
  setInterval(() => {
    console.log(`WebSocket stats: ${connectedClients.size} unique aliases connected`);
    let totalConnections = 0;
    for (const clients of connectedClients.values()) {
      totalConnections += clients.size;
    }
    console.log(`Total WebSocket connections: ${totalConnections}`);
  }, 15 * 60 * 1000);
  
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

// Gmail Account Management with batched DB updates
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
        
        // Reset account user counts
        accountUserCounts.set(email, 0);
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
    timeoutConnection: 30000,
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
async function getImapClient(accountEmail, persistConnection = true) {
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
        // Perform a no-op to check that the connection is still active
        try {
          await existingClient.noop();
          return existingClient;
        } catch (noopError) {
          console.warn(`NOOP failed for ${accountEmail}, recreating connection`);
        }
      }
      
      // Existing client not usable, close it if needed
      try {
        if (existingClient._socket && existingClient._socket.writable) {
          await existingClient.close();
        }
      } catch (closeError) {
        console.warn(`Error closing unusable IMAP client for ${accountEmail}:`, closeError);
      } finally {
        imapClients.delete(accountEmail);
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
      imapClients.delete(accountEmail);
    });
    
    client.on('close', () => {
      console.log(`IMAP connection closed for ${accountEmail}`);
      imapClients.delete(accountEmail);
    });
    
    client.on('end', () => {
      console.log(`IMAP connection ended for ${accountEmail}`);
      imapClients.delete(accountEmail);
    });
    
    // Connect to the server
    try {
      await client.connect();
      console.log(`IMAP client connected for ${accountEmail}`);
      
      // Only store the client if we want a persistent connection
      if (persistConnection) {
        imapClients.set(accountEmail, client);
      }
      
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
      
      // Add to batch updates instead of immediate DB write
      addPendingDbUpdate(accountEmail, 'status', 'auth-error');
    }
    
    throw error;
  }
}

// Add a pending DB update to the batch
function addPendingDbUpdate(accountEmail, field, value) {
  if (!pendingDbUpdates.has(accountEmail)) {
    pendingDbUpdates.set(accountEmail, new Map());
  }
  pendingDbUpdates.get(accountEmail).set(field, value);
  
  // If this is a critical update, schedule a flush soon
  if (field === 'status' && (value === 'auth-error' || value === 'error')) {
    // Schedule urgent flush in 10 seconds if not already scheduled
    if (!global.pendingFlushTimeout) {
      global.pendingFlushTimeout = setTimeout(flushPendingDbUpdates, 10000);
    }
  }
}

// Flush pending DB updates in a single batch transaction
async function flushPendingDbUpdates() {
  if (pendingDbUpdates.size === 0) return;
  
  console.log(`Flushing ${pendingDbUpdates.size} pending DB updates`);
  
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    
    // Process each account's updates
    for (const [accountEmail, updates] of pendingDbUpdates.entries()) {
      // Build update query dynamically
      const fields = [];
      const values = [];
      
      for (const [field, value] of updates.entries()) {
        fields.push(`${field} = ?`);
        values.push(value);
      }
      
      // Always update the timestamp
      fields.push('updated_at = NOW()');
      
      // Add the account email for WHERE clause
      values.push(accountEmail);
      
      // Execute the update
      const query = `UPDATE gmail_accounts SET ${fields.join(', ')} WHERE email = ?`;
      await connection.query(query, values);
    }
    
    await connection.commit();
    console.log(`Successfully committed ${pendingDbUpdates.size} account updates`);
    
    // Clear the pending updates
    pendingDbUpdates.clear();
    
  } catch (error) {
    await connection.rollback();
    console.error('Error flushing pending DB updates:', error);
    
    // If critical error, try again soon
    setTimeout(flushPendingDbUpdates, 60000);
  } finally {
    connection.release();
    global.pendingFlushTimeout = null;
  }
}

// Schedule regular flushes of pending DB updates
setInterval(flushPendingDbUpdates, DB_UPDATE_INTERVAL);

// Safe way to close IMAP client
async function safelyCloseImapClient(accountEmail) {
  if (imapClients.has(accountEmail)) {
    const client = imapClients.get(accountEmail);
    
    try {
      // Don't remove from imapClients until we've successfully closed the connection
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

// Improved alias generation with user-based account rotation
export async function generateGmailAlias(userId, strategy = 'dot', domain = 'gmail.com') {
  try {
    // Check if this user already has an assigned account
    let account;
    
    if (userId && userAccountAssignments.has(userId)) {
      const assignedAccountEmail = userAccountAssignments.get(userId);
      
      // Get the account from DB
      const [accounts] = await pool.query(
        'SELECT * FROM gmail_accounts WHERE email = ? AND status = "active"',
        [assignedAccountEmail]
      );
      
      if (accounts.length > 0) {
        account = accounts[0];
        console.log(`Using previously assigned account ${account.email} for user ${userId}`);
      } else {
        // Account no longer valid, need to assign a new one
        userAccountAssignments.delete(userId);
        // Fall through to assignment logic below
      }
    }
    
    // If user doesn't have an assigned account, get next account using rotation logic
    if (!account) {
      // Get all available accounts
      const [allAccounts] = await pool.query(`
        SELECT * FROM gmail_accounts 
        WHERE status = 'active'
        ORDER BY id
      `);
      
      if (allAccounts.length === 0) {
        throw new Error('No Gmail accounts available');
      }
      
      // Find the account with the lowest number of assigned users
      let selectedAccount = null;
      let lowestUserCount = Infinity;
      
      for (const acc of allAccounts) {
        const userCount = accountUserCounts.get(acc.email) || 0;
        
        // If we found an account with fewer users, select it
        if (userCount < lowestUserCount) {
          selectedAccount = acc;
          lowestUserCount = userCount;
        }
      }
      
      // If all accounts have the same number of users, pick one randomly
      if (!selectedAccount) {
        const randomIndex = Math.floor(Math.random() * allAccounts.length);
        selectedAccount = allAccounts[randomIndex];
      }
      
      account = selectedAccount;
      
      // Assign this account to the user
      if (userId) {
        userAccountAssignments.set(userId, account.email);
        
        // Increment user count for this account
        const currentCount = accountUserCounts.get(account.email) || 0;
        accountUserCounts.set(account.email, currentCount + 1);
      }
      
      console.log(`Assigned account ${account.email} to user ${userId || 'anonymous'}, current user count: ${accountUserCounts.get(account.email) || 0}`);
    }
    
    // Generate unique alias based on strategy
    const alias = strategy === 'dot' 
      ? generateDotAlias(account.email, domain)
      : generatePlusAlias(account.email, domain);
    
    console.log(`Generated alias: ${alias} for user ${userId || 'anonymous'}`);
    
    // Store in-memory alias cache
    aliasCache.set(alias, {
      parentAccount: account.email,
      parentAccountId: account.id,
      created: Date.now(),
      lastAccessed: Date.now(),
      userId: userId || null,
      expires: new Date(Date.now() + ALIAS_TTL)
    });
    
    // Add to pending DB updates for batched processing
    addPendingDbUpdate(account.email, 'alias_count', account.alias_count + 1);
    
    return { alias };
    
  } catch (error) {
    console.error('Failed to generate Gmail alias:', error);
    throw new Error('Failed to generate alias: ' + error.message);
  }
}

function generateDotAlias(email, domain = 'gmail.com') {
  // Extract username and domain
  const [username, _] = email.split('@');
  
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

function generatePlusAlias(email, domain = 'gmail.com') {
  // Extract username and domain
  const [username, _] = email.split('@');
  
  // Add random tag
  const tag = Math.random().toString(36).substring(2, 8);
  
  return `${username}+${tag}@${domain}`;
}

// Faster email fetching with improved caching
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
      
      console.log(`Found alias ${aliasEmail} in cache, parent account: ${parentAccount}`);
    } else {
      console.log(`Alias ${aliasEmail} not found in cache, checking user permissions`);
      
      // For both authenticated and anonymous users, generate a new alias
      if (userId) {
        console.log(`User ${userId} requesting missing alias, creating new one`);
        const result = await generateGmailAlias(userId);
        return fetchGmailEmails(userId, result.alias); // Recursive call with new alias
      } else {
        throw new Error('Alias not found and no user ID provided');
      }
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
        addPendingDbUpdate(parentAccount, 'status', 'active');
        
        // Schedule an immediate DB flush for critical status changes
        setTimeout(flushPendingDbUpdates, 1000);
        
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
    
    // If we have very few emails in cache or cache is stale, trigger a background fetch
    const shouldFetchInBackground = cachedEmails.length < 5 || 
      (cachedEmails.length > 0 && Date.now() - cachedEmails[0].timestamp > 60000); // 1 minute stale
    
    if (shouldFetchInBackground) {
      console.log(`${cachedEmails.length} emails in cache for ${aliasEmail}, triggering background fetch`);
      
      // Don't await - fetch in background
      fetchEmailsForAlias(parentAccount, aliasEmail).catch(error => {
        console.error(`Background fetch failed for ${aliasEmail}:`, error);
      });
    }
    
    // Return cached emails sorted by date (newest first)
    console.log(`Returning ${cachedEmails.length} cached emails for ${aliasEmail}`);
    return cachedEmails.sort((a, b) => 
      new Date(b.internalDate) - new Date(a.internalDate)
    );
  
  } catch (error) {
    console.error(`Error fetching Gmail emails for ${aliasEmail}:`, error);
    throw error;
  }
}

// Optimized fetching specifically for an alias (reduced fetch time)
async function fetchEmailsForAlias(accountEmail, alias) {
  let client = null;
  
  try {
    // Get IMAP client - don't persist this one-time fetch client
    client = await getImapClient(accountEmail, false);
    
    // Keep track of the last fetch time for this alias
    const lastFetchKey = `last_fetch_${alias}`;
    const lastFetchTime = globalThis[lastFetchKey] || new Date(0);
    
    // Look in both INBOX and Spam folders, but only fetch new messages since last check
    const folders = ['INBOX', '[Gmail]/Spam'];
    let totalEmails = 0;
    
    for (const folder of folders) {
      try {
        console.log(`Searching ${folder} for emails to ${alias}...`);
        
        // Select the mailbox
        const mailbox = await client.mailboxOpen(folder);
        console.log(`Opened ${folder} for ${accountEmail}, message count: ${mailbox.exists}`);
        
        // If no messages, skip to next folder
        if (mailbox.exists === 0) {
          console.log(`No messages in ${folder} for ${accountEmail}`);
          continue;
        }
        
        // Search for emails to this alias, only since last fetch
        const searchCriteria = {
          to: alias,
          since: lastFetchTime
        };
        
        const search = await client.search(searchCriteria);
        console.log(`Found ${search.length} new messages for ${alias} in ${folder} since ${lastFetchTime.toISOString()}`);
        
        // If no messages found in search, skip to next folder
        if (search.length === 0) {
          continue;
        }
        
        // Fetch messages in smaller batches to reduce memory usage and improve speed
        const batchSize = 5; // Smaller batch size for faster responses
        for (let i = 0; i < search.length; i += batchSize) {
          const batch = search.slice(i, i + batchSize);
          
          // Fetch only headers first, then body on demand
          for await (const message of client.fetch(batch, { envelope: true })) {
            try {
              // First check if the message is actually addressed to our alias
              const toAddresses = message.envelope.to.map(to => to.address.toLowerCase());
              if (toAddresses.includes(alias.toLowerCase())) {
                // Now fetch the full message body
                const fullMessage = await client.fetchOne(message.uid, { source: true });
                
                // Parse the email (optimized)
                const email = await parseImapMessage(fullMessage.source.toString(), alias);
                
                // Add to cache
                const cacheKey = `${alias}:${message.uid}`;
                if (!emailCache.has(cacheKey)) {
                  addToEmailCache(cacheKey, email);
                  totalEmails++;
                  
                  // Notify connected clients about the new email
                  notifyClients(alias, email);
                }
              }
            } catch (messageError) {
              console.error(`Error processing message ${message.uid}:`, messageError);
            }
          }
        }
      } catch (folderError) {
        console.error(`Error processing folder ${folder} for ${accountEmail}:`, folderError);
        // Continue to next folder even if one fails
      }
    }
    
    // Update the last fetch time
    globalThis[lastFetchKey] = new Date();
    
    console.log(`Fetched a total of ${totalEmails} new emails for ${alias}`);
    
    // Add to pending DB updates instead of immediate update
    if (totalEmails > 0) {
      addPendingDbUpdate(accountEmail, 'quota_used', parseInt(accountEmail.quota_used || 0) + 1);
    }
    
  } catch (error) {
    console.error(`Error fetching emails for alias ${alias}:`, error);
    throw error;
  } finally {
    // Always close non-persistent clients
    if (client) {
      try {
        // Don't wait for logout to complete - just let it happen asynchronously
        client.logout().catch(err => {
          console.warn(`Error logging out IMAP client for ${accountEmail}:`, err);
        });
      } catch (error) {
        console.warn(`Error closing IMAP client for ${accountEmail}:`, error);
      }
    }
  }
}

// Parse an IMAP message efficiently using simpleParser for better results
async function parseImapMessage(source, recipientAlias) {
  try {
    // Use simpleParser for faster parsing with less memory usage
    const parsed = await simpleParser(source, {
      skipHtmlToText: true, // Skip html to text conversion for performance
      skipTextToHtml: true, // Skip text to html conversion for performance
      skipTextLinks: true   // Skip text links for performance
    });
    
    // Extract information
    const from = parsed.from?.text || '';
    const fromName = parsed.from?.value?.[0]?.name || parsed.from?.value?.[0]?.address?.split('@')[0] || '';
    const fromEmail = parsed.from?.value?.[0]?.address || '';
    const to = recipientAlias;
    const subject = parsed.subject || '(No Subject)';
    const bodyHtml = parsed.html || '';
    const bodyText = parsed.text || '';
    const date = parsed.date || new Date();
    
    // Get attachments info (optimized to not store full content)
    const attachments = parsed.attachments?.map(att => ({
      filename: att.filename,
      contentType: att.contentType,
      size: att.size,
      contentId: att.contentId,
      disposition: att.disposition
    })) || [];
    
    // Generate a unique ID based on message ID and date
    const id = parsed.messageId || `${date.getTime()}-${Math.random().toString(36).substring(2, 10)}`;
    
    return {
      id,
      threadId: parsed.messageId || id, 
      from,
      fromName,
      fromEmail,
      to,
      subject,
      bodyHtml,
      bodyText,
      internalDate: date.toISOString(),
      timestamp: Date.now(),
      snippet: bodyText.substring(0, 150).replace(/\s+/g, ' ').trim(),
      recipientAlias,
      attachments
    };
  } catch (error) {
    console.error('Error parsing email message:', error);
    // Fall back to a simple parsing approach if mailparser fails
    return {
      id: `fallback-${Date.now()}-${Math.random().toString(36).substring(2, 10)}`,
      threadId: `fallback-thread-${Date.now()}`,
      from: 'Error Parsing Email',
      fromName: 'Error',
      fromEmail: 'error@parsing.email',
      to: recipientAlias,
      subject: 'Error Parsing Email',
      bodyHtml: '',
      bodyText: 'There was an error parsing this email.',
      internalDate: new Date().toISOString(),
      timestamp: Date.now(),
      snippet: 'Error parsing email',
      recipientAlias,
      attachments: []
    };
  }
}

// Return only the most recent alias for each user
export async function getUserAliases(userId) {
  if (!userId) return [];
  
  try {
    // Get all aliases from memory cache for this user
    const userAliases = [];
    
    for (const [alias, data] of aliasCache.entries()) {
      if (data.userId === userId) {
        userAliases.push({
          alias,
          created: data.created
        });
      }
    }
    
    // Sort by creation date, newest first
    userAliases.sort((a, b) => b.created - a.created);
    
    // Return only the aliases, not the full objects
    const result = userAliases.map(a => a.alias);
    console.log(`User ${userId} has ${result.length} aliases, returning newest ones`);
    
    return result;
  } catch (error) {
    console.error('Failed to get user aliases:', error);
    return [];
  }
}

// When a user rotates their alias, assign them a different account
export async function rotateUserAlias(userId, strategy = 'dot', domain = 'gmail.com') {
  try {
    // If user has an account assignment, clear it to force a new account
    if (userId && userAccountAssignments.has(userId)) {
      const oldAccount = userAccountAssignments.get(userId);
      
      // Decrease the user count for the old account
      const currentCount = accountUserCounts.get(oldAccount) || 0;
      if (currentCount > 0) {
        accountUserCounts.set(oldAccount, currentCount - 1);
      }
      
      // Remove the user's assignment
      userAccountAssignments.delete(userId);
      
      console.log(`Cleared account assignment for user ${userId} to force rotation`);
    }
    
    // Generate a new alias (will assign a new account as needed)
    return await generateGmailAlias(userId, strategy, domain);
  } catch (error) {
    console.error('Failed to rotate Gmail alias:', error);
    throw error;
  }
}

// Improved email polling with more efficient searching and better error handling
async function pollForNewEmails(accountEmail) {
  let client = null;
  
  try {
    // Skip polling if this account has no aliases
    let hasAliases = false;
    for (const data of aliasCache.values()) {
      if (data.parentAccount === accountEmail) {
        hasAliases = true;
        break;
      }
    }
    
    if (!hasAliases) {
      console.log(`Skipping polling for ${accountEmail}: no aliases assigned`);
      return;
    }
    
    // Get IMAP client but don't persist it
    client = await getImapClient(accountEmail, false);
    
    // Check both INBOX and Spam folders
    const folders = ['INBOX', '[Gmail]/Spam'];
    
    // Get all aliases for this account
    const accountAliases = [];
    for (const [alias, data] of aliasCache.entries()) {
      if (data.parentAccount === accountEmail) {
        accountAliases.push(alias);
      }
    }
    
    if (accountAliases.length === 0) {
      console.log(`No aliases found for ${accountEmail}, skipping polling`);
      return;
    }
    
    console.log(`Polling for ${accountAliases.length} aliases on account ${accountEmail}`);
    
    // Process each folder
    for (const folder of folders) {
      try {
        // Select the folder
        await client.mailboxOpen(folder);
        console.log(`Opened ${folder} for ${accountEmail}`);
        
        // Instead of searching for ALL emails (slow), search for recent ones
        // This significantly reduces fetch time
        const oneDayAgo = new Date();
        oneDayAgo.setDate(oneDayAgo.getDate() - 1);
        
        // Get messages newer than 1 day
        const messages = await client.search({ since: oneDayAgo });
        console.log(`Found ${messages.length} messages from last 24 hours in ${folder}`);
        
        if (messages.length === 0) continue;
        
        // Process in smaller batches for better performance
        const BATCH_SIZE = 10;
        for (let i = 0; i < messages.length; i += BATCH_SIZE) {
          const batch = messages.slice(i, i + BATCH_SIZE);
          
          // Get message headers first (much faster than full messages)
          for await (const message of client.fetch(batch, { envelope: true })) {
            try {
              // Check if any of our aliases is in the recipient list
              const recipients = [...(message.envelope.to || []), ...(message.envelope.cc || [])];
              const matchingAliases = [];
              
              for (const recipient of recipients) {
                const address = recipient.address?.toLowerCase();
                if (address && accountAliases.includes(address)) {
                  matchingAliases.push(address);
                }
              }
              
              // If we found matches, fetch the full message
              if (matchingAliases.length > 0) {
                const fullMessage = await client.fetchOne(message.uid, { source: true });
                
                // Process for each matching alias
                for (const alias of matchingAliases) {
                  // Parse the message
                  const email = await parseImapMessage(fullMessage.source.toString(), alias);
                  
                  // Add to cache with unique key
                  const cacheKey = `${alias}:${message.uid}`;
                  if (!emailCache.has(cacheKey)) {
                    addToEmailCache(cacheKey, email);
                    
                    // Notify WebSocket clients
                    notifyClients(alias, email);
                    
                    console.log(`New email found for ${alias} in ${folder}`);
                  }
                }
              }
            } catch (messageError) {
              console.error(`Error processing message ${message.uid}:`, messageError);
            }
          }
        }
      } catch (folderError) {
        console.error(`Error processing folder ${folder}:`, folderError);
      }
    }
    
    // Add to pending quota update instead of immediate DB update
    addPendingDbUpdate(accountEmail, 'quota_used', parseInt(accountEmail.quota_used || 0) + 1);
    addPendingDbUpdate(accountEmail, 'last_used', 'NOW()');
    
  } catch (error) {
    console.error(`Error polling Gmail account ${accountEmail}:`, error);
    
    // Add to pending status update instead of immediate DB write
    if (error.message?.includes('Invalid credentials') || 
        error.message?.includes('authentication failed') ||
        error.message?.includes('[AUTH]')) {
      addPendingDbUpdate(accountEmail, 'status', 'auth-error');
      activeImapAccounts.delete(accountEmail);
    } else if (error.message?.includes('quota') || error.message?.includes('rate limit')) {
      addPendingDbUpdate(accountEmail, 'status', 'rate-limited');
    } else if (error.message?.includes('network') || 
               error.message?.includes('timeout') || 
               error.message?.includes('connection')) {
      addPendingDbUpdate(accountEmail, 'status', 'network-error');
    }
    
    // Force a DB update soon for error conditions
    setTimeout(flushPendingDbUpdates, 10000);
  } finally {
    // Close the IMAP connection properly if it's still open
    if (client) {
      try {
        await client.logout();
      } catch (logoutError) {
        console.warn(`Error during IMAP logout for ${accountEmail}:`, logoutError);
      }
    }
  }
}

// Set up polling schedule with dynamic intervals
function schedulePolling(accountEmail) {
  console.log(`Setting up polling schedule for ${accountEmail}`);
  
  // Check if account is active
  (async () => {
    try {
      // Get latest account state from database
      const [accounts] = await pool.query(
        'SELECT * FROM gmail_accounts WHERE email = ? AND status = "active"',
        [accountEmail]
      );
      
      if (accounts.length === 0) {
        console.log(`Not scheduling polling for inactive/missing account: ${accountEmail}`);
        activeImapAccounts.delete(accountEmail);
        return;
      }
      
      console.log(`Scheduling polling for ${accountEmail}`);
      
      // Count aliases for this account to determine priority
      let aliasCount = 0;
      for (const data of aliasCache.values()) {
        if (data.parentAccount === accountEmail) {
          aliasCount++;
        }
      }
      
      // Determine polling interval based on activity
      let interval = POLLING_INTERVALS.medium; // Default
      
      if (aliasCount > 10) {
        interval = POLLING_INTERVALS.high;
      } else if (aliasCount > 5) {
        interval = POLLING_INTERVALS.medium;
      } else {
        interval = POLLING_INTERVALS.low;
      }
      
      // Start with an initial poll (don't await - let it run in background)
      pollForNewEmails(accountEmail).catch(error => {
        console.error(`Initial poll for ${accountEmail} failed:`, error);
      });
      
      // Schedule next poll
      setTimeout(() => {
        if (activeImapAccounts.has(accountEmail)) {
          schedulePolling(accountEmail);
        } else {
          console.log(`Stopped polling for ${accountEmail} as it's no longer active`);
        }
      }, interval);
      
    } catch (error) {
      console.error(`Error setting up polling for ${accountEmail}:`, error);
    }
  })();
}

// More efficient caching with LRU eviction
function addToEmailCache(key, email) {
  // If cache is at capacity, remove oldest entries
  if (emailCache.size >= MAX_CACHE_SIZE) {
    // Get all entries, sort by timestamp, and remove oldest 10%
    const entries = Array.from(emailCache.entries());
    const oldestEntries = entries
      .sort((a, b) => a[1].timestamp - b[1].timestamp)
      .slice(0, Math.ceil(MAX_CACHE_SIZE * 0.1));
    
    // Delete oldest entries
    for (const [oldKey] of oldestEntries) {
      emailCache.delete(oldKey);
    }
    
    console.log(`Cleared ${oldestEntries.length} oldest emails from cache`);
  }
  
  // Add to cache with timestamp
  emailCache.set(key, {
    ...email,
    timestamp: Date.now()
  });
}

// Clean up inactive aliases with batched DB updates
export async function cleanupInactiveAliases() {
  console.log('Running alias cleanup...');
  
  const now = Date.now();
  let count = 0;
  
  // Track account alias changes for batch updates
  const accountAliasChanges = new Map();
  
  // Check each alias for expiration
  for (const [alias, data] of aliasCache.entries()) {
    if (now - data.lastAccessed > ALIAS_TTL) {
      // Track the parent account for alias count update
      if (data.parentAccount) {
        // Increment count of aliases removed for this account
        const currentCount = accountAliasChanges.get(data.parentAccount) || 0;
        accountAliasChanges.set(data.parentAccount, currentCount + 1);
      }
      
      // Remove from user assignments if needed
      if (data.userId && userAccountAssignments.has(data.userId)) {
        if (userAccountAssignments.get(data.userId) === data.parentAccount) {
          userAccountAssignments.delete(data.userId);
          
          // Decrement user count for the account
          const currentCount = accountUserCounts.get(data.parentAccount) || 0;
          if (currentCount > 0) {
            accountUserCounts.set(data.parentAccount, currentCount - 1);
          }
        }
      }
      
      // Remove alias from cache
      aliasCache.delete(alias);
      count++;
    }
  }
  
  // Add account alias count changes to pending DB updates
  for (const [accountEmail, aliasCount] of accountAliasChanges.entries()) {
    // Get current count from database
    const [accounts] = await pool.query(
      'SELECT alias_count FROM gmail_accounts WHERE email = ?',
      [accountEmail]
    );
    
    if (accounts.length > 0) {
      const currentCount = accounts[0].alias_count || 0;
      const newCount = Math.max(0, currentCount - aliasCount);
      
      // Add to pending updates
      addPendingDbUpdate(accountEmail, 'alias_count', newCount);
    }
  }
  
  if (count > 0) {
    console.log(`Cleaned up ${count} expired aliases with ${accountAliasChanges.size} affected accounts`);
    
    // Force a DB update soon if we cleaned up aliases
    setTimeout(flushPendingDbUpdates, 10000);
  }
}

// Get the next available account using better rotation
async function getNextAvailableAccount() {
  try {
    // Get all active accounts
    const [accounts] = await pool.query(`
      SELECT * FROM gmail_accounts 
      WHERE status = 'active'
      ORDER BY id
    `);
    
    if (accounts.length === 0) {
      console.error('No available Gmail accounts');
      return null;
    }
    
    // Implement round-robin assignment using user counts
    let selectedAccount = null;
    let lowestUserCount = Infinity;
    
    for (const account of accounts) {
      const userCount = accountUserCounts.get(account.email) || 0;
      
      if (userCount < lowestUserCount) {
        lowestUserCount = userCount;
        selectedAccount = account;
      }
    }
    
    // If all have the same count, use one with lowest alias_count from DB
    if (!selectedAccount) {
      selectedAccount = accounts.reduce((prev, curr) => 
        (curr.alias_count || 0) < (prev.alias_count || 0) ? curr : prev
      );
    }
    
    console.log(`Selected account ${selectedAccount.email} for new alias (users: ${accountUserCounts.get(selectedAccount.email) || 0})`);
    
    return selectedAccount;
  } catch (error) {
    console.error('Error selecting next available account:', error);
    return null;
  }
}

// Get account statistics with better real-time data
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
    
    // Count real alias distribution
    const accountAliasDistribution = new Map();
    for (const [_, data] of aliasCache.entries()) {
      if (data.parentAccount) {
        const currentCount = accountAliasDistribution.get(data.parentAccount) || 0;
        accountAliasDistribution.set(data.parentAccount, currentCount + 1);
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
      accounts: accounts.map(account => ({
        id: account.id,
        email: account.email,
        status: account.status,
        aliasCount: account.alias_count,
        realAliasCount: accountAliasDistribution.get(account.email) || 0,
        userCount: accountUserCounts.get(account.email) || 0,
        quotaUsed: account.quota_used,
        lastUsed: account.last_used,
        hasActiveConnection: imapClients.has(account.email)
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
    maxSize: MAX_CACHE_SIZE,
    aliasCount: aliasCache.size,
    connectedClients: connectedClients.size,
    accountConnections: imapClients.size
  };
}

// Initialize account user counts on startup
export async function initializeImapService() {
  try {
    console.log('Initializing IMAP service...');
    
    // Get all active accounts from database
    const [accounts] = await pool.query(
      'SELECT * FROM gmail_accounts WHERE status = "active"'
    );
    
    console.log(`Found ${accounts.length} active Gmail accounts`);
    
    // Initialize account user counts
    for (const account of accounts) {
      accountUserCounts.set(account.email, 0);
      activeImapAccounts.add(account.email);
    }
    
    // Start the periodic DB update flush
    setInterval(flushPendingDbUpdates, DB_UPDATE_INTERVAL);
    
    // Start polling for all active accounts
    for (const account of accounts) {
      schedulePolling(account.email);
    }
    
    console.log('IMAP service initialized successfully');
    return true;
  } catch (error) {
    console.error('Failed to initialize IMAP service:', error);
    return false;
  }
}
