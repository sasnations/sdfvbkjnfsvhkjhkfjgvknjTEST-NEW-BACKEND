import { google } from 'googleapis';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

// In-memory storage
const gmailAccountsStore = new Map(); // Stores Gmail account credentials and tokens
const aliasToAccountMap = new Map(); // Maps email aliases to parent Gmail accounts
const userAliasMap = new Map(); // Maps users to their assigned aliases
const emailCache = new Map(); // Cache for fetched emails
const gmailCredentialsStore = new Map(); // Stores Gmail API credentials

// Configuration
const MAX_CACHE_SIZE = 10000; // Maximum number of emails to cache
const ALIAS_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds

// Constants
const GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'];
const POLLING_INTERVALS = {
  high: 10000,    // 10 seconds
  medium: 30000,  // 30 seconds
  low: 60000      // 60 seconds
};

// Encryption utilities for token security
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

// OAuth client setup
function getOAuthClient(specificCredential = null) {
  let credential;
  
  if (specificCredential) {
    // Use the specified credential
    credential = specificCredential;
  } else {
    // Get the next available credential using round-robin
    credential = getNextAvailableCredential();
    
    if (!credential) {
      // Fallback to environment variables if no credentials in store
      return new google.auth.OAuth2(
        process.env.GMAIL_CLIENT_ID,
        process.env.GMAIL_CLIENT_SECRET,
        process.env.GMAIL_REDIRECT_URI
      );
    }
  }
  
  return new google.auth.OAuth2(
    credential.clientId,
    credential.clientSecret,
    credential.redirectUri
  );
}

// Get the next available Gmail credential using round-robin with status check
function getNextAvailableCredential() {
  // Get all active credentials
  const activeCredentials = [...gmailCredentialsStore.values()]
    .filter(cred => cred.active)
    .sort((a, b) => a.usageCount - b.usageCount);
  
  if (activeCredentials.length === 0) {
    return null;
  }
  
  // Get the least used credential
  const credential = activeCredentials[0];
  
  // Update usage stats
  credential.usageCount += 1;
  credential.lastUsed = new Date().toISOString();
  gmailCredentialsStore.set(credential.id, credential);
  
  return credential;
}

// Gmail Account Management
export async function addGmailAccount(code) {
  const oauth2Client = getOAuthClient();
  
  try {
    // Exchange authorization code for tokens
    const { tokens } = await oauth2Client.getToken(code);
    
    // Set credentials to get user info
    oauth2Client.setCredentials(tokens);
    
    // Get Gmail profile to identify the email
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
    const profile = await gmail.users.getProfile({ userId: 'me' });
    
    const email = profile.data.emailAddress;
    
    // Store account in memory with encrypted refresh token
    gmailAccountsStore.set(email, {
      email,
      refreshToken: tokens.refresh_token ? encrypt(tokens.refresh_token) : null,
      accessToken: tokens.access_token,
      expiresAt: Date.now() + (tokens.expires_in * 1000),
      quotaUsed: 0,
      lastUsed: Date.now(),
      aliases: [],
      status: 'active'
    });
    
    console.log(`Added Gmail account: ${email}`);
    
    // Start polling for this account
    schedulePolling(email);
    
    return { email };
  } catch (error) {
    console.error('Failed to add Gmail account:', error);
    throw new Error('Failed to authenticate with Gmail');
  }
}

// Get or refresh access token
export async function getValidAccessToken(accountEmail) {
  const account = gmailAccountsStore.get(accountEmail);
  
  if (!account) {
    throw new Error('Gmail account not found');
  }
  
  // Check if token is still valid
  if (account.accessToken && account.expiresAt > Date.now()) {
    return account.accessToken;
  }
  
  // Refresh the token
  try {
    const oauth2Client = getOAuthClient();
    const refreshToken = decrypt(account.refreshToken);
    
    oauth2Client.setCredentials({ refresh_token: refreshToken });
    const { credentials } = await oauth2Client.refreshAccessToken();
    
    // Update account with new tokens
    account.accessToken = credentials.access_token;
    account.expiresAt = Date.now() + (credentials.expires_in * 1000);
    gmailAccountsStore.set(accountEmail, account);
    
    return account.accessToken;
  } catch (error) {
    console.error('Failed to refresh access token:', error);
    account.status = 'error';
    gmailAccountsStore.set(accountEmail, account);
    throw new Error('Failed to refresh access token');
  }
}

// Alias Generation
export async function generateGmailAlias(userId, strategy = 'dot') {
  // Get next available account
  const account = getNextAvailableAccount();
  
  if (!account) {
    console.error('No Gmail accounts available. Current accounts:', [...gmailAccountsStore.keys()]);
    throw new Error('No Gmail accounts available');
  }
  
  // Generate unique alias based on strategy
  const alias = strategy === 'dot' 
    ? generateDotAlias(account.email)
    : generatePlusAlias(account.email);
  
  // Map alias to account and user
  aliasToAccountMap.set(alias, {
    parentAccount: account.email,
    created: Date.now(),
    lastAccessed: Date.now()
  });
  
  // Add alias to user's list
  if (!userAliasMap.has(userId)) {
    userAliasMap.set(userId, []);
  }
  userAliasMap.get(userId).push(alias);
  
  // Add alias to account
  account.aliases.push(alias);
  account.lastUsed = Date.now();
  gmailAccountsStore.set(account.email, account);
  
  return { alias };
}

function generateDotAlias(email) {
  // Extract username and domain
  const [username, domain] = email.split('@');
  
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

function generatePlusAlias(email) {
  // Extract username and domain
  const [username, domain] = email.split('@');
  
  // Add random tag
  const tag = Math.random().toString(36).substring(2, 8);
  
  return `${username}+${tag}@${domain}`;
}

// Email Fetching
export async function fetchGmailEmails(userId, aliasEmail) {
  // Get alias mapping
  const aliasMapping = aliasToAccountMap.get(aliasEmail);
  
  if (!aliasMapping) {
    throw new Error('Alias not found');
  }
  
  // Update last accessed timestamp
  aliasMapping.lastAccessed = Date.now();
  aliasToAccountMap.set(aliasEmail, aliasMapping);
  
  // Check if user owns this alias
  if (!userAliasMap.has(userId) || !userAliasMap.get(userId).includes(aliasEmail)) {
    throw new Error('Unauthorized access to alias');
  }
  
  // Get account for this alias
  const account = gmailAccountsStore.get(aliasMapping.parentAccount);
  
  if (!account || account.status !== 'active') {
    throw new Error('Gmail account unavailable');
  }
  
  // Get cached emails first
  const cachedEmails = [];
  for (const [key, email] of emailCache.entries()) {
    if (key.startsWith(`${aliasEmail}:`)) {
      cachedEmails.push(email);
    }
  }
  
  // Return cached emails sorted by date (newest first)
  return cachedEmails.sort((a, b) => 
    new Date(b.internalDate) - new Date(a.internalDate)
  );
}

// Email Polling (Background Task)
async function pollForNewEmails(accountEmail) {
  const account = gmailAccountsStore.get(accountEmail);
  
  if (!account || account.status !== 'active' || account.aliases.length === 0) {
    return;
  }
  
  try {
    // Get fresh access token
    const accessToken = await getValidAccessToken(accountEmail);
    
    // Initialize Gmail API client
    const oauth2Client = getOAuthClient();
    oauth2Client.setCredentials({ access_token: accessToken });
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
    
    // Fetch emails for all aliases associated with this account
    for (const alias of account.aliases) {
      // Build query to get recent emails sent to this alias
      const query = `to:${alias} newer_than:10m`;
      
      try {
        // List messages matching query
        const response = await gmail.users.messages.list({
          userId: 'me',
          q: query,
          maxResults: 10
        });
        
        const messages = response.data.messages || [];
        
        // Fetch full message details for each message
        for (const message of messages) {
          // Check if already in cache
          const cacheKey = `${alias}:${message.id}`;
          
          if (!emailCache.has(cacheKey)) {
            // Fetch full message
            const fullMessage = await gmail.users.messages.get({
              userId: 'me',
              id: message.id,
              format: 'full'
            });
            
            // Process message to extract headers, body, etc.
            const processedEmail = processGmailMessage(fullMessage.data, alias);
            
            // Add to cache
            addToEmailCache(cacheKey, processedEmail);
          }
        }
      } catch (error) {
        console.error(`Error fetching emails for alias ${alias}:`, error);
      }
    }
    
    // Update account metrics
    account.lastPolled = Date.now();
    account.quotaUsed += 1;
    gmailAccountsStore.set(accountEmail, account);
    
  } catch (error) {
    console.error(`Error polling Gmail account ${accountEmail}:`, error);
    
    // Update account status based on error
    if (error.message.includes('quota') || error.message.includes('rate limit')) {
      account.status = 'rate-limited';
    } else if (error.message.includes('auth') || error.message.includes('token')) {
      account.status = 'auth-error';
    } else {
      account.status = 'error';
    }
    
    gmailAccountsStore.set(accountEmail, account);
  }
}

function schedulePolling(accountEmail) {
  const account = gmailAccountsStore.get(accountEmail);
  
  if (!account || account.status !== 'active') {
    return;
  }
  
  // Determine polling interval based on activity
  let interval = POLLING_INTERVALS.low;
  
  // More active accounts get polled more frequently
  if (account.aliases.length > 10) {
    interval = POLLING_INTERVALS.high;
  } else if (account.aliases.length > 5) {
    interval = POLLING_INTERVALS.medium;
  }
  
  // Schedule next poll
  setTimeout(() => {
    pollForNewEmails(accountEmail)
      .finally(() => schedulePolling(accountEmail));
  }, interval);
}

// Process Gmail message into standardized format
function processGmailMessage(message, recipientAlias) {
  // Extract headers
  const headers = {};
  message.payload.headers.forEach(header => {
    headers[header.name.toLowerCase()] = header.value;
  });
  
  // Extract body
  let bodyHtml = '';
  let bodyText = '';
  
  // Process parts recursively to find the body
  function processMessageParts(parts) {
    if (!parts) return;
    
    for (const part of parts) {
      if (part.mimeType === 'text/html' && part.body.data) {
        bodyHtml = Buffer.from(part.body.data, 'base64').toString('utf-8');
      } else if (part.mimeType === 'text/plain' && part.body.data) {
        bodyText = Buffer.from(part.body.data, 'base64').toString('utf-8');
      }
      
      if (part.parts) {
        processMessageParts(part.parts);
      }
    }
  }
  
  if (message.payload.parts) {
    processMessageParts(message.payload.parts);
  } else if (message.payload.body && message.payload.body.data) {
    // Handle single-part messages
    if (message.payload.mimeType === 'text/html') {
      bodyHtml = Buffer.from(message.payload.body.data, 'base64').toString('utf-8');
    } else {
      bodyText = Buffer.from(message.payload.body.data, 'base64').toString('utf-8');
    }
  }
  
  // Extract attachments
  const attachments = [];
  
  // Format the processed email
  return {
    id: message.id,
    threadId: message.threadId,
    labelIds: message.labelIds,
    from: headers.from,
    to: headers.to,
    subject: headers.subject || '(No Subject)',
    bodyHtml,
    bodyText,
    internalDate: new Date(parseInt(message.internalDate)).toISOString(),
    timestamp: Date.now(),
    snippet: message.snippet,
    recipientAlias,
    attachments
  };
}

// Cache Management
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

// Alias Management
export function cleanupInactiveAliases() {
  const now = Date.now();
  
  for (const [alias, data] of aliasToAccountMap.entries()) {
    if (now - data.lastAccessed > ALIAS_TTL) {
      // Remove alias from mapping
      aliasToAccountMap.delete(alias);
      
      // Remove from parent account's alias list
      const account = gmailAccountsStore.get(data.parentAccount);
      if (account) {
        account.aliases = account.aliases.filter(a => a !== alias);
        gmailAccountsStore.set(data.parentAccount, account);
      }
      
      // Remove from user's alias list
      for (const [userId, aliases] of userAliasMap.entries()) {
        if (aliases.includes(alias)) {
          userAliasMap.set(userId, aliases.filter(a => a !== alias));
          break;
        }
      }
    }
  }
}

// Load Balancing
function getNextAvailableAccount() {
  // Get all active accounts
  const availableAccounts = [...gmailAccountsStore.values()]
    .filter(account => account.status === 'active')
    .sort((a, b) => {
      // Primary sort: quota usage
      if (a.quotaUsed !== b.quotaUsed) {
        return a.quotaUsed - b.quotaUsed;
      }
      // Secondary sort: number of aliases
      if (a.aliases.length !== b.aliases.length) {
        return a.aliases.length - b.aliases.length;
      }
      // Tertiary sort: last used timestamp
      return a.lastUsed - b.lastUsed;
    });
  
  if (availableAccounts.length === 0) {
    console.log('No available Gmail accounts found. Current accounts:', [...gmailAccountsStore.entries()].map(([email, acc]) => ({
      email,
      status: acc.status,
      aliasCount: acc.aliases.length
    })));
    return null;
  }
  
  return availableAccounts[0];
}

// User Alias Management
export function getUserAliases(userId) {
  return userAliasMap.get(userId) || [];
}

export function rotateUserAlias(userId) {
  // Delete current alias
  const currentAliases = userAliasMap.get(userId) || [];
  
  // Generate a new alias for the user
  return generateGmailAlias(userId);
}

// Credential Management
export async function addGmailCredential(credential) {
  const id = uuidv4();
  
  const newCredential = {
    ...credential,
    id,
    usageCount: 0,
    lastUsed: new Date().toISOString(),
    active: true // Default to active
  };
  
  gmailCredentialsStore.set(id, newCredential);
  
  return { ...newCredential, clientSecret: '***********' }; // Don't return the actual secret
}

export async function updateGmailCredential(id, updates) {
  const credential = gmailCredentialsStore.get(id);
  
  if (!credential) {
    throw new Error('Credential not found');
  }
  
  const updatedCredential = {
    ...credential,
    ...updates
  };
  
  gmailCredentialsStore.set(id, updatedCredential);
  
  return { ...updatedCredential, clientSecret: '***********' };
}

export async function deleteGmailCredential(id) {
  if (!gmailCredentialsStore.has(id)) {
    throw new Error('Credential not found');
  }
  
  gmailCredentialsStore.delete(id);
}

export async function updateGmailCredentialStatus(id, active) {
  const credential = gmailCredentialsStore.get(id);
  
  if (!credential) {
    throw new Error('Credential not found');
  }
  
  credential.active = active;
  gmailCredentialsStore.set(id, credential);
}

export async function getGmailCredentials() {
  return [...gmailCredentialsStore.values()].map(cred => ({
    ...cred,
    clientSecret: '***********' // Don't return the actual secrets
  }));
}

// Setup periodic cleanup task
setInterval(cleanupInactiveAliases, 3600000); // Run every hour

// Initialize OAuth URL generator
export function getAuthUrl(credentialId = null) {
  let oauth2Client;
  
  if (credentialId) {
    const credential = gmailCredentialsStore.get(credentialId);
    if (!credential) {
      throw new Error('Credential not found');
    }
    oauth2Client = getOAuthClient(credential);
  } else {
    oauth2Client = getOAuthClient();
  }
  
  return oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: GMAIL_SCOPES,
    prompt: 'consent' // Force to get refresh token
  });
}

// Admin functions
export function getGmailAccountStats() {
  const stats = {
    totalAccounts: gmailAccountsStore.size,
    totalAliases: aliasToAccountMap.size,
    totalUsers: userAliasMap.size,
    accounts: []
  };
  
  for (const [email, account] of gmailAccountsStore.entries()) {
    stats.accounts.push({
      email,
      status: account.status,
      aliasCount: account.aliases.length,
      quotaUsed: account.quotaUsed,
      lastUsed: account.lastUsed
    });
  }
  
  return stats;
}

export function getEmailCacheStats() {
  return {
    size: emailCache.size,
    maxSize: MAX_CACHE_SIZE
  };
}

// Export for testing and monitoring
export const stores = {
  gmailAccountsStore,
  aliasToAccountMap,
  userAliasMap,
  emailCache,
  gmailCredentialsStore
};

// Public API for creating Gmail aliases without authentication
export async function createPublicGmailAlias(strategy = 'dot') {
  // Generate a random user ID for public users
  const publicUserId = `public_${Math.random().toString(36).substring(2, 15)}`;
  
  try {
    // Use the same function as authenticated users
    return await generateGmailAlias(publicUserId, strategy);
  } catch (error) {
    console.error('Failed to create public Gmail alias:', error);
    throw error;
  }
}
