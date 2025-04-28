import { pool } from '../db/init.js';
import { stores } from '../services/gmailService.js';

/**
 * Utility functions for debugging the Gmail service
 */

// Function to generate a debug report of all Gmail service memory stores
export async function generateGmailDebugReport() {
  const { 
    emailCache,
    aliasCache
  } = stores;
  
  // Fetch accounts from database
  const [accounts] = await pool.query(`
    SELECT 
      id, email, status, quota_used, alias_count, last_used, created_at, updated_at
    FROM gmail_accounts
    ORDER BY last_used DESC
  `);
  
  // Fetch credentials from database
  const [credentials] = await pool.query(`
    SELECT 
      id, client_id, redirect_uri, active, usage_count, last_used, created_at, updated_at
    FROM gmail_credentials
    ORDER BY last_used DESC
  `);
  
  const report = {
    timestamp: new Date().toISOString(),
    accounts: {
      count: accounts.length,
      details: accounts.map(account => ({
        id: account.id,
        email: account.email,
        status: account.status,
        aliasCount: account.alias_count,
        lastUsed: account.last_used,
        quotaUsed: account.quota_used,
        created: account.created_at
      }))
    },
    aliases: {
      count: aliasCache.size,
      databaseCount: 0,
      memoryCacheCount: aliasCache.size,
      details: [...aliasCache.entries()].slice(0, 20).map(([alias, data]) => ({
        alias,
        parentAccount: data.parentAccount,
        userId: data.userId,
        created: new Date(data.created).toISOString(),
        lastAccessed: new Date(data.lastAccessed).toISOString(),
        expires: data.expires ? new Date(data.expires).toISOString() : null
      }))
    },
    credentials: {
      count: credentials.length,
      details: credentials.map(cred => ({
        id: cred.id,
        active: cred.active,
        usageCount: cred.usage_count,
        lastUsed: cred.last_used,
        redirectUri: cred.redirect_uri
      }))
    },
    emailCache: {
      size: emailCache.size
    }
  };
  
  return report;
}

// Function to dump the Gmail debug report to the console
export async function dumpGmailServiceStatus() {
  const report = await generateGmailDebugReport();
  
  console.log('======= GMAIL SERVICE DEBUG REPORT =======');
  console.log(`Generated at: ${report.timestamp}`);
  console.log('\n--- ACCOUNTS ---');
  console.log(`Total accounts: ${report.accounts.count}`);
  console.table(report.accounts.details);
  
  console.log('\n--- ALIASES ---');
  console.log(`Total aliases: ${report.aliases.count} (Memory: ${report.aliases.memoryCacheCount})`);
  if (report.aliases.details.length > 0) {
    console.table(report.aliases.details);
  } else {
    console.log('No aliases found');
  }
  
  console.log('\n--- CREDENTIALS ---');
  console.log(`Total credentials: ${report.credentials.count}`);
  console.table(report.credentials.details);
  
  console.log('\n--- EMAIL CACHE ---');
  console.log(`Cache size: ${report.emailCache.size}`);
  console.log('=========================================');
  
  return report;
}

// Function to check the health of specific accounts
export async function checkAccountHealth(accountEmail) {
  try {
    // Get account details from database
    const [accounts] = await pool.query(
      'SELECT * FROM gmail_accounts WHERE email = ?',
      [accountEmail]
    );
    
    if (accounts.length === 0) {
      console.error(`Account ${accountEmail} not found`);
      return {
        found: false,
        email: accountEmail
      };
    }
    
    const account = accounts[0];
    
    // Check if account has refresh token
    const hasRefreshToken = !!account.refresh_token;
    
    // Count aliases from in-memory cache
    let aliasCount = 0;
    for (const data of stores.aliasCache.values()) {
      if (data.parentAccount === accountEmail) {
        aliasCount++;
      }
    }
    
    return {
      found: true,
      id: account.id,
      email: account.email,
      status: account.status,
      aliasCount: aliasCount,
      inMemoryAliases: aliasCount,
      databaseAliasCount: account.alias_count,
      tokenExpiry: account.expires_at ? new Date(parseInt(account.expires_at)).toISOString() : 'unknown',
      hasRefreshToken,
      lastUsed: new Date(account.last_used).toISOString(),
      quotaUsed: account.quota_used
    };
  } catch (error) {
    console.error(`Error checking account health: ${error.message}`);
    throw error;
  }
}

// Function to check all alias mappings for a specific user
export async function checkUserAliases(userId) {
  try {
    // Count aliases from in-memory cache
    const userAliases = [];
    for (const [alias, data] of stores.aliasCache.entries()) {
      if (data.userId === userId) {
        userAliases.push({
          alias,
          parentAccount: data.parentAccount,
          created: new Date(data.created).toISOString(),
          lastAccessed: new Date(data.lastAccessed).toISOString()
        });
      }
    }
    
    return {
      found: userAliases.length > 0,
      userId,
      aliasCount: userAliases.length,
      details: userAliases
    };
  } catch (error) {
    console.error(`Error checking user aliases: ${error.message}`);
    throw error;
  }
}

// Function to find all aliases for an account
export async function findAccountAliases(accountEmail) {
  try {
    // Count aliases from in-memory cache
    const aliases = [];
    for (const [alias, data] of stores.aliasCache.entries()) {
      if (data.parentAccount === accountEmail) {
        aliases.push({
          alias,
          userId: data.userId,
          created: new Date(data.created).toISOString(),
          lastAccessed: new Date(data.lastAccessed).toISOString()
        });
      }
    }
    
    return {
      email: accountEmail,
      found: aliases.length > 0,
      aliasCount: aliases.length,
      aliases
    };
  } catch (error) {
    console.error(`Error finding account aliases: ${error.message}`);
    throw error;
  }
}

// Recovery functions
export async function recoverFailedAccount(accountEmail) {
  try {
    // Get account details
    const [accounts] = await pool.query(
      'SELECT * FROM gmail_accounts WHERE email = ?',
      [accountEmail]
    );
    
    if (accounts.length === 0) {
      return {
        success: false,
        message: `Account ${accountEmail} not found`
      };
    }
    
    const account = accounts[0];
    const oldStatus = account.status;
    
    // Update status to active
    await pool.query(
      'UPDATE gmail_accounts SET status = \'active\', updated_at = NOW() WHERE id = ?',
      [account.id]
    );
    
    return {
      success: true,
      email: accountEmail,
      oldStatus,
      newStatus: 'active',
      message: `Account ${accountEmail} recovered from ${oldStatus} status`
    };
  } catch (error) {
    console.error(`Error recovering account: ${error.message}`);
    throw error;
  }
}

// Manually reassign an alias to a specific account
export async function reassignAlias(aliasEmail, targetAccountEmail) {
  try {
    // Verify target account exists
    const [targetAccounts] = await pool.query(
      'SELECT id, email FROM gmail_accounts WHERE email = ?',
      [targetAccountEmail]
    );
    
    if (targetAccounts.length === 0) {
      return {
        success: false,
        message: `Target account ${targetAccountEmail} not found`
      };
    }
    
    const targetAccount = targetAccounts[0];
    
    // Get the alias mapping from memory
    if (!stores.aliasCache.has(aliasEmail)) {
      return {
        success: false,
        message: `Alias ${aliasEmail} not found in memory cache`
      };
    }
    
    const aliasData = stores.aliasCache.get(aliasEmail);
    const oldParentAccount = aliasData.parentAccount;
    
    // Update in-memory cache
    aliasData.parentAccount = targetAccountEmail;
    aliasData.parentAccountId = targetAccount.id;
    aliasData.lastAccessed = Date.now();
    stores.aliasCache.set(aliasEmail, aliasData);
    
    // Update account alias counts in database
    // Decrement old parent account's alias count
    if (aliasData.parentAccountId) {
      await pool.query(
        'UPDATE gmail_accounts SET alias_count = GREATEST(0, alias_count - 1), updated_at = NOW() WHERE id = ?',
        [aliasData.parentAccountId]
      );
    }
    
    // Increment new parent account's alias count
    await pool.query(
      'UPDATE gmail_accounts SET alias_count = alias_count + 1, last_used = NOW(), updated_at = NOW() WHERE id = ?',
      [targetAccount.id]
    );
    
    return {
      success: true,
      alias: aliasEmail,
      oldParent: oldParentAccount,
      newParent: targetAccountEmail,
      message: `Alias ${aliasEmail} reassigned from ${oldParentAccount} to ${targetAccountEmail}`
    };
  } catch (error) {
    console.error(`Error reassigning alias: ${error.message}`);
    throw error;
  }
}
