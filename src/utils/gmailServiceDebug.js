import { stores } from '../services/gmailService.js';

/**
 * Utility functions for debugging the Gmail service
 */

// Function to generate a debug report of all Gmail service memory stores
export function generateGmailDebugReport() {
  const { 
    gmailAccountsStore, 
    aliasToAccountMap, 
    userAliasMap,
    emailCache,
    gmailCredentialsStore 
  } = stores;
  
  const report = {
    timestamp: new Date().toISOString(),
    accounts: {
      count: gmailAccountsStore.size,
      details: []
    },
    aliases: {
      count: aliasToAccountMap.size,
      details: []
    },
    users: {
      count: userAliasMap.size,
      details: []
    },
    credentials: {
      count: gmailCredentialsStore.size,
      details: []
    },
    emailCache: {
      size: emailCache.size
    }
  };
  
  // Add account details
  for (const [email, account] of gmailAccountsStore.entries()) {
    report.accounts.details.push({
      email: email,
      status: account.status,
      aliasCount: account.aliases.length,
      lastUsed: new Date(account.lastUsed).toISOString(),
      quotaUsed: account.quotaUsed
    });
  }
  
  // Add alias mapping details
  for (const [alias, data] of aliasToAccountMap.entries()) {
    report.aliases.details.push({
      alias: alias,
      parentAccount: data.parentAccount,
      created: new Date(data.created).toISOString(),
      lastAccessed: new Date(data.lastAccessed).toISOString()
    });
  }
  
  // Add user alias details
  for (const [userId, aliases] of userAliasMap.entries()) {
    report.users.details.push({
      userId: userId,
      aliasCount: aliases.length,
      aliases: aliases
    });
  }
  
  // Add credential details (without secrets)
  for (const [id, cred] of gmailCredentialsStore.entries()) {
    report.credentials.details.push({
      id: id,
      active: cred.active,
      usageCount: cred.usageCount,
      lastUsed: cred.lastUsed,
      redirectUri: cred.redirectUri
    });
  }
  
  return report;
}

// Function to dump the Gmail debug report to the console
export function dumpGmailServiceStatus() {
  const report = generateGmailDebugReport();
  
  console.log('======= GMAIL SERVICE DEBUG REPORT =======');
  console.log(`Generated at: ${report.timestamp}`);
  console.log('\n--- ACCOUNTS ---');
  console.log(`Total accounts: ${report.accounts.count}`);
  console.table(report.accounts.details);
  
  console.log('\n--- ALIASES ---');
  console.log(`Total aliases: ${report.aliases.count}`);
  if (report.aliases.details.length > 20) {
    console.log(`Showing first 20 of ${report.aliases.details.length} aliases`);
    console.table(report.aliases.details.slice(0, 20));
  } else {
    console.table(report.aliases.details);
  }
  
  console.log('\n--- USERS ---');
  console.log(`Total users: ${report.users.count}`);
  console.table(report.users.details);
  
  console.log('\n--- CREDENTIALS ---');
  console.log(`Total credentials: ${report.credentials.count}`);
  console.table(report.credentials.details);
  
  console.log('\n--- EMAIL CACHE ---');
  console.log(`Cache size: ${report.emailCache.size}`);
  console.log('=========================================');
}

// Function to check the health of specific accounts
export function checkAccountHealth(accountEmail) {
  const { gmailAccountsStore } = stores;
  const account = gmailAccountsStore.get(accountEmail);
  
  if (!account) {
    console.error(`Account ${accountEmail} not found`);
    return {
      found: false,
      email: accountEmail
    };
  }
  
  return {
    found: true,
    email: accountEmail,
    status: account.status,
    aliasCount: account.aliases.length,
    tokenExpiry: account.expiresAt ? new Date(account.expiresAt).toISOString() : 'unknown',
    hasRefreshToken: !!account.refreshToken,
    lastUsed: new Date(account.lastUsed).toISOString(),
    quotaUsed: account.quotaUsed
  };
}

// Function to check all alias mappings for a specific user
export function checkUserAliases(userId) {
  const { userAliasMap, aliasToAccountMap } = stores;
  
  if (!userAliasMap.has(userId)) {
    return {
      found: false,
      userId,
      message: 'User has no aliases'
    };
  }
  
  const aliases = userAliasMap.get(userId);
  const details = aliases.map(alias => {
    const mapping = aliasToAccountMap.get(alias);
    return {
      alias,
      hasMapping: !!mapping,
      parentAccount: mapping ? mapping.parentAccount : 'unknown',
      created: mapping ? new Date(mapping.created).toISOString() : 'unknown',
      lastAccessed: mapping ? new Date(mapping.lastAccessed).toISOString() : 'unknown'
    };
  });
  
  return {
    found: true,
    userId,
    aliasCount: aliases.length,
    details
  };
}

// Function to find all aliases for an account
export function findAccountAliases(accountEmail) {
  const { aliasToAccountMap } = stores;
  
  const aliases = [];
  for (const [alias, data] of aliasToAccountMap.entries()) {
    if (data.parentAccount === accountEmail) {
      aliases.push({
        alias,
        created: new Date(data.created).toISOString(),
        lastAccessed: new Date(data.lastAccessed).toISOString()
      });
    }
  }
  
  return {
    email: accountEmail,
    aliasCount: aliases.length,
    aliases
  };
}

// Recovery functions
export function recoverFailedAccount(accountEmail) {
  const { gmailAccountsStore } = stores;
  const account = gmailAccountsStore.get(accountEmail);
  
  if (!account) {
    return {
      success: false,
      message: `Account ${accountEmail} not found`
    };
  }
  
  const oldStatus = account.status;
  account.status = 'active';
  gmailAccountsStore.set(accountEmail, account);
  
  return {
    success: true,
    email: accountEmail,
    oldStatus,
    newStatus: 'active',
    message: `Account ${accountEmail} recovered from ${oldStatus} status`
  };
}

// Manually reassign an alias to a specific account
export function reassignAlias(aliasEmail, targetAccountEmail) {
  const { 
    gmailAccountsStore, 
    aliasToAccountMap 
  } = stores;
  
  // Verify target account exists
  if (!gmailAccountsStore.has(targetAccountEmail)) {
    return {
      success: false,
      message: `Target account ${targetAccountEmail} not found`
    };
  }
  
  // Get the alias mapping
  const aliasMapping = aliasToAccountMap.get(aliasEmail);
  if (!aliasMapping) {
    return {
      success: false,
      message: `Alias ${aliasEmail} not found`
    };
  }
  
  // Get the current parent account
  const currentParentEmail = aliasMapping.parentAccount;
  const currentParentAccount = gmailAccountsStore.get(currentParentEmail);
  
  // Get the target account
  const targetAccount = gmailAccountsStore.get(targetAccountEmail);
  
  // Update alias mapping
  aliasMapping.parentAccount = targetAccountEmail;
  aliasMapping.lastAccessed = Date.now();
  aliasToAccountMap.set(aliasEmail, aliasMapping);
  
  // Remove from current parent account
  if (currentParentAccount) {
    currentParentAccount.aliases = currentParentAccount.aliases.filter(a => a !== aliasEmail);
    gmailAccountsStore.set(currentParentEmail, currentParentAccount);
  }
  
  // Add to target account
  targetAccount.aliases.push(aliasEmail);
  targetAccount.lastUsed = Date.now();
  gmailAccountsStore.set(targetAccountEmail, targetAccount);
  
  return {
    success: true,
    alias: aliasEmail,
    oldParent: currentParentEmail,
    newParent: targetAccountEmail,
    message: `Alias ${aliasEmail} reassigned from ${currentParentEmail} to ${targetAccountEmail}`
  };
}