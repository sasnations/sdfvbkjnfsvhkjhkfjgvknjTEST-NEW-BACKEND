// In-memory cache for storing temporary emails and received emails
class EmailCacheManager {
  constructor() {
    this.tempEmailsCache = new Map(); // Map of temp email id -> temp email object
    this.receivedEmailsCache = new Map(); // Map of temp email id -> array of received emails
    this.emailIdLookup = new Map(); // Map of email address -> temp email id (for faster lookups)
    
    // Cache statistics for monitoring
    this.stats = {
      tempEmailHits: 0,
      tempEmailMisses: 0,
      receivedEmailHits: 0,
      receivedEmailMisses: 0,
      lastPurge: Date.now()
    };
    
    // Purge expired emails every hour to prevent memory leaks
    setInterval(() => this.purgeExpiredEmails(), 60 * 60 * 1000);
  }

  // Store a temporary email in cache
  addTempEmail(tempEmail) {
    this.tempEmailsCache.set(tempEmail.id, tempEmail);
    this.emailIdLookup.set(tempEmail.email, tempEmail.id);
    
    // Initialize an empty array for received emails for this temp email
    if (!this.receivedEmailsCache.has(tempEmail.id)) {
      this.receivedEmailsCache.set(tempEmail.id, []);
    }
    
    return tempEmail;
  }

  // Get temp email by id
  getTempEmailById(id) {
    const email = this.tempEmailsCache.get(id);
    if (email) {
      this.stats.tempEmailHits++;
      return email;
    }
    this.stats.tempEmailMisses++;
    return null;
  }

  // Get temp email by email address
  getTempEmailByAddress(email) {
    const id = this.emailIdLookup.get(email);
    if (id) {
      return this.getTempEmailById(id);
    }
    this.stats.tempEmailMisses++;
    return null;
  }

  // Add received email to cache
  addReceivedEmail(tempEmailId, receivedEmail) {
    if (!this.receivedEmailsCache.has(tempEmailId)) {
      this.receivedEmailsCache.set(tempEmailId, []);
    }
    
    // Add to the beginning of the array (newest first)
    const emails = this.receivedEmailsCache.get(tempEmailId);
    emails.unshift(receivedEmail);
    
    // Keep a reasonable limit (e.g., 100 emails per temp email)
    if (emails.length > 100) {
      emails.pop();
    }
    
    return receivedEmail;
  }

  // Get received emails for a temp email
  getReceivedEmails(tempEmailId, page = 1, limit = 10) {
    if (!this.receivedEmailsCache.has(tempEmailId)) {
      this.stats.receivedEmailMisses++;
      return null;
    }
    
    this.stats.receivedEmailHits++;
    const emails = this.receivedEmailsCache.get(tempEmailId);
    
    // Calculate pagination
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;
    
    return {
      data: emails.slice(startIndex, endIndex),
      metadata: {
        total: emails.length,
        page: page,
        limit: limit,
        pages: Math.ceil(emails.length / limit)
      }
    };
  }

  // Remove a temp email and its received emails from cache
  removeTempEmail(tempEmailId) {
    const tempEmail = this.tempEmailsCache.get(tempEmailId);
    if (tempEmail) {
      this.emailIdLookup.delete(tempEmail.email);
    }
    
    this.tempEmailsCache.delete(tempEmailId);
    this.receivedEmailsCache.delete(tempEmailId);
  }

  // Remove a specific received email
  removeReceivedEmail(tempEmailId, receivedEmailId) {
    if (!this.receivedEmailsCache.has(tempEmailId)) {
      return false;
    }
    
    const emails = this.receivedEmailsCache.get(tempEmailId);
    const filteredEmails = emails.filter(email => email.id !== receivedEmailId);
    
    if (filteredEmails.length !== emails.length) {
      this.receivedEmailsCache.set(tempEmailId, filteredEmails);
      return true;
    }
    
    return false;
  }

  // Purge expired emails from cache
  purgeExpiredEmails() {
    const now = new Date();
    let purgedCount = 0;
    
    // Purge expired temp emails
    for (const [id, email] of this.tempEmailsCache.entries()) {
      if (new Date(email.expires_at) < now) {
        this.removeTempEmail(id);
        purgedCount++;
      }
    }
    
    this.stats.lastPurge = Date.now();
    console.log(`Purged ${purgedCount} expired emails from cache`);
    return purgedCount;
  }

  // Get cache stats
  getStats() {
    return {
      ...this.stats,
      tempEmailCacheSize: this.tempEmailsCache.size,
      receivedEmailCacheSize: this.receivedEmailsCache.size,
      emailLookupCacheSize: this.emailIdLookup.size,
      memoryUsageMB: process.memoryUsage().heapUsed / 1024 / 1024
    };
  }
}

// Create a singleton instance
const emailCacheManager = new EmailCacheManager();

export default emailCacheManager; 