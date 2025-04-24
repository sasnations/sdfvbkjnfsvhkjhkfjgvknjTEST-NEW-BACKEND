/**
 * A simple in-memory store for temporary emails and received emails
 * This is used to quickly serve emails without hitting the database
 */
class EmailMemoryStore {
  constructor() {
    // Map of email address -> array of received emails
    this.emailStore = new Map();
    
    // Store statistics for monitoring
    this.stats = {
      totalEmails: 0,
      totalRecipients: 0,
      lastPurgeTime: Date.now()
    };
    
    // Purge old emails every hour to prevent memory leaks
    setInterval(() => this.purgeOldEmails(), 60 * 60 * 1000);
  }

  /**
   * Store a received email
   * @param {string} recipient - The recipient email address
   * @param {Object} email - The email object to store
   */
  storeEmail(recipient, email) {
    if (!this.emailStore.has(recipient)) {
      this.emailStore.set(recipient, []);
      this.stats.totalRecipients++;
    }
    
    // Add to the beginning of the array (newest first)
    const emails = this.emailStore.get(recipient);
    emails.unshift(email);
    
    // Keep a reasonable limit to prevent memory issues (100 emails per address)
    if (emails.length > 100) {
      emails.pop();
    }
    
    this.stats.totalEmails++;
    return email;
  }

  /**
   * Get all emails for a recipient
   * @param {string} recipient - The recipient email address
   * @returns {Array} - Array of emails or empty array if none found
   */
  getEmails(recipient) {
    return this.emailStore.get(recipient) || [];
  }

  /**
   * Remove old emails to prevent memory leaks
   * This keeps emails for 48 hours only
   */
  purgeOldEmails() {
    const now = Date.now();
    const TWO_DAYS_MS = 48 * 60 * 60 * 1000;
    let purgedCount = 0;
    
    for (const [recipient, emails] of this.emailStore.entries()) {
      const freshEmails = emails.filter(email => {
        // Keep emails less than 2 days old
        const emailTime = new Date(email.received_at).getTime();
        return (now - emailTime) < TWO_DAYS_MS;
      });
      
      purgedCount += emails.length - freshEmails.length;
      
      if (freshEmails.length === 0) {
        // Remove the recipient entirely if no emails are left
        this.emailStore.delete(recipient);
        this.stats.totalRecipients--;
      } else {
        this.emailStore.set(recipient, freshEmails);
      }
    }
    
    this.stats.totalEmails -= purgedCount;
    this.stats.lastPurgeTime = now;
    
    console.log(`Purged ${purgedCount} old emails from memory store`);
  }

  /**
   * Get stats about the memory store
   */
  getStats() {
    return {
      ...this.stats,
      recipientCount: this.emailStore.size,
      memoryUsageMB: process.memoryUsage().heapUsed / 1024 / 1024
    };
  }
}

// Create a singleton instance
const emailMemoryStore = new EmailMemoryStore();

export default emailMemoryStore; 