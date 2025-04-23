// Cache Manager Service
// This service provides a centralized caching mechanism for the application

class CacheManager {
  constructor() {
    // Main cache storage
    this.cache = new Map();
    
    // TTL settings for different cache types (in milliseconds)
    this.ttlSettings = {
      domains: 30 * 60 * 1000, // 30 minutes
      tempEmails: 5 * 60 * 1000, // 5 minutes
      receivedEmails: 2 * 60 * 1000, // 2 minutes
      blogPosts: 15 * 60 * 1000, // 15 minutes
      blogCategories: 60 * 60 * 1000, // 1 hour
      messages: 10 * 60 * 1000, // 10 minutes
      stats: 5 * 60 * 1000, // 5 minutes
      users: 15 * 60 * 1000, // 15 minutes
      default: 10 * 60 * 1000 // 10 minutes default
    };
    
    // Cache statistics
    this.stats = {
      hits: 0,
      misses: 0,
      sets: 0,
      invalidations: 0,
      lastCleanup: Date.now()
    };
    
    // Set up automatic cache cleanup
    this.setupCleanupInterval();
    
    console.log('Cache manager initialized');
  }
  
  // Get TTL for a specific cache type
  getTTL(type) {
    return this.ttlSettings[type] || this.ttlSettings.default;
  }
  
  // Set up automatic cache cleanup interval
  setupCleanupInterval() {
    // Run cleanup every 10 minutes
    const interval = 10 * 60 * 1000;
    
    setInterval(() => {
      this.cleanup();
    }, interval);
  }
  
  // Generate cache key
  generateKey(type, identifier, params = {}) {
    // Convert params object to a stable string representation
    const paramsStr = Object.entries(params)
      .sort(([keyA], [keyB]) => keyA.localeCompare(keyB))
      .map(([key, value]) => `${key}:${JSON.stringify(value)}`)
      .join('|');
      
    return `${type}:${identifier}${paramsStr ? `:${paramsStr}` : ''}`;
  }
  
  // Get item from cache
  get(type, identifier, params = {}) {
    const key = this.generateKey(type, identifier, params);
    const item = this.cache.get(key);
    
    if (!item) {
      this.stats.misses++;
      return null;
    }
    
    // Check if item has expired
    if (Date.now() > item.expiresAt) {
      this.cache.delete(key);
      this.stats.misses++;
      return null;
    }
    
    this.stats.hits++;
    return item.data;
  }
  
  // Set item in cache
  set(type, identifier, data, params = {}, customTTL = null) {
    const key = this.generateKey(type, identifier, params);
    const ttl = customTTL || this.getTTL(type);
    
    this.cache.set(key, {
      data,
      createdAt: Date.now(),
      expiresAt: Date.now() + ttl,
      type,
      identifier,
      params
    });
    
    this.stats.sets++;
    return data;
  }
  
  // Delete specific item from cache
  delete(type, identifier, params = {}) {
    const key = this.generateKey(type, identifier, params);
    return this.cache.delete(key);
  }
  
  // Invalidate all items of a specific type
  invalidateType(type) {
    let count = 0;
    
    for (const [key, item] of this.cache.entries()) {
      if (item.type === type) {
        this.cache.delete(key);
        count++;
      }
    }
    
    if (count > 0) {
      this.stats.invalidations += count;
      console.log(`Invalidated ${count} cache entries of type: ${type}`);
    }
    
    return count;
  }
  
  // Invalidate all items related to a specific identifier across all types
  invalidateIdentifier(identifier) {
    let count = 0;
    
    for (const [key, item] of this.cache.entries()) {
      if (item.identifier === identifier) {
        this.cache.delete(key);
        count++;
      }
    }
    
    if (count > 0) {
      this.stats.invalidations += count;
      console.log(`Invalidated ${count} cache entries for identifier: ${identifier}`);
    }
    
    return count;
  }
  
  // Clear entire cache
  clear() {
    const size = this.cache.size;
    this.cache.clear();
    this.stats.invalidations += size;
    console.log(`Cleared entire cache (${size} entries)`);
    return size;
  }
  
  // Cleanup expired items
  cleanup() {
    const now = Date.now();
    let count = 0;
    
    for (const [key, item] of this.cache.entries()) {
      if (now > item.expiresAt) {
        this.cache.delete(key);
        count++;
      }
    }
    
    this.stats.lastCleanup = now;
    
    if (count > 0) {
      console.log(`Cache cleanup: removed ${count} expired entries`);
    }
    
    return count;
  }
  
  // Get cache statistics
  getStats() {
    return {
      ...this.stats,
      size: this.cache.size,
      types: this.getTypeStats(),
      memoryUsage: this.estimateMemoryUsage()
    };
  }
  
  // Get statistics by cache type
  getTypeStats() {
    const typeStats = {};
    
    for (const [_, item] of this.cache.entries()) {
      if (!typeStats[item.type]) {
        typeStats[item.type] = 0;
      }
      typeStats[item.type]++;
    }
    
    return typeStats;
  }
  
  // Estimate memory usage (rough approximation)
  estimateMemoryUsage() {
    let totalSize = 0;
    
    for (const [key, item] of this.cache.entries()) {
      // Estimate key size (2 bytes per character)
      totalSize += key.length * 2;
      
      // Estimate data size using JSON stringification
      try {
        totalSize += JSON.stringify(item.data).length * 2;
      } catch (e) {
        // If data can't be stringified, make a rough estimate
        totalSize += 1000;
      }
      
      // Add fixed overhead for each cache entry (timestamps, etc.)
      totalSize += 100;
    }
    
    return {
      bytes: totalSize,
      kilobytes: Math.round(totalSize / 1024),
      megabytes: (totalSize / (1024 * 1024)).toFixed(2)
    };
  }
}

// Create singleton instance
const cacheManager = new CacheManager();

export default cacheManager;