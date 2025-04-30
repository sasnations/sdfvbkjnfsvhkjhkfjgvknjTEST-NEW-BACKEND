import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import { authenticateToken, requireAdmin, authenticateMasterPassword } from '../middleware/auth.js';
import { 
  addGmailAccount, 
  generateGmailAlias, 
  fetchGmailEmails, 
  getUserAliases,
  rotateUserAlias,
  getGmailAccountStats,
  getEmailCacheStats,
  initializeImapService
} from '../services/gmailImapService.js';

const router = express.Router();

// Initialize IMAP service when the server starts
initializeImapService().catch(error => {
  console.error('Failed to initialize IMAP service:', error);
});

// ==================== User Routes ====================

// Create a new Gmail alias
router.post('/create', async (req, res) => {
  try {
    // Allow both authenticated and unauthenticated users
    const userId = req.user?.id || `anon_${uuidv4()}`;
    const { strategy, domain } = req.body; // 'dot' or 'plus', 'gmail.com' or 'googlemail.com'
    
    const result = await generateGmailAlias(
      userId, 
      strategy || 'dot', 
      domain || 'gmail.com'
    );
    
    res.json(result);
  } catch (error) {
    console.error('Failed to create Gmail alias:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to create Gmail alias',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Get all Gmail aliases for the user
router.get('/aliases', async (req, res) => {
  try {
    // Allow both authenticated and unauthenticated users
    const userId = req.user?.id || req.query.userId || `anon_${uuidv4()}`;
    const aliases = await getUserAliases(userId);
    
    res.json({ aliases });
  } catch (error) {
    console.error('Failed to fetch Gmail aliases:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to fetch Gmail aliases',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Fetch emails for a specific alias
router.get('/:alias/emails', async (req, res) => {
  try {
    // Allow both authenticated and unauthenticated users
    const userId = req.user?.id || req.query.userId || `anon_${uuidv4()}`;
    const { alias } = req.params;
    
    const emails = await fetchGmailEmails(userId, alias);
    
    res.json({ emails });
  } catch (error) {
    console.error('Failed to fetch emails:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to fetch emails',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Rotate to a new Gmail alias
router.post('/rotate', async (req, res) => {
  try {
    // Allow both authenticated and unauthenticated users
    const userId = req.user?.id || req.body.userId || `anon_${uuidv4()}`;
    const { strategy, domain } = req.body;
    
    const result = await rotateUserAlias(
      userId, 
      strategy || 'dot', 
      domain || 'gmail.com'
    );
    
    res.json(result);
  } catch (error) {
    console.error('Failed to rotate Gmail alias:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to rotate Gmail alias',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// ==================== Public Routes ====================

// Public routes for non-authenticated users
router.post('/public/create', async (req, res) => {
  try {
    const userId = req.query.userId || `anon_${uuidv4()}`;
    const { strategy, domain } = req.body; // 'dot' or 'plus', 'gmail.com' or 'googlemail.com'
    
    const result = await generateGmailAlias(
      userId, 
      strategy || 'dot', 
      domain || 'gmail.com'
    );
    
    res.json(result);
  } catch (error) {
    console.error('Failed to create Gmail alias:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to create Gmail alias',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

router.get('/public/aliases/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const aliases = await getUserAliases(userId);
    
    res.json({ aliases });
  } catch (error) {
    console.error('Failed to fetch Gmail aliases:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to fetch Gmail aliases',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

router.get('/public/emails/:alias', async (req, res) => {
  try {
    const { alias } = req.params;
    const userId = req.query.userId || `anon_${uuidv4()}`;
    
    const emails = await fetchGmailEmails(userId, alias);
    
    res.json({ emails });
  } catch (error) {
    console.error('Failed to fetch emails:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to fetch emails',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

router.post('/public/rotate', async (req, res) => {
  try {
    const { userId, strategy, domain } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }
    
    const result = await rotateUserAlias(
      userId, 
      strategy || 'dot', 
      domain || 'gmail.com'
    );
    
    res.json(result);
  } catch (error) {
    console.error('Failed to rotate Gmail alias:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to rotate Gmail alias',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// ==================== Admin Routes ====================

// Add a new Gmail account with IMAP
router.post('/admin/accounts', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { email, appPassword } = req.body;
    
    if (!email || !appPassword) {
      return res.status(400).json({ error: 'Email and app password are required' });
    }
    
    const result = await addGmailAccount(email, appPassword);
    
    res.json(result);
  } catch (error) {
    console.error('Failed to add Gmail account:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to add Gmail account',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Admin route with passphrase for adding Gmail account (alternative auth)
router.post('/admin/accounts-alt', async (req, res) => {
  try {
    // Check admin passphrase
    const adminAccess = req.headers['admin-access'];
    if (adminAccess !== process.env.ADMIN_PASSPHRASE) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const { email, appPassword } = req.body;
    
    if (!email || !appPassword) {
      return res.status(400).json({ error: 'Email and app password are required' });
    }
    
    const result = await addGmailAccount(email, appPassword);
    
    res.json(result);
  } catch (error) {
    console.error('Failed to add Gmail account:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to add Gmail account',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Get Gmail accounts statistics
router.get('/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const accountStats = await getGmailAccountStats();
    const cacheStats = getEmailCacheStats();
    
    res.json({
      accounts: accountStats,
      cache: cacheStats
    });
  } catch (error) {
    console.error('Failed to get Gmail stats:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to get Gmail stats',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Admin route with passphrase for stats (alternative auth)
router.get('/admin/stats-alt', async (req, res) => {
  try {
    // Check admin passphrase
    const adminAccess = req.headers['admin-access'];
    if (adminAccess !== process.env.ADMIN_PASSPHRASE) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const accountStats = await getGmailAccountStats();
    const cacheStats = getEmailCacheStats();
    
    res.json({
      accounts: accountStats,
      cache: cacheStats
    });
  } catch (error) {
    console.error('Failed to get Gmail stats:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to get Gmail stats',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

export default router;
