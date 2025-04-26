import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import { authenticateToken, requireAdmin, authenticateMasterPassword } from '../middleware/auth.js';
import { 
  addGmailAccount, 
  generateGmailAlias, 
  fetchGmailEmails, 
  getUserAliases,
  rotateUserAlias,
  getAuthUrl,
  getGmailAccountStats,
  getEmailCacheStats,
  getGmailCredentials,
  addGmailCredential,
  updateGmailCredential,
  deleteGmailCredential,
  updateGmailCredentialStatus
} from '../services/gmailService.js';

const router = express.Router();

// ==================== User Routes ====================

// Create a new Gmail alias
router.post('/create', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { strategy } = req.body; // 'dot' or 'plus'
    
    const result = await generateGmailAlias(userId, strategy);
    
    res.json(result);
  } catch (error) {
    console.error('Failed to create Gmail alias:', error);
    res.status(400).json({ error: error.message || 'Failed to create Gmail alias' });
  }
});

// Get all Gmail aliases for the user
router.get('/aliases', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const aliases = getUserAliases(userId);
    
    res.json({ aliases });
  } catch (error) {
    console.error('Failed to fetch Gmail aliases:', error);
    res.status(400).json({ error: error.message || 'Failed to fetch Gmail aliases' });
  }
});

// Fetch emails for a specific alias
router.get('/:alias/emails', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { alias } = req.params;
    
    const emails = await fetchGmailEmails(userId, alias);
    
    res.json({ emails });
  } catch (error) {
    console.error('Failed to fetch emails:', error);
    res.status(400).json({ error: error.message || 'Failed to fetch emails' });
  }
});

// Rotate to a new Gmail alias
router.post('/rotate', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const result = await rotateUserAlias(userId);
    
    res.json(result);
  } catch (error) {
    console.error('Failed to rotate Gmail alias:', error);
    res.status(400).json({ error: error.message || 'Failed to rotate Gmail alias' });
  }
});

// ==================== Admin Routes ====================

// Get OAuth URL for adding a new Gmail account
router.get('/admin/auth-url', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const authUrl = getAuthUrl();
    
    res.json({ authUrl });
  } catch (error) {
    console.error('Failed to generate auth URL:', error);
    res.status(400).json({ error: error.message || 'Failed to generate auth URL' });
  }
});

// Admin route with passphrase for auth URL (alternative auth)
router.get('/admin/auth-url-alt', async (req, res) => {
  try {
    // Check admin passphrase
    const adminAccess = req.headers['admin-access'];
    if (adminAccess !== process.env.ADMIN_PASSPHRASE) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const authUrl = getAuthUrl();
    
    res.json({ authUrl });
  } catch (error) {
    console.error('Failed to generate auth URL:', error);
    res.status(400).json({ error: error.message || 'Failed to generate auth URL' });
  }
});

// Add a new Gmail account (OAuth callback)
router.post('/admin/accounts', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { code } = req.body;
    
    if (!code) {
      return res.status(400).json({ error: 'Authorization code is required' });
    }
    
    const result = await addGmailAccount(code);
    
    res.json(result);
  } catch (error) {
    console.error('Failed to add Gmail account:', error);
    res.status(400).json({ error: error.message || 'Failed to add Gmail account' });
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
    
    const { code } = req.body;
    
    if (!code) {
      return res.status(400).json({ error: 'Authorization code is required' });
    }
    
    const result = await addGmailAccount(code);
    
    res.json(result);
  } catch (error) {
    console.error('Failed to add Gmail account:', error);
    res.status(400).json({ error: error.message || 'Failed to add Gmail account' });
  }
});

// Get Gmail accounts statistics
router.get('/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const accountStats = getGmailAccountStats();
    const cacheStats = getEmailCacheStats();
    
    res.json({
      accounts: accountStats,
      cache: cacheStats
    });
  } catch (error) {
    console.error('Failed to get Gmail stats:', error);
    res.status(400).json({ error: error.message || 'Failed to get Gmail stats' });
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
    
    const accountStats = getGmailAccountStats();
    const cacheStats = getEmailCacheStats();
    
    res.json({
      accounts: accountStats,
      cache: cacheStats
    });
  } catch (error) {
    console.error('Failed to get Gmail stats:', error);
    res.status(400).json({ error: error.message || 'Failed to get Gmail stats' });
  }
});

// Get all Gmail API credentials
router.get('/admin/credentials', async (req, res) => {
  try {
    // Check admin passphrase
    const adminAccess = req.headers['admin-access'];
    if (adminAccess !== process.env.ADMIN_PASSPHRASE) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const credentials = await getGmailCredentials();
    res.json({ credentials });
  } catch (error) {
    console.error('Failed to get Gmail credentials:', error);
    res.status(400).json({ error: error.message || 'Failed to get Gmail credentials' });
  }
});

// Add a new Gmail API credential
router.post('/admin/credentials', async (req, res) => {
  try {
    // Check admin passphrase
    const adminAccess = req.headers['admin-access'];
    if (adminAccess !== process.env.ADMIN_PASSPHRASE) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const { clientId, clientSecret, redirectUri, active } = req.body;
    
    if (!clientId || !clientSecret || !redirectUri) {
      return res.status(400).json({ error: 'Client ID, Client Secret, and Redirect URI are required' });
    }
    
    const credential = await addGmailCredential({
      clientId,
      clientSecret,
      redirectUri,
      active: active !== false,
      usageCount: 0,
      lastUsed: new Date().toISOString()
    });
    
    res.json(credential);
  } catch (error) {
    console.error('Failed to add Gmail credential:', error);
    res.status(400).json({ error: error.message || 'Failed to add Gmail credential' });
  }
});

// Update a Gmail API credential
router.put('/admin/credentials/:id', async (req, res) => {
  try {
    // Check admin passphrase
    const adminAccess = req.headers['admin-access'];
    if (adminAccess !== process.env.ADMIN_PASSPHRASE) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const { id } = req.params;
    const { clientId, clientSecret, redirectUri, active } = req.body;
    
    if (!clientId || !clientSecret || !redirectUri) {
      return res.status(400).json({ error: 'Client ID, Client Secret, and Redirect URI are required' });
    }
    
    const credential = await updateGmailCredential(id, {
      clientId,
      clientSecret,
      redirectUri,
      active: active !== false
    });
    
    res.json(credential);
  } catch (error) {
    console.error('Failed to update Gmail credential:', error);
    res.status(400).json({ error: error.message || 'Failed to update Gmail credential' });
  }
});

// Delete a Gmail API credential
router.delete('/admin/credentials/:id', async (req, res) => {
  try {
    // Check admin passphrase
    const adminAccess = req.headers['admin-access'];
    if (adminAccess !== process.env.ADMIN_PASSPHRASE) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const { id } = req.params;
    await deleteGmailCredential(id);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Failed to delete Gmail credential:', error);
    res.status(400).json({ error: error.message || 'Failed to delete Gmail credential' });
  }
});

// Update Gmail API credential status
router.patch('/admin/credentials/:id/status', async (req, res) => {
  try {
    // Check admin passphrase
    const adminAccess = req.headers['admin-access'];
    if (adminAccess !== process.env.ADMIN_PASSPHRASE) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const { id } = req.params;
    const { active } = req.body;
    
    if (typeof active !== 'boolean') {
      return res.status(400).json({ error: 'Active status is required' });
    }
    
    await updateGmailCredentialStatus(id, active);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Failed to update Gmail credential status:', error);
    res.status(400).json({ error: error.message || 'Failed to update Gmail credential status' });
  }
});

export default router;