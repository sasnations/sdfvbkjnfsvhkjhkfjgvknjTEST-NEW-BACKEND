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
  updateGmailCredentialStatus,
  verifyCredential
} from '../services/gmailService.js';

const router = express.Router();

// ==================== User Routes ====================

// Create a new Gmail alias
router.post('/create', async (req, res) => {
  try {
    // Allow both authenticated and unauthenticated users
    const userId = req.user?.id || `anon_${uuidv4()}`;
    const { strategy } = req.body; // 'dot' or 'plus'
    
    const result = await generateGmailAlias(userId, strategy);
    
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
    
    const result = await rotateUserAlias(userId);
    
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
    const { strategy } = req.body; // 'dot' or 'plus'
    
    const result = await generateGmailAlias(userId, strategy);
    
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
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }
    
    const result = await rotateUserAlias(userId);
    
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

// Get OAuth URL for adding a new Gmail account
router.get('/admin/auth-url', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { credentialId } = req.query; // Optional credential ID
    let authUrl;
    
    if (credentialId) {
      authUrl = await getAuthUrl(credentialId);
    } else {
      authUrl = await getAuthUrl();
    }
    
    res.json({ authUrl });
  } catch (error) {
    console.error('Failed to generate auth URL:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to generate auth URL',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
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
    
    const { credentialId } = req.query; // Optional credential ID
    let authUrl;
    
    if (credentialId) {
      authUrl = await getAuthUrl(credentialId);
    } else {
      authUrl = await getAuthUrl();
    }
    
    res.json({ authUrl });
  } catch (error) {
    console.error('Failed to generate auth URL:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to generate auth URL',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
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
    
    const { code } = req.body;
    
    if (!code) {
      return res.status(400).json({ error: 'Authorization code is required' });
    }
    
    const result = await addGmailAccount(code);
    
    res.json(result);
  } catch (error) {
    console.error('Failed to add Gmail account:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to add Gmail account',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// GET handler for OAuth callback - FIXED to remove undefined segment
router.get('/admin/accounts-alt', async (req, res) => {
  try {
    // Get the code from query parameters
    const { code } = req.query;
    
    if (!code) {
      console.error('OAuth callback received without code');
      return res.status(400).send('Authorization code is required');
    }
    
    console.log('Received OAuth callback with code:', code);
    
    try {
      // Process the code
      const result = await addGmailAccount(code.toString());
      console.log('Successfully added Gmail account:', result.email);
      
      // Redirect back to the admin page with success parameters
      // FIX: Remove the undefined path segment from redirect URL
      res.redirect(`${process.env.FRONTEND_URL}/adminonlygmail?success=true&email=${encodeURIComponent(result.email)}`);
    } catch (error) {
      console.error('Failed to add Gmail account in callback:', error);
      
      // Redirect with error message
      // FIX: Remove the undefined path segment from redirect URL
      const errorMsg = error.message || 'Failed to add Gmail account';
      res.redirect(`${process.env.FRONTEND_URL}/adminonlygmail?error=${encodeURIComponent(errorMsg)}`);
    }
  } catch (error) {
    console.error('OAuth callback general error:', error);
    res.status(500).send('Internal server error processing OAuth callback');
  }
});

// Verify a Gmail API credential
router.post('/admin/verify-credential', async (req, res) => {
  try {
    // Check admin passphrase
    const adminAccess = req.headers['admin-access'];
    if (adminAccess !== process.env.ADMIN_PASSPHRASE) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const { credentialId } = req.body;
    
    if (!credentialId) {
      return res.status(400).json({ error: 'Credential ID is required' });
    }
    
    const result = await verifyCredential(credentialId);
    
    res.json(result);
  } catch (error) {
    console.error('Failed to verify credential:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to verify credential',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// GET handler for credential verification (fallback)
router.get('/admin/verify-credential', async (req, res) => {
  try {
    // Check admin passphrase
    const adminAccess = req.headers['admin-access'];
    if (adminAccess !== process.env.ADMIN_PASSPHRASE) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const { credentialId } = req.query;
    
    if (!credentialId) {
      return res.status(400).json({ error: 'Credential ID is required' });
    }
    
    const result = await verifyCredential(credentialId.toString());
    
    res.json(result);
  } catch (error) {
    console.error('Failed to verify credential (GET):', error);
    res.status(400).json({ 
      error: error.message || 'Failed to verify credential',
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
    res.status(400).json({ 
      error: error.message || 'Failed to get Gmail credentials',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
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
      usageCount: 0
    });
    
    res.json(credential);
  } catch (error) {
    console.error('Failed to add Gmail credential:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to add Gmail credential',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
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
    
    // Allow partial updates
    const updates = {};
    if (clientId) updates.clientId = clientId;
    if (clientSecret) updates.clientSecret = clientSecret;
    if (redirectUri) updates.redirectUri = redirectUri;
    if (typeof active !== 'undefined') updates.active = active;
    
    const credential = await updateGmailCredential(id, updates);
    
    res.json(credential);
  } catch (error) {
    console.error('Failed to update Gmail credential:', error);
    res.status(400).json({ 
      error: error.message || 'Failed to update Gmail credential',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
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
    res.status(400).json({ 
      error: error.message || 'Failed to delete Gmail credential',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
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
    res.status(400).json({ 
      error: error.message || 'Failed to update Gmail credential status',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

export default router;
