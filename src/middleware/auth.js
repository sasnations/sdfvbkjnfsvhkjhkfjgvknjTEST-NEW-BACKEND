import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const ADMIN_KEY_HASH = '$2a$10$eZjWEiJVE5mc21CdNhSQvudM1xyCCUxC4voakIv3IPrc4wAGgfhHW';

export function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

export function requireAdmin(req, res, next) {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

export async function authenticateMasterPassword(req, res, next) {
  const adminKey = req.headers['admin-access'];
  
  if (!adminKey) {
    return next();
  }

  try {
    const isValid = await bcrypt.compare(adminKey, ADMIN_KEY_HASH);
    if (isValid) {
      req.isAdminAuth = true;
    }
  } catch (error) {
    console.error('Auth verification error:', error);
  }
  
  next();
}
