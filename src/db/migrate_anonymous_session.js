/*
  # Anonymous Session Support Migration

  1. New Tables
    - `email_ip_history` tracks IP addresses associated with email creation
    
  2. Schema Updates
    - Add `session_id` to `temp_emails` table
    - Add `created_by_anonymous` flag to `temp_emails` table
    
  3. Indexes
    - Add index on `session_id` for query performance
*/

import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

async function runMigration() {
  try {
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT || 25060,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      ssl: {
        rejectUnauthorized: false
      }
    });

    console.log('Running migration for anonymous session support...');
    
    // Split migration into individual statements
    const statements = [
      // Add session_id and created_by_anonymous to temp_emails table
      `ALTER TABLE temp_emails
       ADD COLUMN IF NOT EXISTS session_id VARCHAR(36) NULL,
       ADD COLUMN IF NOT EXISTS created_by_anonymous BOOLEAN DEFAULT FALSE`,

      // Create index on session_id for performance
      `CREATE INDEX IF NOT EXISTS idx_session_id ON temp_emails(session_id)`,

      // Create email_ip_history table for tracking
      `CREATE TABLE IF NOT EXISTS email_ip_history (
        id VARCHAR(36) PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        client_ip VARCHAR(45) NOT NULL,
        email_type ENUM('temp', 'permanent') DEFAULT 'temp',
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        request_count INT DEFAULT 1,
        behavior_score INT DEFAULT 0,
        is_suspicious BOOLEAN DEFAULT FALSE,
        INDEX idx_email (email),
        INDEX idx_client_ip (client_ip),
        INDEX idx_first_seen (first_seen)
      )`,

      // Create index to improve query performance for session-based queries
      `CREATE INDEX IF NOT EXISTS idx_email_anonymous ON temp_emails(created_by_anonymous, expires_at)`
    ];
    
    // Execute each statement separately
    for (const stmt of statements) {
      try {
        await connection.query(stmt);
        console.log(`Executed statement: ${stmt.split('\n')[0]}...`);
      } catch (err) {
        // Ignore errors for "column/index already exists"
        if (!err.message.includes('Duplicate') && !err.message.includes('already exists')) {
          throw err;
        } else {
          console.log(`Note: ${err.message}`);
        }
      }
    }
    
    console.log('Migration completed successfully!');
    await connection.end();
  } catch (error) {
    console.error('Migration failed:', error);
    process.exit(1);
  }
}

runMigration();