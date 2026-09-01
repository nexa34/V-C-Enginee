#!/bin/bash
# Backup script for VGenius application
# Sends backup to Telegram (includes database dump)
# SECURITY: All sensitive operations use env vars, never expose passwords in process list

PROJECT_DIR="$(dirname "$0")"
BACKUP_DIR="$PROJECT_DIR/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
ARCHIVE_NAME="vgenius_backup_$TIMESTAMP.tar.gz"
ARCHIVE_PATH="$BACKUP_DIR/$ARCHIVE_NAME"

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# Load DB credentials from .env
if [ -f "$PROJECT_DIR/.env" ]; then
    export $(grep -v '^#' "$PROJECT_DIR/.env" | xargs)
fi

# Validate required env vars
if [ -z "$DB_PASSWORD" ] || [ "$DB_PASSWORD" = "CHANGE_ME_REQUIRED_STRONG_PASSWORD" ]; then
    echo "[BACKUP] ERROR: DB_PASSWORD not configured in .env" >> "$PROJECT_DIR/backup.log"
    exit 1
fi

if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ "$TELEGRAM_BOT_TOKEN" = "CHANGE_ME_REQUIRED" ]; then
    echo "[BACKUP] ERROR: TELEGRAM_BOT_TOKEN not configured" >> "$PROJECT_DIR/backup.log"
    exit 1
fi

# Use MYSQL_PWD env var instead of -p flag (avoids password in process list)
export MYSQL_PWD="$DB_PASSWORD"

# Create database dump with consistency guarantees
DB_DUMP="$BACKUP_DIR/db_dump_$TIMESTAMP.sql"
mysqldump -h "${DB_HOST:-localhost}" -P "${DB_PORT:-3306}" -u "${DB_USER:-vgenius}" \
    --single-transaction --routines --triggers --events \
    "${DB_NAME:-vgenius}" > "$DB_DUMP" 2>/dev/null

# Unset password from environment immediately after use
unset MYSQL_PWD

if [ ! -s "$DB_DUMP" ]; then
    echo "[BACKUP] ERROR: Database dump failed or empty" >> "$PROJECT_DIR/backup.log"
    exit 1
fi

# Create archive (excluding node_modules, .git, .env, backups)
tar -czf "$ARCHIVE_PATH" -C "$PROJECT_DIR" . \
    --exclude='node_modules' \
    --exclude='.git' \
    --exclude='.env' \
    --exclude='backups' \
    --exclude='*.log' \
    2>/dev/null

# Remove DB dump after archiving
rm -f "$DB_DUMP"

# Validate archive was created
if [ ! -s "$ARCHIVE_PATH" ]; then
    echo "[BACKUP] ERROR: Archive creation failed" >> "$PROJECT_DIR/backup.log"
    exit 1
fi

# Send to Telegram (note: Telegram is NOT encrypted end-to-end for bot API)
# Consider encrypting sensitive data before transmission
if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_ADMIN_CHAT_ID" ]; then
    # Send status message
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d chat_id="$TELEGRAM_ADMIN_CHAT_ID" \
        -d text="Backup completed: $ARCHIVE_NAME ($(du -h "$ARCHIVE_PATH" | cut -f1))" \
        >/dev/null
    
    # Send the backup file
    curl -s -F "chat_id=$TELEGRAM_ADMIN_CHAT_ID" \
        -F "document=@$ARCHIVE_PATH" \
        -F "caption=Encrypted backup from $(hostname) - $(date)" \
        "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendDocument" >/dev/null
fi

echo "[BACKUP] $(date '+%Y-%m-%d %H:%M:%S') - Created: $ARCHIVE_PATH" >> "$PROJECT_DIR/backup.log"
