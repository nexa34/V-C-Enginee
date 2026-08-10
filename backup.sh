#!/bin/bash
# Backup script for VGenius application
# Sends backup to Telegram (includes database dump)

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

# Create database dump
DB_DUMP="$BACKUP_DIR/db_dump_$TIMESTAMP.sql"
mysqldump -h "${DB_HOST:-localhost}" -P "${DB_PORT:-3306}" -u "${DB_USER:-vgenius}" -p"${DB_PASSWORD}" "${DB_NAME:-vgenius}" > "$DB_DUMP" 2>/dev/null

# Create archive (excluding node_modules, .git, .env, backups)
tar -czf "$ARCHIVE_PATH" -C "$PROJECT_DIR" . --exclude='node_modules' --exclude='.git' --exclude='.env' --exclude='backups' 2>/dev/null

# Send to Telegram
if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_ADMIN_CHAT_ID" ]; then
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d chat_id="$TELEGRAM_ADMIN_CHAT_ID" \
        -d text="Backup completed: $ARCHIVE_NAME"
    # Send the backup file
    curl -s -F "chat_id=$TELEGRAM_ADMIN_CHAT_ID" \
        -F "document=@$ARCHIVE_PATH" \
        "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendDocument" >/dev/null
fi

# Clean up db dump
rm -f "$DB_DUMP"

echo "Backup created: $ARCHIVE_PATH" >> "$PROJECT_DIR/backup.log"