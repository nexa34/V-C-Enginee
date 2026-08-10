#!/bin/bash
cd "$(dirname "$0")"
git pull origin main
npm install --silent
pm2 reload myapp || pm2 restart myapp

# Setup auto-backup cron job (every 6 hours)
CRON_JOB="0 */6 * * * $(dirname "$0")/backup.sh"
(crontab -l 2>/dev/null | grep -v "backup.sh"; echo "$CRON_JOB") | crontab -

echo "Deployment completed at $(date)" >> deploy.log