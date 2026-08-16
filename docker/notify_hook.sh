#!/usr/bin/env bash
# Example notify hook: appends a line to a log file. A real deployment would
# swap this for a script that emails, posts to Slack/PagerDuty, sends an
# SMS, etc. ransomshield passes incident details via RANSOMSHIELD_* env vars
# and does not wait for this script to finish.
echo "$(date -Iseconds) ALERT pid=${RANSOMSHIELD_PID} action_taken=${RANSOMSHIELD_ACTION_TAKEN} reason=\"${RANSOMSHIELD_REASON}\" report=${RANSOMSHIELD_REPORT_PATH}" >> /var/log/ransomshield-notifications.log
