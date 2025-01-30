#!/bin/bash

# Configuration
AWS_PROFILE=${AWS_PROFILE:-"default"}
INSTANCE_ID=${INSTANCE_ID:-"your-instance-id"}
REGION="us-east-1"

function log_info() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: $1"
}

function log_error() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: $1" >&2
}

# Check if the instance is running
function get_instance_status() {
  log_info "Checking instance status..."
  STATUS=$(aws ec2 describe-instance-status \
    --instance-ids "$INSTANCE_ID" \
    --profile "$AWS_PROFILE" \
    --query 'InstanceStatuses[0].InstanceState.Name' \
    --output text 2> /dev/null)

  echo "$STATUS"
}

# Start the instance if it's not running
function start_instance() {
  log_info "Starting instance $INSTANCE_ID..."
  aws ec2 start-instances \
    --instance-ids "$INSTANCE_ID" \
    --profile "$AWS_PROFILE" \
    > /dev/null

  log_info "Instance started. Waiting for initialization (2 minutes)..."
  sleep 120
}

# Connect to the instance using SSM
function connect_to_instance() {
  log_info "Connecting to instance $INSTANCE_ID via SSM..."
  aws ssm start-session \
    --target "$INSTANCE_ID" \
    --profile "$AWS_PROFILE"
}

# Main script logic
log_info "Starting EC2 connection process..."
if [ -z "$INSTANCE_ID" ]; then
  log_error "INSTANCE_ID is not set. Please set it as an environment variable or update the script."
  exit 1
fi

STATUS=$(get_instance_status)

if [[ "$STATUS" == "running" ]]; then
  log_info "Instance is already running."
elif [[ "$STATUS" == "stopped" || "$STATUS" == "stopping" ]]; then
  start_instance
else
  log_error "Unexpected instance status: $STATUS"
  exit 1
fi

connect_to_instance
