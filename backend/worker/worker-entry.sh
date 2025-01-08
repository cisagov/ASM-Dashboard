#!/bin/bash
# Sets up an explicit proxy using mitmproxy.

set -e # Exit immediately if a command exits with a non-zero status.

PROXY_PORT=8080

echo "Starting proxy with mitmproxy..."

# Start mitmproxy using Python, redirect logs to pm2-error.log
mitmdump --set stream_large_bodies=1 --listen-port $PROXY_PORT -s /app/worker/mitmproxy_sign_requests.py > ~/pm2-error.log 2>&1 &

# Wait for the proxy port to be ready
echo "Waiting for mitmproxy to be ready on port $PROXY_PORT..."
for i in {1..10}; do
  if nc -z localhost $PROXY_PORT; then
    echo "Proxy is ready!"
    break
  fi
  echo "Retrying... ($i/10)"
  sleep 1
done

if ! nc -z localhost $PROXY_PORT; then
  echo "Proxy failed to start. Exiting."
  cat ~/pm2-error.log
  exit 1
fi

# Install the mitmproxy SSL certificate so that HTTPS connections can be proxied.
echo "Installing mitmproxy SSL certificate..."
cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
update-ca-certificates --fresh

# Export environment variables for Python and AWS to trust the mitmproxy self-signed certificate.
export AWS_CA_BUNDLE=/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt

# Main code
echo "Running main worker script..."
timeout 1d python worker/worker.py "$@"

# Stop the proxy
echo "Stopping proxy..."
pkill -f mitmdump || true

# Print logs if any errors occurred
if [ -s ~/pm2-error.log ]; then
  echo "Printing error logs:"
  cat ~/pm2-error.log
else
  echo "No errors logged."
fi

echo "Worker finished successfully."
