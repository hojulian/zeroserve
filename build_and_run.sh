#!/bin/bash
set -e

# Build the project
cargo build

# Create a sample site directory if it doesn't exist
mkdir -p site
if [ ! -f "site/index.html" ]; then
    echo "<h1>Hello from zeroserve!</h1>" > site/index.html
fi

# Pack the site into a tarball
cargo run -- --pack site > site.tar

echo "Site packed into site.tar"
echo "Starting zeroserve on http://127.0.0.1:8080"
echo "Press Ctrl+C to stop the server"

# Run the server
cargo run -- --addr 127.0.0.1:8080 site.tar
