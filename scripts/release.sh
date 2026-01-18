#!/bin/bash
# LogZero Release Script
# Usage: ./scripts/release.sh v1.0.0

set -e

VERSION=$1

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 v1.0.0"
    exit 1
fi

# Validate version format
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format v1.0.0"
    exit 1
fi

VERSION_NUM="${VERSION#v}"

echo "Releasing LogZero $VERSION"
echo "========================="

# Update version in wails.json
echo "Updating version in wails.json..."
if command -v jq &> /dev/null; then
    jq --arg v "$VERSION_NUM" '.info.productVersion = $v' wails.json > wails.json.tmp && mv wails.json.tmp wails.json
else
    # Fallback: sed replacement
    sed -i.bak "s/\"productVersion\": \"[^\"]*\"/\"productVersion\": \"$VERSION_NUM\"/" wails.json
    rm -f wails.json.bak
fi

# Commit version bump
git add wails.json
git commit -m "Bump version to $VERSION" || echo "No changes to commit"

# Create and push tag
echo "Creating tag $VERSION..."
git tag -a "$VERSION" -m "Release $VERSION"

echo "Pushing to remote..."
git push origin main
git push origin "$VERSION"

echo ""
echo "Release $VERSION triggered!"
echo "GitHub Actions will now build installers for all platforms."
echo "Check progress at: https://github.com/OrbitalForensics/LogZero/actions"
echo ""
echo "Once complete, the release will be available at:"
echo "https://github.com/OrbitalForensics/LogZero/releases/tag/$VERSION"
