# Branch Strategy

## Branch Usage

**IMPORTANT:** Always check which branch you are on before making any changes.
- **Never** make modifications directly on `main` branch
- **Always** make changes on `develop` branch or a feature branch off `develop`
- Run `git branch` to verify your current branch before committing

### `main` - Publish Only
- **Purpose:** Production-ready code and new publishes
- **When to push:** Only when creating a new publish to ghcr.io
- **Automated actions on push:**
  - Docker image published to `ghcr.io`
- **Do NOT:** Merge feature branches, PRs, or development work directly to main

### `develop` - All Development
- **Purpose:** Active development, feature branches, PRs
- **When to push:** Everything else (features, bug fixes, refactoring)
- **Automated actions on push:**
  - Docker image built and published to `ghcr.io` (development tag)
- **Do NOT:** Put production code here that isn't ready for testing

## Publish Process

1. Develop features on `develop` branch
2. Merge completed features to `develop`
3. When ready to publish, merge `develop` → `main`
4. Push to `main` triggers automatic Docker image publish to `ghcr.io`

## Downloading Packages

### Docker Image
```bash
# Latest publish
docker pull ghcr.io/<repository>:latest

# Specific version
docker pull ghcr.io/<repository>:v1.0.0
```

