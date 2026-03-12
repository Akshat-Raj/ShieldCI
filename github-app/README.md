# ShieldCI GitHub App

## Required Environment Variables

```
GITHUB_APP_ID=<your app id>
GITHUB_PRIVATE_KEY_PATH=<path to .pem file>
GITHUB_WEBHOOK_SECRET=<webhook secret>
SHIELDCI_API_URL=<backend API URL>
PORT=3001
```

## Setup

1. Register a GitHub App at https://github.com/settings/apps/new
   - **Webhook URL**: `https://your-domain.com/webhook`
   - **Permissions**: `checks: write`, `pull_requests: write`, `contents: read`
   - **Events**: `push`, `pull_request`
2. Download the private key `.pem` file
3. Set environment variables in `.env`
4. `npm install && npm start`

## Architecture

```
webhook (push/PR) → Express server → authenticate as GitHub App
                                    → queue scan job
                                    → create "in_progress" check run
                                    → run ShieldCI scan (Docker or local)
                                    → post results as check run + PR comment
```
