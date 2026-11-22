#!/usr/bin/env bash
# ==============================================================================
# One-time setup for Keyless GitHub Actions -> Cloud Run Workload Identity
# Usage: bash scripts/setup-github-wif.sh <GITHUB_OWNER>/<REPO_NAME>
# ==============================================================================
set -euo pipefail

REPO_SLUG="${1:-}"
if [[ -z "$REPO_SLUG" || "$REPO_SLUG" != */* ]]; then
    echo "Usage: bash scripts/setup-github-wif.sh <GITHUB_OWNER>/<REPO_NAME>" >&2
    exit 2
fi

PROJECT_ID="${GCP_PROJECT_ID:-compounder-core-prod-487014}"
GITHUB_OWNER="${REPO_SLUG%%/*}"
SA_NAME="acta-github-deployer"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
POOL_NAME="github-actions-pool"
PROVIDER_NAME="github-oidc"

gcloud services enable iamcredentials.googleapis.com sts.googleapis.com --project="$PROJECT_ID" --quiet

if ! gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" >/dev/null 2>&1; then
    gcloud iam service-accounts create "$SA_NAME" \
        --project="$PROJECT_ID" \
        --display-name="Acta GitHub Actions Deployer"
fi

for role in \
    roles/run.admin \
    roles/cloudbuild.builds.editor \
    roles/artifactregistry.writer \
    roles/iam.serviceAccountUser \
    roles/storage.admin \
    roles/secretmanager.viewer \
    roles/serviceusage.serviceUsageConsumer; do
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="$role" \
        --condition=None \
        --quiet >/dev/null
done

if ! gcloud iam workload-identity-pools describe "$POOL_NAME" --project="$PROJECT_ID" --location="global" >/dev/null 2>&1; then
    gcloud iam workload-identity-pools create "$POOL_NAME" \
        --project="$PROJECT_ID" \
        --location="global" \
        --display-name="GitHub Actions Pool"
fi

if ! gcloud iam workload-identity-pools providers describe "$PROVIDER_NAME" \
    --project="$PROJECT_ID" --location="global" --workload-identity-pool="$POOL_NAME" >/dev/null 2>&1; then
    gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_NAME" \
        --project="$PROJECT_ID" \
        --location="global" \
        --workload-identity-pool="$POOL_NAME" \
        --display-name="GitHub OIDC" \
        --issuer-uri="https://token.actions.githubusercontent.com" \
        --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.repository_owner=assertion.repository_owner" \
        --attribute-condition="assertion.repository_owner == '${GITHUB_OWNER}'"
fi

POOL_ID="$(gcloud iam workload-identity-pools describe "$POOL_NAME" --project="$PROJECT_ID" --location="global" --format='value(name)')"
PROVIDER_ID="$(gcloud iam workload-identity-pools providers describe "$PROVIDER_NAME" --project="$PROJECT_ID" --location="global" --workload-identity-pool="$POOL_NAME" --format='value(name)')"

gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
    --project="$PROJECT_ID" \
    --role="roles/iam.workloadIdentityUser" \
    --member="principalSet://iam.googleapis.com/${POOL_ID}/attribute.repository/${REPO_SLUG}" \
    --quiet >/dev/null

if command -v gh >/dev/null 2>&1; then
    gh variable set GCP_WORKLOAD_IDENTITY_PROVIDER --repo "$REPO_SLUG" --body "$PROVIDER_ID"
    gh variable set GCP_DEPLOY_SERVICE_ACCOUNT --repo "$REPO_SLUG" --body "$SA_EMAIL"
    echo "[acta] Configured keyless GitHub Actions variables on $REPO_SLUG!"
else
    echo "Set these two GitHub Repository Variables on $REPO_SLUG:"
    echo "  GCP_WORKLOAD_IDENTITY_PROVIDER=$PROVIDER_ID"
    echo "  GCP_DEPLOY_SERVICE_ACCOUNT=$SA_EMAIL"
fi
