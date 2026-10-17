# SAS WAF Security Platform — Setup Guide

Centralized AWS WAF security, threat intelligence, investigation and controlled response for an **AWS Organization**. The platform runs in one central security account. It reads live WAF data from your member accounts through a read-only cross-account role, and it changes WAF only through an approval workflow (simulate → approve → execute → verify → audit).

This guide deploys it into **your** AWS Organization so it shows real-time data from your accounts. There is no demo or sample data: everything you see comes from your accounts.

---

## How it works

```
Management account                 Central security account                       Member accounts (all or some OUs)
──────────────────                 ────────────────────────                       ─────────────────────────────────
CloudFormation StackSet  ───────────────────────────────────────────────────────► SASWafDiscoveryRole (read-only)
                                                                                   SASWafResponseRole  (approved writes)
                                   EventBridge (every 30 min / 6 h)
                                     └► Step Functions sync ── assume role ──────► WAFv2, ALB, API Gateway, CloudFront,
                                          └► Lambdas → RDS PostgreSQL                CloudWatch metrics, sampled requests
                                   ECS Fargate API (FastAPI) ◄── CloudFront ◄──── Security team browser (SSO + MFA)
                                   S3 + CloudFront console (React)
```

- **Telemetry sync** every 30 minutes: sampled requests (`GetSampledRequests`) and CloudWatch metrics.
- **Full discovery** every 6 hours: Web ACLs, rules, ALBs, API Gateway stages, CloudFront distributions, logging and drift.
- **Full WAF logs** (optional): accounts that log WAF traffic to S3 can replicate their logs to the platform for complete request-level evidence. All other accounts are shown as **sampled**, and the console says so.
- **Manual refresh**: the refresh button in the console starts a sync when data is older than one hour.

---

## 1. Before you start

### Accounts

| Account | What you do there |
|---|---|
| **Management account** (or a StackSets delegated administrator) | Deploy the cross-account roles to member accounts with a StackSet |
| **Central security account** (recommended: a dedicated security/tooling account) | Deploy and run the platform |
| **Member accounts** | Nothing manual; the StackSet creates two IAM roles in each |

### Tools on your workstation

| Tool | Version | Check |
|---|---|---|
| AWS CLI | v2 | `aws --version` |
| Docker | any recent | `docker --version` |
| Python | 3.12 | `python --version` |
| Node.js | 20.19 or newer | `node --version` |
| Git | any | `git --version` |

The commands below are for Bash (Linux, macOS, or Git Bash/WSL on Windows).

### Permissions

- **Central security account:** administrator access (the stacks create a VPC, RDS, ECS, Lambda, IAM roles, KMS keys and S3 buckets).
- **Management account:** permission to create StackSets with `SERVICE_MANAGED` permissions.

### Decide these values first

| Value | Example | Used in |
|---|---|---|
| Home region | `eu-west-1` | Everything in the central account |
| Console domain | `waf.example.com` | CloudFront viewer address |
| Origin domain | `origin.waf.example.com` | ALB behind CloudFront |
| Pilot OU | `ou-ab12-pilot123` | First StackSet rollout (about 5 accounts) |
| Approval email (optional) | `soc-approvals@example.com` | Approval notifications (SNS) |
| Full-logging accounts (optional) | `111122223333,444455556666` | Accounts that replicate WAF logs to the platform |

### Cost

The default setup costs about **$407/month on-demand** in the central account, or about **$345/month** with a 1-year RDS reservation. The full breakdown and ways to reduce it are in [`infra/README.md`](infra/README.md).

---

## 2. Get the code

```bash
git clone https://github.com/Harjeet2411/centralized-waf-security-platform.git
cd centralized-waf-security-platform
```

Set shell variables used in the rest of this guide (with **central security account** credentials active):

```bash
export AWS_REGION=eu-west-1                       # your home region
export CENTRAL_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
export VERSION=v1
export ARTIFACT_BUCKET=sas-waf-artifacts-$CENTRAL_ACCOUNT-$AWS_REGION
out() { aws cloudformation describe-stacks --stack-name "$1" \
          --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text; }
```

---

## 3. Prepare sign-in (OIDC with MFA)

Users sign in through an OpenID Connect (OIDC) provider that fronts **AWS IAM Identity Center** (for example Okta, Microsoft Entra ID, Ping, or Amazon Cognito federated to Identity Center). Users are never created automatically: an administrator grants access in the console.

Create an OIDC web application in your identity provider:

| Setting | Value |
|---|---|
| Application type | Web application (authorization code flow with PKCE, confidential client) |
| Redirect / callback URL | `https://<console domain>/api/v1/auth/callback` |
| Scopes | `openid email profile` |
| MFA | Required for this application |

Write down the **issuer URL**, **client ID** and **client secret**.

> The platform requires MFA: the ID token's `amr` claim must contain `mfa`. If it does not, sign-in fails with **403 MFA required**. Check this with a test login before you roll out.

---

## 4. Request TLS certificates

In **AWS Certificate Manager**:

1. In your **home region**: a certificate for the origin domain (`origin.waf.example.com`). The ALB uses it.
2. In **us-east-1**: a certificate for the console domain (`waf.example.com`). CloudFront uses it.

Validate both (DNS validation is easiest) and copy their ARNs.

---

## 5. Build and upload the pipeline

Create the artifact bucket, build the Lambda packages (Linux wheels are downloaded for you), and upload them:

```bash
aws s3 mb s3://$ARTIFACT_BUCKET --region $AWS_REGION

cd lambdas
python -m venv .venv && . .venv/bin/activate      # Git Bash on Windows: . .venv/Scripts/activate
pip install -e ".[dev]"
python build.py                                   # writes dist/<function>.zip + step_functions.asl.json
aws s3 sync dist s3://$ARTIFACT_BUCKET/releases/$VERSION/ --exclude ".deps/*"
cd ..
```

---

## 6. Deploy the platform stack (central account)

This creates the network, database, cache, encryption key, secrets, buckets, the seven pipeline Lambdas, the sync state machine and its schedules.

```bash
aws cloudformation deploy --stack-name sas-waf-platform \
  --template-file infra/central_account/platform.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    ArtifactBucket=$ARTIFACT_BUCKET \
    ArtifactPrefix=releases/$VERSION/ \
    AlertEmail=soc-approvals@example.com \
    LoggingAccountIds=""
```

`LoggingAccountIds` is optional (comma-separated full-logging account IDs, see step 14). The stack takes 20–30 minutes, mostly for RDS. If you set `AlertEmail`, confirm the SNS subscription email.

Read the two external IDs that the member-account roles will require:

```bash
export DISCOVERY_EXTERNAL_ID=$(aws secretsmanager get-secret-value \
  --secret-id sas-waf-prod/sts/discovery-external-id --query SecretString --output text)
export RESPONSE_EXTERNAL_ID=$(aws secretsmanager get-secret-value \
  --secret-id sas-waf-prod/sts/response-external-id --query SecretString --output text)
```

---

## 7. Deploy the cross-account roles (management account)

Switch your credentials to the **management account**, keeping the shell variables from steps 2 and 6.

Enable trusted access for StackSets once (console: *CloudFormation → StackSets → Enable trusted access*, or):

```bash
aws organizations enable-aws-service-access --service-principal member.org.stacksets.cloudformation.amazonaws.com
```

Create the StackSet and roll it out to the **pilot OU** first:

```bash
aws cloudformation create-stack-set --stack-set-name sas-waf-roles \
  --permission-model SERVICE_MANAGED --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_NAMED_IAM \
  --template-body file://infra/stacksets/cross-account-waf-roles.yaml \
  --parameters \
    ParameterKey=CentralAccountId,ParameterValue=$CENTRAL_ACCOUNT \
    ParameterKey=DiscoveryExternalId,ParameterValue=$DISCOVERY_EXTERNAL_ID \
    ParameterKey=ResponseExternalId,ParameterValue=$RESPONSE_EXTERNAL_ID

aws cloudformation create-stack-instances --stack-set-name sas-waf-roles \
  --deployment-targets OrganizationalUnitIds=ou-ab12-pilot123 \
  --regions $AWS_REGION
```

IAM roles are global, so one region is enough. Each member account gets:

| Role | Trusted by | Can do |
|---|---|---|
| `SASWafDiscoveryRole` | the platform's collector Lambda, with the discovery external ID | Read WAF, ALB, API Gateway, CloudFront and CloudWatch configuration and metrics |
| `SASWafResponseRole` | the platform API, with the response external ID, an approval ID tag and the approver's identity | Update IP sets and Web ACLs, associate Web ACLs, enable logging. Deleting WAF resources, IAM, Organizations and S3 deletes are explicitly denied |

> A `SERVICE_MANAGED` StackSet never deploys to the management account itself. If the management account runs workloads behind WAF, deploy `infra/stacksets/cross-account-waf-roles.yaml` there as a normal stack.

---

## 8. Build and push the backend image (central account)

Switch back to the **central security account**.

```bash
export REPO_URI=$(out sas-waf-platform BackendRepositoryUri)
aws ecr get-login-password | docker login --username AWS --password-stdin ${REPO_URI%%/*}
docker build --platform linux/amd64 -t $REPO_URI:$VERSION backend
docker push $REPO_URI:$VERSION
```

---

## 9. Deploy the application stack (central account)

This creates the ECS Fargate API, the ALB with its own WAF (reachable only through CloudFront), the console bucket and the CloudFront distribution.

```bash
aws cloudformation deploy --stack-name sas-waf-app \
  --template-file infra/central_account/app.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    ImageUri=$REPO_URI:$VERSION \
    AlbCertificateArn=<home-region certificate ARN> \
    AlbOriginDomain=origin.waf.example.com \
    CloudFrontAliases=waf.example.com \
    CloudFrontCertificateArn=<us-east-1 certificate ARN> \
    OidcIssuer=<issuer URL> \
    OidcClientId=<client ID>
```

Then:

1. **DNS:** create a CNAME/alias from `origin.waf.example.com` to the `AlbDnsName` output, and from `waf.example.com` to the CloudFront distribution.
2. **OIDC client secret:**
   ```bash
   aws secretsmanager put-secret-value --secret-id sas-waf-prod/oidc/client-secret --secret-string '<client secret>'
   ```
3. **Threat-intelligence keys (optional):** a provider left empty is skipped.
   ```bash
   aws secretsmanager put-secret-value --secret-id sas-waf-prod/ti/provider-keys \
     --secret-string '{"abuseipdb": "<key>", "greynoise": "<key>", "virustotal": ""}'
   ```
   Check each provider's licence terms; VirusTotal's public API, for example, does not allow commercial use.
4. **Restart the API** so it reads the secrets (ECS injects them when a task starts):
   ```bash
   aws ecs list-services --cluster sas-waf-prod-api               # shows the service ARN
   aws ecs update-service --cluster sas-waf-prod-api --service <service ARN> --force-new-deployment
   ```

---

## 10. Create the database schema and the first administrator

Both run as one-off tasks with the same image. Collect the network values first:

```bash
TASK_DEF=$(out sas-waf-app TaskDefinitionArn)
SUBNET=$(out sas-waf-platform AppSubnets | cut -d, -f1)
SG=$(out sas-waf-platform AppSecurityGroupId)
NET="awsvpcConfiguration={subnets=[$SUBNET],securityGroups=[$SG]}"
```

Create the schema:

```bash
aws ecs run-task --cluster sas-waf-prod-api --launch-type FARGATE --task-definition $TASK_DEF \
  --network-configuration "$NET" \
  --overrides '{"containerOverrides":[{"name":"api","command":["alembic","upgrade","head"]}]}'
```

Create the first Security Admin. `--sso-subject` is the `sub` claim your identity provider puts in that person's ID token:

```bash
aws ecs run-task --cluster sas-waf-prod-api --launch-type FARGATE --task-definition $TASK_DEF \
  --network-configuration "$NET" \
  --overrides '{"containerOverrides":[{"name":"api","command":["python","-m","app.cli","create-admin","--email","you@example.com","--name","Your Name","--sso-subject","<IdP sub>"]}]}'
```

This works only while no Security Admin exists. The task output is in the CloudWatch log group `/ecs/sas-waf-prod-api`.

---

## 11. Publish the console

```bash
cd WAF_PLATFORM
npm ci
npm run build
aws s3 sync dist s3://$(out sas-waf-app SpaBucketName) --delete
aws cloudfront create-invalidation --distribution-id $(out sas-waf-app DistributionId) --paths "/*"
cd ..
```

Open `https://waf.example.com` and sign in with SSO.

---

## 12. Connect your accounts

1. In the console, go to **WAF inventory → Accounts → Register account**. Add each pilot account: account ID, name, environment, owner team and the regions where it runs WAF. The role ARNs are derived from the account ID (the StackSet roles).
2. Go to **Governance → Users & access → Provision user** to give your team access. Pick a role for each person (Security Admin, Security Analyst, SOC Analyst, AWS Administrator, Application Owner, Auditor, Executive, Read Only) and, for Application Owners, the accounts they own.
3. Click the **refresh** button in the top bar to start the first sync, or wait for the next scheduled run (telemetry every 30 minutes, full discovery every 6 hours). The first full discovery fills in Web ACLs, rules and endpoints.
4. Check **Governance → Platform health**. Each pilot account's collector should be **Healthy**. A **Degraded** or **Unavailable** collector shows the AWS error (usually a missing StackSet instance, a region that is not enabled, or an SCP that blocks the role).

---

## 13. Enable controlled response (optional, per Web ACL)

The platform blocks IPs by adding them to a **platform-owned IP set**. Before an IP block can be approved for a Web ACL, add to that Web ACL:

1. An IP set (IPv4), for example `sas-platform-blocklist`.
2. A rule whose name starts with `SAS-Platform-Block` (for example `SAS-Platform-Block`), type *IP set*, action **Block**, at a high priority.

Rule action changes, rate limits, drift remediation and Web ACL association need no preparation. Every change still needs a simulation, guardrail checks, the required approvers, and post-change verification.

---

## 14. Add full WAF logs (optional)

For accounts that already log WAF traffic to an S3 bucket named `aws-waf-logs-*`:

1. List their account IDs in the platform stack parameter `LoggingAccountIds` and redeploy step 6.
2. In each of those accounts, configure **S3 replication** from the WAF log bucket to the platform bucket (`WafLogBucketName` output of `sas-waf-platform`).

New log files are ingested automatically, and those accounts show **Full** visibility instead of **Sampled**.

---

## 15. Roll out to the whole organization

After the pilot accounts look right for a few days, add more OUs from the management account:

```bash
aws cloudformation create-stack-instances --stack-set-name sas-waf-roles \
  --deployment-targets OrganizationalUnitIds=<ou-1>,<ou-2> --regions $AWS_REGION
```

Auto-deployment adds the roles to new accounts that join those OUs. Register the new accounts in the console (step 12).

---

## Updating the platform

| What changed | Do this |
|---|---|
| Backend code | Step 8 with a new `VERSION` → redeploy step 9 with the new `ImageUri` → run the schema task in step 10 |
| Lambda code | Step 5 with a new `VERSION` → redeploy step 6 with the new `ArtifactPrefix` |
| Console code | Step 11 |
| Member-account roles | From the management account: `aws cloudformation update-stack-set --stack-set-name sas-waf-roles --template-body file://infra/stacksets/cross-account-waf-roles.yaml --capabilities CAPABILITY_NAMED_IAM --parameters ParameterKey=CentralAccountId,UsePreviousValue=true ParameterKey=DiscoveryExternalId,UsePreviousValue=true ParameterKey=ResponseExternalId,UsePreviousValue=true` |

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Sign-in returns **403 MFA required** | The ID token's `amr` claim lacks `mfa`. Enforce MFA for the OIDC application in your identity provider. |
| Sign-in returns **User is not provisioned for this platform** | No active user has that `sub`. Use step 10 for the first admin; after that a Security Admin adds users in **Users & access**. |
| An account's collector is **Unavailable** with `AccessDenied` on `sts:AssumeRole` | The StackSet instance is missing in that account, the external ID differs, or an SCP blocks the role. Check the StackSet instance status in the management account. |
| Collector **Degraded** for one region or service | The account does not use that region, or an SCP denies that API. The other accounts and regions keep syncing. |
| Console shows **502/504** for API calls | CloudFront cannot reach the ALB: check the origin DNS record and that the ALB certificate covers `AlbOriginDomain`. |
| Approving an IP block returns **409** | The Web ACL has no `SAS-Platform-Block*` IP-set rule. See step 13. |
| Threat intelligence shows **Degraded** | A provider key is missing, invalid or rate-limited. Scoring continues from WAF telemetry only. |

---

## Security notes

- The browser never talks to AWS and never holds AWS credentials; it only calls the platform API with an HttpOnly, Secure, SameSite=Strict session cookie.
- Member-account write access is limited to the approval workflow: the response role requires an approval ID and the approver's identity, and every change is verified and recorded in an append-only audit trail (exportable as CSV).
- Allow-listed entities (payment gateways, partners, internal ranges) can never be blocked; the check runs in the database at request time and again before execution.
- Secrets (database password, OIDC client secret, external IDs, threat-intelligence keys) live in AWS Secrets Manager, encrypted with the platform KMS key.

---

## Developing and testing

Contributors can run the automated tests locally; PostgreSQL and Redis run in Docker:

```bash
docker compose up -d --wait postgres redis

cd backend
python -m venv .venv && . .venv/bin/activate      # Git Bash on Windows: . .venv/Scripts/activate
pip install -e ".[dev]"
pytest -q && ruff check .

cd ../lambdas
pip install -e ".[dev]"
pytest -q && ruff check .
cfn-lint ../infra/stacksets/*.yaml ../infra/central_account/*.yaml

cd ../WAF_PLATFORM
npm ci && npm run build
```

More detail: [`CLAUDE.md`](CLAUDE.md) (architecture, rules, scoring models), [`infra/README.md`](infra/README.md) (infrastructure and cost), [`docs/`](docs/) (requirements and changelog).
