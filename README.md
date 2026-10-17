# SAS WAF Security Platform — Self-Hosted Staging Setup

This branch (`staging`) runs the whole platform on **one EC2 instance** in your AWS Organization's central account. PostgreSQL, Redis, the API, the sync pipeline and the HTTPS console all run on that instance with Docker Compose. It reads **real-time WAF data** from your member accounts.

> The full AWS-native deployment (RDS, Lambda, Step Functions, ECS, CloudFront) is on the `dev` branch.

## What it costs

The only billable resources are the instance and the two things attached to it:

| Item | us-east-1 on-demand | $/month |
|---|---|---:|
| EC2 `t3.medium` (4 GB; recommended) — or `t3.small` (2 GB) | $0.0416/h — or $0.0208/h | 30.37 — or 15.18 |
| EBS gp3 30 GB (root volume) | $0.08/GB | 2.40 |
| Public IPv4 address (Elastic IP, attached) | $0.005/h | 3.65 |
| **Total** | | **≈ $36** — or **≈ $21** with `t3.small` |

Everything else is free: IAM roles, the StackSet, CloudFormation, the security group, SSM Parameter Store (standard parameters), Session Manager, and the TLS certificate (Caddy's own CA, or Let's Encrypt).

Small usage-based charges can still appear: CloudWatch `GetMetricData` ($0.01 per 1,000 metrics requested by the telemetry sync — typically cents per month for a few accounts) and normal data transfer. A 1-year Savings Plan or Reserved Instance lowers the instance price further.

### Compared with the `dev` branch

| | `staging` (this branch) | `dev` (AWS-native) |
|---|---|---|
| Runs on | 1 EC2 instance | ECS Fargate, Lambda, Step Functions, RDS Multi-AZ, ElastiCache |
| Monthly cost | ≈ $21–36 | ≈ $345–407 |
| Sign-in | Optional: operator sign-in by email (admin-only network) and/or SSO | SSO with MFA |
| High availability | No (single instance; data on its EBS volume) | Yes (Multi-AZ) |
| Full WAF logs (S3) | Not supported; all accounts show **Sampled** visibility | Supported |
| Backups | Manual (see *Operating the instance*) | Automated RDS backups |

---

## How it works

```
Management account               Central account: ONE EC2 instance (docker compose)          Member accounts
──────────────────               ─────────────────────────────────────────────────           ───────────────
StackSet (free) ───────────────────────────────────────────────────────────────────────────► SASWafDiscoveryRole
                                 worker   every 30 min / 6 h ── assume role (instance role) ─► SASWafResponseRole
                                 api      FastAPI (approvals execute through the response role)
                                 web      Caddy: HTTPS console + reverse proxy ◄── admins only (security group)
                                 postgres, redis, ttl-expiry
```

| Container | Replaces (on `dev`) |
|---|---|
| `worker` (`python -m selfhosted_worker`) | Lambda collectors + Step Functions + EventBridge schedules |
| `api` | ECS Fargate API |
| `web` (Caddy) | S3 + CloudFront + ALB |
| `postgres`, `redis` | RDS PostgreSQL, ElastiCache |
| `ttl-expiry` | ECS scheduled task |
| SSM Parameter Store | Secrets Manager |

The instance uses an IAM **instance role** (`SASStagingHostRole`); no access keys exist anywhere. Member-account roles trust only that role, only with your external IDs, and the host may only assume roles inside your organization.

---

## 1. Before you start

| You need | Notes |
|---|---|
| AWS Organization | Management account access (for the StackSet) and a central account (for the instance) |
| AWS CLI v2 | `aws --version` |
| Your organization ID | `aws organizations describe-organization --query Organization.Id --output text` (management account) |
| Your admin IP range | The only network allowed to open the console, e.g. `198.51.100.7/32` (`curl -s https://checkip.amazonaws.com`) |
| A public subnet in the central account | The default VPC's subnets work (`aws ec2 describe-subnets --filters Name=default-for-az,Values=true`) |

> The member-account role names are fixed (`SASWafDiscoveryRole`, `SASWafResponseRole`). A member account can serve **either** this staging host **or** the `dev` deployment at one time, not both.

Commands are for Bash (Linux, macOS, Git Bash or WSL). Set your region:

```bash
export AWS_REGION=eu-west-1
```

---

## 2. Store the secrets (central account)

Generate the two external IDs and keep them in SSM Parameter Store (standard parameters are free):

```bash
DISCOVERY_EXTERNAL_ID=$(openssl rand -hex 32)
RESPONSE_EXTERNAL_ID=$(openssl rand -hex 32)
aws ssm put-parameter --name /sas-waf-staging/discovery-external-id --type SecureString --value "$DISCOVERY_EXTERNAL_ID"
aws ssm put-parameter --name /sas-waf-staging/response-external-id --type SecureString --value "$RESPONSE_EXTERNAL_ID"
```

The repository is private, so give the instance a **read-only** GitHub token (fine-grained token, this repository only, *Contents: Read-only*):

```bash
aws ssm put-parameter --name /sas-waf-staging/github-token --type SecureString --value '<github token>'
```

Optional parameters (skip any you don't use):

| Parameter | Value |
|---|---|
| `/sas-waf-staging/ti-keys-json` | `{"abuseipdb": "<key>", "greynoise": "<key>", "virustotal": ""}` (SecureString) |
| `/sas-waf-staging/oidc-issuer`, `oidc-client-id`, `oidc-client-secret` | Only if you also want SSO sign-in (redirect URL `https://<console address>/api/v1/auth/callback`) |

---

## 3. Launch the instance (central account)

```bash
aws cloudformation deploy --stack-name sas-waf-staging \
  --template-file infra/staging/host.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    VpcId=<vpc-id> \
    SubnetId=<public-subnet-id> \
    AdminCidr=198.51.100.7/32 \
    OrganizationId=o-abc123defg \
    InstanceType=t3.medium
```

Optional parameters: `SiteAddress` (a DNS name you point at the Elastic IP), `CaddyTls` (an email address for a free Let's Encrypt certificate; needs `SiteAddress` and `AllowHttpFromAnywhere=true`), `VolumeSize`, `Branch`.

Read the outputs:

```bash
aws cloudformation describe-stacks --stack-name sas-waf-staging --query "Stacks[0].Outputs" --output table
```

The instance installs Docker, clones this branch, writes its `.env` from Parameter Store and starts the stack. The first boot takes about **10 minutes** (it builds the images).

---

## 4. Deploy the member-account roles (management account)

Switch to the **management account**. Enable StackSets trusted access once (console: *CloudFormation → StackSets → Enable trusted access*, or `aws organizations enable-aws-service-access --service-principal member.org.stacksets.cloudformation.amazonaws.com`).

Use the same external IDs as step 2. In a new shell, read them back from the central account with `aws ssm get-parameter --with-decryption --name /sas-waf-staging/discovery-external-id --query Parameter.Value --output text` (and the same for `response-external-id`).

```bash
aws cloudformation create-stack-set --stack-set-name sas-waf-roles \
  --permission-model SERVICE_MANAGED --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_NAMED_IAM \
  --template-body file://infra/stacksets/cross-account-waf-roles.yaml \
  --parameters \
    ParameterKey=CentralAccountId,ParameterValue=<central account id> \
    ParameterKey=DiscoveryExternalId,ParameterValue=$DISCOVERY_EXTERNAL_ID \
    ParameterKey=ResponseExternalId,ParameterValue=$RESPONSE_EXTERNAL_ID \
    ParameterKey=CollectorRoleName,ParameterValue=SASStagingHostRole \
    ParameterKey=ResponseExecutorRoleName,ParameterValue=SASStagingHostRole

aws cloudformation create-stack-instances --stack-set-name sas-waf-roles \
  --deployment-targets OrganizationalUnitIds=<pilot OU id> --regions $AWS_REGION
```

Start with a pilot OU of a few accounts. IAM is global, so one region is enough.

---

## 5. Create the first administrator (central account)

Open a shell on the instance with Session Manager (no SSH key or port 22 needed; the command is in the `ConnectCommand` output):

```bash
aws ssm start-session --target <instance id>
```

On the instance:

```bash
sudo -i
tail -n 20 /var/log/sas-waf-bootstrap.log     # bootstrap finished?
cd /opt/sas-waf && docker compose ps           # api healthy; web, worker, ttl-expiry running
docker compose exec api python -m app.cli create-admin \
  --email you@example.com --name "Your Name" --sso-subject operator:you@example.com
```

`--sso-subject` only matters if you add SSO later (then use the `sub` claim from your identity provider).

---

## 6. Open the console

1. Open the `ConsoleUrl` output (`https://<elastic ip>`) from your admin network.
2. With the default `CaddyTls=internal`, the browser warns about the certificate. Either accept it, or trust Caddy's root certificate once: run `docker compose exec web cat /data/caddy/pki/authorities/local/root.crt` on the instance, then import it into your browser or OS trust store.
3. Enter your email and click **Sign in**. Every sign-in is recorded in the audit trail.

## 7. Connect your accounts

1. **WAF inventory → Accounts → Register account** for each pilot account (account ID, name, environment, owner, regions with WAF).
2. **Governance → Users & access → Provision user** for each admin. Approvals need a second person: a requester can never approve their own change.
3. Click **refresh** in the top bar, or wait for the schedule (full discovery at start-up and every 6 hours, telemetry every 30 minutes).
4. **Governance → Platform health**: each account should be **Healthy**. **Unavailable** with `AccessDenied` means the StackSet instance or external ID is wrong for that account.

## 8. Enable IP blocks (optional, per Web ACL)

Add an IP set (e.g. `sas-platform-blocklist`) and a rule whose name starts with `SAS-Platform-Block` (type *IP set*, action **Block**) to each Web ACL where you want approved IP blocks. Rule action changes, rate limits, drift remediation and Web ACL association need no preparation.

---

## Operating the instance

All commands run on the instance (`aws ssm start-session …`, then `sudo -i; cd /opt/sas-waf`).

| Task | Command |
|---|---|
| Status | `docker compose ps` |
| Logs | `docker compose logs -f api worker` |
| Update to the latest `staging` | `git pull && docker compose up -d --build` |
| Restart | `docker compose restart` |
| Back up the database | `docker compose exec -T postgres pg_dump -U sas sas_waf \| gzip > /root/sas_waf-$(date +%F).sql.gz` |
| Restore a backup | `gunzip -c <file> \| docker compose exec -T postgres psql -U sas sas_waf` |
| Change a setting | edit `.env`, then `docker compose up -d` |

- **Pause costs:** stopping the instance (`aws ec2 stop-instances`) stops the instance charge; EBS and the Elastic IP are still billed while it is stopped (≈ $6/month). Data survives stop/start.
- **Copy backups off the instance** (for example to your workstation, or to an S3 bucket you already have). A backup on the same disk does not protect against losing the instance.
- **Remove everything:** delete the `sas-waf-staging` stack (this deletes the instance and its data — back up first), delete the SSM parameters, and remove the StackSet instances and the StackSet from the management account.

---

## Security notes

- **Operator sign-in has no password.** Anyone who can reach the console can sign in as any provisioned user. It is safe only because the security group admits **only `AdminCidr`** on port 443. Keep `AdminCidr` narrow (a `/32` or your VPN), never `0.0.0.0/0`. The backend refuses operator sign-in when `SAS_ENVIRONMENT=production`.
- To require real authentication, add the OIDC parameters (step 2) and their values to `/opt/sas-waf/.env`, set `OPERATOR_LOGIN=false`, and run `docker compose up -d`.
- No AWS access keys exist: the containers use the instance role through IMDSv2. The browser never talks to AWS.
- Every WAF change still goes through simulation, allow-list guardrails, approval by a different person, execution, verification and the append-only audit trail.
- PostgreSQL and Redis listen on the instance's loopback only; the only open ports are 443 (and 80 for the HTTPS redirect), limited to `AdminCidr` by default.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Console does not load | Your IP is not in `AdminCidr` (update the stack), or the first boot is still building: `tail /var/log/sas-waf-bootstrap.log`. |
| Bootstrap log shows `git clone` failed | The repository is private: add `/sas-waf-staging/github-token` (step 2), then delete and recreate the stack. |
| `No active user with that email` | Create the first admin (step 5); later users are added in **Users & access**. |
| Account **Unavailable**, `AccessDenied` on `sts:AssumeRole` | StackSet instance missing in that account, external IDs differ between SSM and the StackSet, the StackSet was created without `CollectorRoleName`/`ResponseExecutorRoleName` = `SASStagingHostRole`, or an SCP blocks it. |
| Account **Degraded**, `Unable to locate credentials` | The containers cannot reach the instance role. The launch template sets the IMDS hop limit to 2; check it was not changed. |
| Approving an IP block returns **409** | The Web ACL has no `SAS-Platform-Block*` IP-set rule (step 8). |
| `password authentication failed` after editing `.env` | `POSTGRES_PASSWORD` only applies when the database volume is first created. Put the original value back. |

---

## Developing and testing

```bash
docker compose up -d --wait postgres redis        # without a .env, only the test dependencies start

cd backend && python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
pytest -q && ruff check .

cd ../lambdas && pip install -e ".[dev]"
pytest -q && ruff check .
cfn-lint ../infra/staging/host.yaml ../infra/stacksets/*.yaml ../infra/central_account/*.yaml

cd ../WAF_PLATFORM && npm ci && npm run build
```

To run the full self-hosted stack on your own machine: `cp .env.example .env`, set `SITE_ADDRESS=localhost` and the other values, then `docker compose up -d --build` and open `https://localhost`. It syncs AWS data only if the machine has AWS credentials that the member roles trust.

More detail: [`CLAUDE.md`](CLAUDE.md), [`infra/README.md`](infra/README.md), [`docs/`](docs/).
