# SAS WAF Platform — Infrastructure

| Template | Where | What |
|---|---|---|
| `stacksets/cross-account-waf-roles.yaml` | all 39 spoke accounts (SERVICE_MANAGED StackSet) | `SASWafDiscoveryRole` (read-only), `SASWafResponseRole` (approved writes only) |
| `central_account/platform.yaml` | central security account | VPC, 5 interface endpoints + S3 gateway endpoint, RDS PostgreSQL 16 Multi-AZ, Redis 7, KMS, secrets, ECR, WAF-log staging + 7-year Object Lock audit buckets, SNS, the 7 pipeline Lambdas, Step Functions sync + EventBridge schedules |
| `central_account/app.yaml` | central security account | FastAPI on ECS Fargate, ALB + AWS WAF (only reachable via CloudFront), SPA on S3 + CloudFront, TTL-expiry scheduled task |
| `central_account/step_functions.asl.json` | uploaded with the Lambda build | sync state machine definition (`${...}` filled by DefinitionSubstitutions) |

Nothing here has been deployed by the build. All templates pass `cfn-lint`; `lambdas/tests/test_infra.py` asserts the security-relevant properties.

## Deploy order (pilot first — Implementation Rule #10)

```bash
# 1. Build Lambda zips (Linux wheels) + stage the ASL, then upload
python lambdas/build.py
aws s3 sync lambdas/dist s3://<artifact-bucket>/releases/<version>/ --exclude ".deps/*"

# 2. Platform stack
aws cloudformation deploy --stack-name sas-waf-platform \
  --template-file infra/central_account/platform.yaml --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides ArtifactBucket=<artifact-bucket> ArtifactPrefix=releases/<version>/ \
    LoggingAccountIds=<6 logging account ids, comma separated> AlertEmail=<soc-approvals@example.com>

# 3. Read the generated external IDs and roll the StackSet out to the 5 PILOT accounts first
aws secretsmanager get-secret-value --secret-id sas-waf-prod/sts/discovery-external-id --query SecretString --output text
aws secretsmanager get-secret-value --secret-id sas-waf-prod/sts/response-external-id --query SecretString --output text
aws cloudformation create-stack-set --stack-set-name sas-waf-roles --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=false --capabilities CAPABILITY_NAMED_IAM \
  --template-body file://infra/stacksets/cross-account-waf-roles.yaml \
  --parameters ParameterKey=CentralAccountId,ParameterValue=<central-account> \
    ParameterKey=DiscoveryExternalId,ParameterValue=<discovery-id> ParameterKey=ResponseExternalId,ParameterValue=<response-id>
aws cloudformation create-stack-instances --stack-set-name sas-waf-roles \
  --deployment-targets OrganizationalUnitIds=<pilot-ou> --regions <home-region>

# 4. Backend image -> ECR (repository from the platform stack output BackendRepositoryUri)
docker build -t <repo-uri>:<version> backend && docker push <repo-uri>:<version>

# 5. Application stack
aws cloudformation deploy --stack-name sas-waf-app \
  --template-file infra/central_account/app.yaml --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides ImageUri=<repo-uri>:<version> AlbCertificateArn=<regional-acm-arn> \
    AlbOriginDomain=origin.waf.example.com OidcIssuer=<issuer> OidcClientId=<client-id> \
    CloudFrontAliases=waf.example.com CloudFrontCertificateArn=<us-east-1-acm-arn>

# 6. Schema migration (one-off task, same image)
aws ecs run-task --cluster sas-waf-prod-api --launch-type FARGATE --task-definition <TaskDefinitionArn> \
  --network-configuration "awsvpcConfiguration={subnets=[<app-subnet-a>],securityGroups=[<AppSecurityGroupId>]}" \
  --overrides '{"containerOverrides":[{"name":"api","command":["alembic","upgrade","head"]}]}'
```

After deploy:

- **DNS:** point `AlbOriginDomain` (CNAME/alias) at output `AlbDnsName`, and the viewer alias at the CloudFront distribution.
- **Secrets:** put real values into `sas-waf-prod/ti/provider-keys` and `sas-waf-prod/oidc/client-secret`.
- **Bootstrap (one-off tasks, same image, same `run-task` command as step 6 with a different command override):**
  `["python","-m","app.cli","create-admin","--email","<you>","--name","<name>","--sso-subject","<IdP sub>"]`
  (works only while no active Security Admin exists), then
  `["python","-m","app.cli","register-accounts","--file","/tmp/accounts.csv"]` for the 5 pilot accounts.
  The image has a read-only root FS, so either bake the CSV into a release image or have the first admin use the
  API instead: `POST /api/v1/governance/accounts` and `POST /api/v1/governance/users` (Security Admin only).
- **Blocklist rule:** before any IP block can be approved, each WebACL needs a platform-owned IP set referenced by a BLOCK rule named `SAS-Platform-Block*`.
- **Frontend:** upload the SPA build (Milestone 5) to output `SpaBucketName`, then invalidate the distribution.
- **Logging accounts:** in each of the 6 full-logging accounts, configure S3 replication of `aws-waf-logs-*` objects into `WafLogBucketName`.
- **Scale out:** after the pilot is verified end-to-end, add the remaining accounts' OUs to the StackSet.

## Monthly cost estimate (us-east-1 on-demand, Oct 2026 list prices, default parameters)

| Component | Basis | $/month |
|---|---|---:|
| RDS PostgreSQL `db.t3.large` Multi-AZ | $0.272/h × 730 | 198.56 |
| RDS gp3 storage 50 GB (Multi-AZ) + backups | 50 GB × $0.23 + ~$1 | 12.50 |
| ElastiCache `cache.t3.micro` (1 node) | $0.017/h | 12.41 |
| NAT Gateway (1 AZ) + ~40 GB processed | $0.045/h + $0.045/GB | 34.65 |
| Interface endpoints: 5 services × 1 AZ | $0.01/h each (+ data) | 37.00 |
| ALB + ~1 LCU | $0.0225/h + $0.008/LCU-h | 22.27 |
| Fargate API: 2 tasks × 0.25 vCPU / 0.5 GB | $0.01234/h per task | 18.02 |
| Fargate TTL worker: 288 runs/day × 1 min | per-minute billing | 1.78 |
| AWS WAF on the platform ALB | 1 WebACL + 4 rules + requests | 9.60 |
| Public IPv4 (NAT EIP + 2 ALB addresses) | $0.005/h each | 10.95 |
| Lambda (~1.27M GB-s, 7 functions) | after free tier | 14.50 |
| Step Functions (~140k transitions) | $0.025 / 1k | 3.40 |
| Secrets Manager (6) + KMS (1 CMK) | | 4.10 |
| CloudWatch Logs (~6 GB ingested, 30-day retention) | | 3.50 |
| S3 (30-day WAF-log staging, audit archive, SPA) + ECR | | 2.50 |
| CloudFront (internal SOC traffic) | inside the always-free tier | 0.00 |
| Data transfer out | | 1.00 |
| Threat-intel APIs | budget line from the master spec | 20.00 |
| **Total (on-demand)** | | **≈ 406.74** |

**This is over the $350 ceiling by about $57 when everything is billed on-demand.** The master spec's estimate left out or undercounted:

- **Interface endpoints:** budgeted at $25, but five services cost $36.50 in one AZ ($73 in two).
- **Public IPv4:** charged since 2024 and not budgeted ($10.95).
- **Platform WAF and Fargate:** neither was in the spec's estimate ($9.60 and $19.80).

Ways to bring it under $350, from smallest change to largest:

| Lever | Saving | Trade-off |
|---|---:|---|
| 1-year RDS Reserved Instance (no upfront) for `db.t3.large` Multi-AZ | ≈ −61 | 1-year commitment; no architecture change |
| `DbInstanceClass=db.t4g.large` (Graviton; supported for PostgreSQL 16) | ≈ −10 | none functional |
| Drop the `logs` and `states` interface endpoints (traffic falls back to NAT; volume is small) | ≈ −14.60 | that traffic leaves the private path (still TLS) |
| `DesiredCount=1` for the API | ≈ −9 | no task redundancy — conflicts with the 99.9% availability target, not recommended |

**Recommended:** reserve the RDS instance, which brings the total to about **$345/month** with no design change. Adding the Graviton switch lands at about **$335**.

`HighAvailabilityEndpoints=true` (endpoints in both AZs) adds $36.50. The template defaults to one AZ and says so in the parameter description.

**Licensing outside this table:** VirusTotal's public API forbids commercial use. AbuseIPDB and GreyNoise free tiers have their own terms. Paid tiers suitable for a financial institution (VirusTotal especially) can cost far more than the $20 budget line. Decide the providers before production. Running with only AbuseIPDB + GreyNoise is supported (the worker degrades gracefully per provider).
