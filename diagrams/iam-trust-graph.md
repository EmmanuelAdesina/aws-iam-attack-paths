# IAM Trust Graph — Topology and Threat Model

> Most IAM diagrams show permissions.
> This diagram shows **trust relationships** — the edges that define who can become what.

---

## Trust Topology — Normal Operating State

```mermaid
graph LR
    subgraph HUMANS["Human Access Layer"]
        DEV["Developer<br/>Identity"]
        SEC["Security<br/>Team"]
    end

    subgraph ROLES["Role Layer"]
        DEVROLE["Development<br/>Role"]
        DEPLOYROLE["Deployment<br/>Role"]
        PRODROLE["Production<br/>Role"]
        AUDITROLE["Audit<br/>Role"]
    end

    subgraph PIPELINE["Automation Layer"]
        CICD["CI/CD Pipeline<br/>GitHub Actions / CodePipeline"]
    end

    subgraph RESOURCES["Resource Layer"]
        S3["S3<br/>Storage"]
        RDS["RDS<br/>Database"]
        LAMBDA["Lambda<br/>Functions"]
        SECRETS["Secrets<br/>Manager"]
        TRAIL["CloudTrail"]
        CONFIG["AWS Config"]
        GD["GuardDuty"]
    end

    subgraph GUARDRAILS["Governance Layer"]
        SCP["AWS Organizations<br/>SCP"]
    end

    DEV -->|"assumes"| DEVROLE
    DEVROLE -->|"triggers"| CICD
    CICD -->|"assumes"| DEPLOYROLE
    DEPLOYROLE -->|"assumes"| PRODROLE
    SEC -->|"assumes"| AUDITROLE

    PRODROLE --> S3
    PRODROLE --> RDS
    PRODROLE --> LAMBDA
    PRODROLE --> SECRETS

    AUDITROLE --> TRAIL
    AUDITROLE --> CONFIG
    AUDITROLE --> GD

    SCP -. "restricts" .-> DEVROLE
    SCP -. "restricts" .-> DEPLOYROLE
    SCP -. "restricts" .-> PRODROLE

    style HUMANS fill:#0f172a,color:#94a3b8,stroke:#334155
    style ROLES fill:#1a1033,color:#c4b5fd,stroke:#6d28d9
    style PIPELINE fill:#0a1f2e,color:#7dd3fc,stroke:#0284c7
    style RESOURCES fill:#0a1f0f,color:#86efac,stroke:#166534
    style GUARDRAILS fill:#1c1a00,color:#fde68a,stroke:#92400e
```

---

## Trust Boundaries — Where Attacks Happen

```mermaid
graph TD
    B1["Boundary 1<br/>Human → Role<br/>Authentication"]
    B2["Boundary 2<br/>Role → Role<br/>Privilege Escalation"]
    B3["Boundary 3<br/>Role → Resource<br/>Authorization"]
    B4["Boundary 4<br/>Organization → Account<br/>Governance"]

    B1 -->|"weakened by"| W1["No MFA · Long-lived keys<br/>Weak federation config"]
    B2 -->|"weakened by"| W2["Wildcard trust principals<br/>Unscoped AssumeRole · Missing ExternalId"]
    B3 -->|"weakened by"| W3["Resource policy wildcards<br/>S3 public exposure · KMS misconfig"]
    B4 -->|"weakened by"| W4["Missing SCPs · No OU structure<br/>Management account overexposure"]

    style B1 fill:#1e3a5f,color:#bfdbfe,stroke:#1d4ed8
    style B2 fill:#3b1f5e,color:#ddd6fe,stroke:#6d28d9
    style B3 fill:#1a3a2a,color:#bbf7d0,stroke:#15803d
    style B4 fill:#3b2800,color:#fde68a,stroke:#b45309
    style W1 fill:#1c0a0a,color:#fca5a5,stroke:#7f1d1d
    style W2 fill:#1c0a0a,color:#fca5a5,stroke:#7f1d1d
    style W3 fill:#1c0a0a,color:#fca5a5,stroke:#7f1d1d
    style W4 fill:#1c0a0a,color:#fca5a5,stroke:#7f1d1d
```

---

## Trust Flow Analysis

### Boundary 1 — Human → Role (Authentication)

Human identities should never use long-lived IAM user credentials in modern AWS architectures. The correct model:

```
Human Identity
     ↓
Enterprise IdP (Okta, Azure AD, Google Workspace)
     ↓
SAML / OIDC Federation
     ↓
STS Temporary Credentials (15 min – 12 hours)
     ↓
Role Assumption
```

Controls that harden this boundary:
- MFA enforcement at the IdP level
- Short-duration STS sessions
- IP-based conditions on role trust policies
- Access analyzer to surface unused role assumptions

---

### Boundary 2 — Role → Role (Privilege Escalation Surface)

This is where most IAM attacks occur.

A role trust policy controls who (or what) can assume it. The most common misconfiguration:

```json
// Vulnerable: trusts the entire account (every identity)
{
  "Principal": {
    "AWS": "arn:aws:iam::123456789012:root"
  }
}

// Hardened: trusts only the specific pipeline role
{
  "Principal": {
    "AWS": "arn:aws:iam::123456789012:role/CICDDeploymentRole"
  },
  "Condition": {
    "StringEquals": {
      "sts:ExternalId": "unique-id-per-relationship"
    }
  }
}
```

The difference: the first trusts ~every identity in the account. The second trusts one specific role with a verified external ID.

**Every trust policy that references `:root` is granting account-wide assumption rights.**

---

### Boundary 3 — Role → Resource (Authorization)

Resource-based policies are evaluated **independently** of IAM identity policies. Both layers must be reviewed separately.

Common oversight: engineers audit IAM roles thoroughly, then deploy an S3 bucket with a policy that grants access independently of IAM. The role restriction is bypassed entirely.

```
IAM Identity Policy says: "Allow"
Resource Policy says:     "Allow to Principal *"
Effective result:         Anyone on the internet can access
```

This is why `aws s3api get-bucket-policy` should be in every security review checklist, regardless of IAM posture.

---

### Boundary 4 — Organization → Account (Governance)

Service Control Policies operate above IAM. They define what is **never permitted**, regardless of what IAM policies allow.

```json
{
  "Effect": "Deny",
  "Action": [
    "cloudtrail:DeleteTrail",
    "cloudtrail:StopLogging",
    "iam:CreateUser",
    "guardduty:DeleteDetector",
    "config:DeleteConfigRule"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassRole"
    }
  }
}
```

SCPs enforce invariants that IAM policies cannot: behaviors that should be impossible regardless of how permissive any single identity's policies are.

---

## CI/CD Pipelines — The Hidden Privilege Concentration Point

CI/CD systems are among the most dangerous privilege concentration points in AWS environments. They frequently have:

- `sts:AssumeRole` on deployment roles across multiple accounts
- `iam:PassRole` on application roles
- Access to secrets in Secrets Manager or Parameter Store

A compromised pipeline does not give an attacker one account. It gives them every environment the pipeline can deploy to.

Hardening requirements for CI/CD IAM:
- Use OIDC federation, not long-lived access keys stored as CI/CD secrets
- Scope deployment roles to specific actions and resource ARNs
- Separate deployment roles per environment (no single role deploys to both staging and production)
- Enable CloudTrail alerts on assumption of pipeline roles from unexpected principals

---

## Threat Modeling Questions

Before signing off on any IAM architecture, these must be answerable:

1. Which roles trust external principals? Are all of them documented?
2. What is the shortest path from any identity to production data?
3. Which services can assume privileged roles? Are those services hardened?
4. What is the blast radius if the CI/CD pipeline is compromised?
5. Which trust relationships have not been reviewed in the last 90 days?
6. Is there an SCP preventing CloudTrail from being disabled?
7. Would you detect a new cross-account trust relationship added at 2 AM?

The unanswered questions define the attacker's roadmap.

---

## Core Insight

> AWS environments are not secured by permissions.
>
> They are secured by carefully designed **trust relationships** — a directed graph where every edge is a deliberate choice, and every unreviewed edge is a potential attack path.
>
> The primary objective of IAM architecture is not to grant access.
> It is to **control how identities evolve into privileges** across the cloud environment.

---

*Part of the [AWS IAM Attack Paths](../README.md) research project.*
