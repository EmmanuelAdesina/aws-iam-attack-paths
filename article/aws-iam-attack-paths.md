# AWS IAM Attack Paths: How Real Cloud Breaches Actually Happen

---

## Introduction

Most AWS IAM explanations describe a permission system. Users belong to groups. Groups have policies. Policies define allowed and denied API calls.

That model is accurate. It is also incomplete.

In production cloud environments, IAM behaves as a distributed trust evaluation engine — a system that determines not just what an identity can do, but **what identities can become, and what they can access after that transition**.

Cloud breaches rarely result from broken encryption or exploited application vulnerabilities. They result from misconfigured trust relationships that allow an attacker to traverse the identity graph from low privilege to high privilege using legitimate AWS mechanisms.

This article traces that traversal from start to finish.

---

## Part 1 — How AWS Authorization Actually Works

Every AWS API call triggers a structured evaluation process:

```
Identity presents credentials
           ↓
AWS evaluates all applicable policy layers:
  · Identity-based policies
  · Resource-based policies
  · Permission boundaries
  · SCPs (AWS Organizations)
  · Session policies (STS)
           ↓
Explicit DENY anywhere → Request denied
No ALLOW anywhere      → Request denied (default deny)
ALLOW + no DENY        → Request permitted
```

The key insight: **AWS does not rely on a single policy**. Access is the intersection of multiple independent layers. An engineer who understands only identity-based policies will leave the resource policy layer unreviewed — and attackers will find it.

---

## Part 2 — The Trust Graph Model

IAM should not be visualized as a flat permission table. It is a directed graph:

- **Nodes** are identities: IAM users, roles, service principals, AWS accounts
- **Edges** are trust relationships: who can assume what, what can call what
- **Reachability** defines risk: if a low-privilege node has a path to a high-privilege node, that path is an attack vector

An attacker who gains control of any node searches for edges leading toward privilege. The question is never *"what can this identity do?"* — it is *"where can this identity go?"*

---

## Part 3 — The Attack, Stage by Stage

### Stage 1 — Initial Access: Credential Exposure

The attack begins with valid credentials. The most common sources:

| Leak Vector | Common Cause |
|---|---|
| Public GitHub repository | Access keys hardcoded in source or committed `.env` files |
| CI/CD pipeline logs | Credentials printed during build steps |
| Developer machine | Keys stored in plaintext in `~/.aws/credentials` |
| S3 bucket | Configuration files exposed via misconfigured bucket policy |

The attacker does not need to break anything to reach this stage. They scan, find, and authenticate. The IAM graph is now theirs to query.

---

### Stage 2 — Enumeration: Mapping the Graph

Before escalating, the attacker maps what is available. This stage is deliberately quiet:

```bash
# Confirm the identity and account
aws sts get-caller-identity

# Discover what roles exist
aws iam list-roles

# Map reachable permissions without triggering action-based alerts
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/dev-user \
  --action-names sts:AssumeRole iam:PassRole iam:CreatePolicyVersion
```

`iam:SimulatePrincipalPolicy` is particularly dangerous from a detection standpoint. It is a read-only API call that returns a complete map of effective permissions without performing a single privileged action. Most SIEM rules do not alert on it.

**Enumeration frequently completes without triggering a single alert.**

---

### Stage 3 — Privilege Escalation: Traversing the Graph

The attacker now selects a path. Multiple paths may exist simultaneously.

**Path A — AssumeRole Chain**

A trust policy allows the compromised identity to assume a higher-privilege role. That role may in turn have `sts:AssumeRole` on a production role. The attacker hops:

```
dev-user → assume → DeploymentRole → assume → ProductionAdminRole
```

Each hop is a legitimate AWS API call with valid credentials. From CloudTrail's perspective, authorized role assumptions are happening. Without anomaly detection on role chain length or privilege deltas, this is invisible.

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/ProductionAdminRole \
  --role-session-name recon-session
```

**Path B — PassRole Abuse**

The compromised identity has `iam:PassRole` on a privileged role. Combined with `ec2:RunInstances`, the attacker launches an EC2 instance with that role attached:

```bash
aws ec2 run-instances \
  --image-id ami-0abcdef1234567890 \
  --instance-type t2.micro \
  --iam-instance-profile Name=AdminInstanceProfile
```

The instance launches. The attacker calls the Instance Metadata Service from inside the instance:

```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/AdminRole
```

Full `AdministratorAccess` credentials are returned. The attacker never directly assumed an admin role. IAM policies blocking direct `sts:AssumeRole` on admin roles did not help.

**Path C — Resource Policy Bypass**

S3 bucket policies are evaluated independently of IAM identity policies. A single misconfigured bucket policy grants access regardless of how tightly IAM roles are scoped:

```json
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::company-sensitive-data/*"
}
```

`Principal: "*"` grants access to any entity on the internet. No IAM identity is required. The attacker never touches the identity graph — they go around it.

**Path D — Cross-Account Trust**

A role in the target account trusts a principal in an external account:

```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::999999999999:root"
  },
  "Action": "sts:AssumeRole"
}
```

If the attacker controls account `999999999999`, or any identity within it, they can assume this role. The CloudTrail logs showing this assumption are written to the **target** account — the source account sees no relevant activity.

---

### Stage 4 — Lateral Movement: Expanding Across Boundaries

With elevated privileges, the attacker expands:

- `Development account` → `Shared Services account` → `Production account`
- Application roles → Secrets Manager → Database credentials
- IAM roles → EC2 Instance Profiles → IMDSv1 credential harvest across a fleet

Cross-account movement is particularly dangerous: **CloudTrail is account-scoped**. An attacker pivoting from Account B into Account A generates CloudTrail events in Account A, but the role assumption that *initiated* the pivot may only appear in Account B's logs — which the Account A security team may not have access to.

Detecting this requires centralized log aggregation across the Organization. Many teams implement this after their first incident.

---

### Stage 5 — Persistence: Control Plane Implants

Standard incident response: terminate instances, rotate credentials, redeploy workloads.

IAM persistence survives all of this.

| Persistence Technique | Why It Survives |
|---|---|
| Create new IAM user with access keys | Lives in control plane, unaffected by workload teardown |
| Add rogue trust policy to existing role | Modifies a legitimate role; easy to overlook in audit |
| Create additional access key on existing role | Second key active while first is rotated out |
| Modify SCP exception list | Persists across every account in the Organization |

The most dangerous technique is trust policy modification on an **existing** role. Security teams monitor for new IAM user creation. Fewer monitor for changes to trust policies on roles that already exist. The modified role looks legitimate in every IAM review — it is the same role that was there before. Only the `AssumeRolePolicyDocument` changed.

**Detection gap: `iam:UpdateAssumeRolePolicy` events in CloudTrail are the signal most teams miss.**

---

### Stage 6 — Impact: What Full Compromise Looks Like

| Impact Category | Real-World Examples |
|---|---|
| Data exfiltration | S3 bulk download; RDS snapshot copied to attacker-controlled account |
| Ransomware | KMS customer-managed key deletion; S3 object deletion with versioning disabled |
| Infrastructure destruction | EC2 and RDS termination across regions |
| Cryptomining | Spot fleet launched in unrestricted regions; costs reach five figures before detection |
| Long-term persistence | Dormant backdoor user activated months after initial compromise |
| Supply chain | Shared services account compromise propagates to all consumer accounts |

---

## Part 4 — Defensive Architecture

The defensive model follows directly from the attack model.

**Stop thinking about permissions. Start thinking about graph reachability.**

### Reduce Trust Surface Area

Every trust relationship is a potential attack edge. Audit trust policies quarterly. Any trust relationship that cannot be justified with a specific, documented use case should be removed.

Replace account-root principals with specific role ARNs:

```json
// Vulnerable: trusts every identity in the account
"Principal": {"AWS": "arn:aws:iam::123456789012:root"}

// Hardened: trusts only the deployment pipeline role
"Principal": {"AWS": "arn:aws:iam::123456789012:role/CICDDeploymentRole"}
```

### Enforce Conditions on Role Assumption

Trust policies support `Condition` blocks. Use them:

```json
{
  "Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::123456789012:role/SecurityEngineer"},
  "Action": "sts:AssumeRole",
  "Condition": {
    "Bool": {"aws:MultiFactorAuthPresent": "true"},
    "StringEquals": {"sts:ExternalId": "unique-external-id-per-relationship"}
  }
}
```

MFA conditions make stolen credential exploitation significantly harder. External IDs prevent confused deputy attacks in cross-account scenarios.

### Restrict PassRole to Specific Targets

```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::123456789012:role/ApplicationRole",
  "Condition": {
    "StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}
  }
}
```

Scope `iam:PassRole` to specific role ARNs and specific service principals. Wildcard resource on PassRole is equivalent to wildcard on AssumeRole.

### Use SCPs as Hard Guarantees

SCPs encode invariants — behaviors that should never be possible regardless of IAM policy configuration:

```json
{
  "Effect": "Deny",
  "Action": [
    "cloudtrail:DeleteTrail",
    "cloudtrail:StopLogging",
    "iam:CreateUser",
    "iam:DeleteAccountPasswordPolicy"
  ],
  "Resource": "*"
}
```

If CloudTrail should never be disabled, that belongs in an SCP, not just a verbal agreement.

### Build Detection Around Control Plane Events

Attackers operating through IAM leave data plane footprints incidentally. The reliable signals are in CloudTrail:

| Event | What It May Indicate |
|---|---|
| `AssumeRole` with unusual chaining pattern | Active role chain traversal |
| `UpdateAssumeRolePolicy` | Trust policy modification / persistence implant |
| `CreateUser` outside automated provisioning | Backdoor account creation |
| `CreateAccessKey` on existing entity | Second credential for persistence |
| `PutBucketPolicy` with wildcard principal | S3 exposure via resource policy |
| `AttachRolePolicy` with admin policies | Privilege escalation attempt |

---

## Conclusion

AWS IAM is not a permission system with an identity layer on top.

It is an identity system with a permission system as one of its outputs.

The input to the authorization engine is not *"what is this identity allowed to do"* — it is *"what has this identity become through trust relationships, and what does that identity have access to"*.

Cloud breaches are not primarily technical failures. They are **trust design failures**. The path from leaked developer credential to production database exists not because any single policy was misconfigured, but because the graph was never modeled as a graph — and therefore no one noticed the path until an attacker walked it.

Model the graph. Find the paths. Close them before they are used.

---

*Part of the [AWS IAM Attack Paths](../README.md) research project.*
