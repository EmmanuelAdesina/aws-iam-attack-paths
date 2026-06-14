# AWS Documentation Reference Map
### Official Sources Mapped to Attack Context

> This is not a link list.
> Each reference is mapped to the attack behavior it governs and the misconfiguration it prevents.

---

## 1. IAM Core Security Model

**[IAM Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)**

The authoritative AWS guidance on IAM posture. Key principles with attack context:

| Best Practice | Attack It Prevents |
|---|---|
| Use roles instead of long-term credentials | Eliminates credential theft as a persistent foothold |
| Enforce MFA for human users | Blocks account takeover from stolen passwords or access keys |
| Apply least-privilege permissions | Limits blast radius when any identity is compromised |
| Use temporary credentials via STS | Short-lived tokens limit the window of exploitation after leak |
| Rotate and remove unused credentials | Removes dormant attack surface that is rarely monitored |

---

## 2. STS and AssumeRole

**[IAM Roles Overview](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html)**
**[STS AssumeRole API Reference](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)**

The foundation of AWS privilege escalation attacks. Every role assumption traverses trust policy evaluation. Key concepts:

| Mechanism | Security Implication |
|---|---|
| Trust policies control who can assume a role | Misconfigured trust = unauthorized privilege inheritance |
| STS issues time-limited credentials | Reduces exploitation window but does not prevent it |
| Cross-account assumption is native AWS functionality | Creates lateral movement paths across account boundaries |
| ExternalId condition prevents confused deputy attacks | Required for all third-party cross-account trust |

---

## 3. IAM Policy Types and Evaluation Logic

**[IAM Policy Types](https://aws.amazon.com/blogs/security/iam-policy-types-how-and-when-to-use-them/)**
**[Policy Evaluation Logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)**

AWS evaluates multiple independent policy layers per request. Understanding all layers is required for accurate threat modeling:

| Policy Layer | What It Controls | Exploitation Pattern |
|---|---|---|
| Identity-based policy | What the role is allowed to do | Overpermissioned roles enable escalation |
| Resource-based policy | Who can access the resource | Wildcard principals bypass IAM entirely |
| Permission boundary | Maximum effective permissions | Misconfigured boundaries create gaps |
| SCP | Organization-wide hard limits | Missing SCPs remove the safety net |
| Session policy | Per-session restrictions | Rarely used; gaps create false confidence |

---

## 4. S3 Security Model

**[S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)**
**[IAM vs. S3 Bucket Policy Interaction](https://aws.amazon.com/blogs/security/iam-policies-and-bucket-policies-and-acls-oh-my-controlling-access-to-s3-resources/)**

S3 access is governed by two independent policy systems evaluated simultaneously:

```
Access Granted When:
  IAM identity policy allows AND bucket policy allows (or is absent)
  OR bucket policy allows regardless of IAM (for cross-account or public access)

Access Denied When:
  Either layer contains an explicit Deny
  OR neither layer contains an Allow
```

Critical misconfigurations and their impact:

| Misconfiguration | Impact |
|---|---|
| `"Principal": "*"` in bucket policy | Internet-public access, no credentials required |
| Block Public Access disabled | Allows public ACLs and policies to take effect |
| Wildcard `s3:*` in bucket policy | Enables upload, delete, and overwrite by unauthorized principals |
| No encryption enforcement condition | Data readable in plaintext over HTTP |

---

## 5. CloudTrail — Detection Coverage

**[CloudTrail Documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)**

CloudTrail is the primary detection surface for IAM-based attacks. Key configuration gaps:

| Gap | Attack Behavior That Goes Undetected |
|---|---|
| Data events not enabled on S3 | S3 public access exfiltration has no log entry |
| No multi-region trail | Attacker operates in a non-covered region |
| CloudTrail log validation disabled | Log tampering is undetectable |
| No CloudWatch Alerts on IAM events | `UpdateAssumeRolePolicy` and `CreateUser` go unnoticed |
| No centralized logging across accounts | Cross-account pivots have no correlated view |

CloudTrail events that **must** trigger alerts:
- `iam:UpdateAssumeRolePolicy` — trust policy modification
- `iam:CreateUser` — new IAM identity outside provisioning automation
- `iam:CreateAccessKey` on any entity
- `sts:AssumeRole` with role chaining exceeding two hops
- `s3:PutBucketPolicy` with wildcard principal

---

## 6. AWS Organizations and SCPs

**[Service Control Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)**

SCPs operate above IAM. They define invariants — behaviors that cannot occur regardless of IAM policy configuration:

| SCP Use Case | IAM Attack It Prevents |
|---|---|
| Deny `cloudtrail:DeleteTrail` | Prevents attackers from erasing evidence |
| Deny `iam:CreateUser` outside automation | Prevents backdoor user creation |
| Deny `guardduty:DeleteDetector` | Prevents detection evasion |
| Restrict allowed regions | Limits attacker's ability to operate outside monitored regions |
| Deny `iam:*` on the management account | Protects organizational root from lateral movement |

---

## 7. IAM Access Analyzer

**[IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)**

Access Analyzer identifies resource policies that allow access from outside the account or organization:

- External access findings: S3 buckets, KMS keys, Lambda functions, SQS queues, IAM roles accessible from outside the trust zone
- Unused access findings: roles, users, and permissions that have not been used within a configurable window
- Policy validation: checks policies against AWS best practices before deployment

**Recommended configuration:** Enable Access Analyzer at the Organization level. Archive expected findings. Treat any new unarchived finding as an incident until confirmed benign.

---

## 8. Shared Responsibility Model

**[AWS Security Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/security.html)**

AWS secures the infrastructure. Customers secure the configuration.

| Layer | Responsible Party | Common Failure |
|---|---|---|
| Physical infrastructure | AWS | Not customer-relevant |
| Network isolation | AWS | Not customer-relevant |
| IAM configuration | Customer | Misconfigured trust policies |
| Credential management | Customer | Long-lived keys, no rotation |
| Resource policies | Customer | Wildcard principals, public S3 |
| CloudTrail configuration | Customer | Incomplete coverage, no alerts |
| SCP design | Customer | Missing guardrails |

**The practical implication:** Every IAM misconfiguration in this repository is within customer responsibility. AWS does not prevent it. Customers must detect and remediate it.

---

## Attack Model Summary

```
Credential Exposure          ← Customer responsibility to prevent
       ↓
IAM Enumeration              ← Customer responsibility to detect
       ↓
Trust Graph Traversal        ← Customer responsibility to restrict
       ↓
AssumeRole / PassRole Abuse  ← Customer responsibility to monitor
       ↓
Cross-Account Pivot          ← Customer responsibility to architect against
       ↓
Production Compromise        ← The outcome of all the above failures
```

---

*Part of the [AWS IAM Attack Paths](../README.md) research project.*
