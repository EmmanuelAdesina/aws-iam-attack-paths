# Security Insights — The Mental Model Behind This Repository

> This document is not a checklist.
> It is the reasoning framework that makes checklists unnecessary.

---

## IAM Is Not What Most Engineers Think It Is

When most people picture AWS IAM, they picture a permission system. Users, roles, policies, allow/deny. A lookup table that governs who can call which API.

That picture is incomplete — and the incompleteness is what attackers exploit.

AWS IAM is better understood as a **distributed authorization engine** built on top of a **directed trust graph**. Every entity in your AWS environment — users, roles, services, accounts — is a node. Every trust relationship between them is a directed edge. Permissions define what a node can *do*. Trust relationships define what a node can *become*.

Attackers do not enumerate permissions. They traverse edges.

---

## The Two Questions That Define Cloud Security Maturity

**Immature posture:** *"Who has access to this resource?"*

**Mature posture:** *"What is the shortest path from any identity in this environment to this resource?"*

The first question is answered by reading a policy document. The second question requires modeling the entire trust graph — and it is the question that determines whether your environment is secure.

---

## How AWS Actually Evaluates Authorization

Every AWS API call triggers a multi-layer evaluation:

```
Request arrives at AWS
         ↓
Is there an explicit DENY anywhere?  →  Yes → DENIED (end)
         ↓ No
Is there an explicit ALLOW?          →  No  → DENIED (end)
         ↓ Yes
Does a Permission Boundary restrict? →  Yes → DENIED (end)
         ↓ No
Does an SCP restrict?                →  Yes → DENIED (end)
         ↓ No
                               ACCESS GRANTED
```

The critical insight: **multiple independent policy layers stack**. An IAM identity policy can allow something that a resource policy or SCP denies. Engineers who understand only one layer leave gaps at the others.

---

## Why Trust Policies Are the Real Attack Surface

An IAM role has two components:

1. **Permission policy** — what the role can do once assumed
2. **Trust policy** — who (or what) is allowed to assume the role

Most security attention goes to the permission policy. Most attacks exploit the trust policy.

A trust policy that specifies `"Principal": {"AWS": "arn:aws:iam::123456789012:root"}` does not restrict access to a specific identity. It grants assumption rights to **every identity in that account**. Compromise any one of them, and the role is yours.

This is not a hypothetical. It is the standard path from developer credential leak to production access.

---

## The PassRole Problem

`iam:PassRole` is consistently underestimated.

What it does: allows an identity to attach a role to an AWS service — EC2, Lambda, ECS, Glue, CodeBuild, and others.

What it means in practice: an identity with `iam:PassRole` on a privileged role, combined with `ec2:RunInstances`, can launch an EC2 instance with `AdministratorAccess` attached. The instance then calls the Instance Metadata Service. The attacker reads the admin credentials from the metadata endpoint.

The IAM policy that enabled this may show only two permissions. The blast radius is full account access.

> `iam:PassRole` is a privilege escalation primitive. It should be treated with the same severity as `iam:CreatePolicyVersion` or `sts:AssumeRole` on privileged roles.

---

## Cross-Account Trust — The Organizational Risk

In multi-account AWS architectures, role trust policies often reference principals in other accounts. This is by design — it enables centralized deployment pipelines, shared security tooling, and federated access patterns.

It also creates a lateral movement surface that spans account boundaries.

When Account A's role trusts a principal in Account B, compromise of Account B's principal becomes compromise of Account A's role. The CloudTrail logs for this activity are split across two accounts. Detection requires centralized log aggregation — which most organizations implement late, if at all.

In AWS Organizations, this expands further: a single compromised identity in a low-security sandbox account may have a trust path to the management account. The graph does not respect the organizational chart.

---

## Persistence — Why It Survives Incident Response

Standard incident response playbooks focus on workload isolation: terminate instances, revoke sessions, rotate credentials.

IAM-based persistence survives all of this.

A backdoor IAM user lives in the control plane, not the data plane. It is not destroyed when an EC2 instance is terminated. It does not disappear when a Lambda function is redeployed. A rogue trust policy modification on an existing role is visible only to engineers who know to look for it — and it survives workload replacement entirely.

**The persistence is in the graph, not the workload.**

This is why detection of IAM modification events — specifically `UpdateAssumeRolePolicy`, `CreateUser`, and `CreateAccessKey` — is more critical than detecting anomalous compute activity.

---

## What Secure IAM Architecture Actually Requires

Security is not achieved by tightening individual policies. It is achieved by designing a trust graph with minimal edges between privilege levels.

The principles that follow from this model:

**1. Minimize trust surface area.**
Every trust relationship is a potential attack path. Every unnecessary trust relationship is an unnecessary risk. Trust policies should reference specific ARNs, not root principals or wildcards.

**2. Enforce conditions on role assumption.**
Trust policies support `Condition` blocks. MFA requirements, IP restrictions, and external ID requirements all constrain the usable attack surface even when trust is correctly scoped.

**3. Treat PassRole as a tier-one permission.**
Audit and restrict `iam:PassRole` with the same rigor applied to `sts:AssumeRole`. Scope it to specific target role ARNs and specific service principals.

**4. Use SCPs as hard guarantees, not soft suggestions.**
IAM policies express intent. SCPs enforce invariants. The actions you never want any identity to perform — disabling CloudTrail, creating long-lived credentials, assuming the management account — belong in SCPs.

**5. Build detection around control plane events.**
Attackers operating through IAM leave data plane footprints only incidentally. The reliable signal is in the control plane: role assumption chains, trust policy modifications, credential creation, and permission boundary changes.

---

## The Mental Model in One Sentence

> Secure AWS environments are not environments where permissions are tight.
> They are environments where the **trust graph has no unintended paths** from any identity to any high-value resource.

Model the graph. Find the paths. Close them before an attacker does.

---

*Part of the [AWS IAM Attack Paths](./README.md) research project.*
