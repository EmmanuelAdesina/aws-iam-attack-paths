<div align="center">

```
█████╗ ██╗    ██╗███████╗    ██╗ █████╗ ███╗   ███╗
██╔══██╗██║    ██║██╔════╝    ██║██╔══██╗████╗ ████║
███████║██║ █╗ ██║███████╗    ██║███████║██╔████╔██║
██╔══██║██║███╗██║╚════██║    ██║██╔══██║██║╚██╔╝██║
██║  ██║╚███╔███╔╝███████║    ██║██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝    ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝
```

# AWS IAM Attack Paths
### Cloud Security Threat Modeling in Practice

**Modeling AWS identity as a directed trust graph — not a permission list.**

[![Security Research](https://img.shields.io/badge/type-security%20research-red?style=flat-square)](.)
[![AWS](https://img.shields.io/badge/platform-AWS-232F3E?style=flat-square&logo=amazonaws)](.)
[![IAM](https://img.shields.io/badge/focus-IAM%20%2F%20STS-FF9900?style=flat-square)](.)
[![Threat Modeling](https://img.shields.io/badge/method-threat%20modeling-8B5CF6?style=flat-square)](.)
[![Educational](https://img.shields.io/badge/use-educational-22C55E?style=flat-square)](.)

</div>

---

## The Core Premise

Most cloud security guides ask: **"Who has permission?"**

That is the wrong question.

The right question is: **"Who can *become* an identity that has permission?"**

This distinction separates a cloud user from a cloud security engineer. AWS IAM is not a flat list of access controls — it is a distributed authorization graph where trust relationships define reachability, and reachability defines risk.

This repository models that graph, traces how attackers traverse it, and shows what secure design looks like when identity is treated as the primary attack surface.

---

## Attack Chain — High Level

```
Leaked Credentials          ← The starting condition, not the exploit
       ↓
Identity Enumeration        ← Low-noise. Frequently undetected.
       ↓
Trust Graph Traversal       ← The actual attack surface
       ↓
Privilege Escalation        ← AssumeRole chains, PassRole injection
       ↓
Lateral Movement            ← Cross-service, cross-account
       ↓
Persistence                 ← Lives in the control plane, not the workload
       ↓
Production Compromise       ← The outcome that was preventable
```

---

## Repository Structure

```
aws-iam-attack-paths/
│
├── README.md                        ← You are here
├── SECURITY-INSIGHTS.md             ← Core thesis and mental model
│
├── article/
│   └── aws-iam-attack-paths.md      ← Full technical write-up
│
├── diagrams/
│   ├── attack-paths.md              ← Complete attack chain (Mermaid)
│   └── iam-trust-graph.md           ← Trust relationship topology
│
├── examples/
│   ├── trust-policy-examples.md     ← Vulnerable vs. hardened trust policies
│   ├── vulnerable-s3-policy.json    ← Annotated misconfiguration
│   └── secure-s3-policy.json        ← Hardened equivalent
│
├── docs/
│   └── index.html                   ← Visual portfolio page
│
└── references/
    └── aws-documentation-links.md   ← Full AWS doc mapping with attack context
```

---

## Four Attack Surfaces — Why They Matter

### `sts:AssumeRole` — Role Chain Exploitation

The primary escalation mechanism. A low-privilege identity with `sts:AssumeRole` on a permissive role quietly inherits its permissions — including access to resources the original identity was never meant to reach.

Attackers do not need admin access. They need *one hop* toward it.

### `iam:PassRole` — Privilege Injection into Compute

Allows attaching a role to a service like EC2 or Lambda. Misconfigured, this is indistinguishable from handing an attacker `AdministratorAccess`. The injected role runs inside the workload; the API call that placed it there leaves a single log line.

> Treat `iam:PassRole` as a privilege escalation primitive. It is not a deployment convenience.

### S3 Resource Policies — IAM Bypass via Resource Layer

Resource-based policies on S3, KMS, and Lambda are evaluated **independently** of IAM identity policies. A wildcard principal on a single bucket policy exposes data regardless of how tightly IAM roles are scoped.

### Cross-Account Trust — Organizational Lateral Movement

A role trust policy that permits external account principals enables pivoting across account boundaries. The source account's CloudTrail sees nothing. The blast radius extends to the full AWS Organization.

---

## Defensive Posture — Eight Questions Every Team Should Answer

If any answer is *"I don't know"*, that gap is active attack surface:

| # | Question |
|---|---|
| 1 | Which identities have `sts:AssumeRole` on privileged roles? |
| 2 | Can any low-privilege identity reach admin via role chaining? |
| 3 | Where does `iam:PassRole` exist, and to which target roles? |
| 4 | Which resource policies allow wildcard or external principals? |
| 5 | Are all cross-account trust relationships documented and reviewed? |
| 6 | Would you detect a trust policy modification at 2 AM? |
| 7 | Would you detect a second access key added to an existing role? |
| 8 | Do your SCPs enforce what your IAM policies intend? |

---

## Key Insight

> AWS IAM security is not about restricting actions.
>
> It is about controlling **identity transitions** across a distributed authorization system.
>
> Most real-world cloud breaches are not exploitation failures.
> They are **trust design failures** — where the graph allowed a path that was never modeled.

---

## Contents at a Glance

| File | What it covers |
|---|---|
| [`SECURITY-INSIGHTS.md`](./SECURITY-INSIGHTS.md) | The mental model: IAM as a trust graph |
| [`article/aws-iam-attack-paths.md`](./article/aws-iam-attack-paths.md) | Full technical breakdown, attack-by-attack |
| [`diagrams/attack-paths.md`](./diagrams/attack-paths.md) | Visual attack chain with six stages |
| [`diagrams/iam-trust-graph.md`](./diagrams/iam-trust-graph.md) | Trust topology across roles, accounts, SCPs |
| [`examples/trust-policy-examples.md`](./examples/trust-policy-examples.md) | Four policy patterns: vulnerable → hardened |
| [`examples/vulnerable-s3-policy.json`](./examples/vulnerable-s3-policy.json) | Annotated S3 misconfiguration |
| [`examples/secure-s3-policy.json`](./examples/secure-s3-policy.json) | Hardened S3 policy equivalent |
| [`references/aws-documentation-links.md`](./references/aws-documentation-links.md) | AWS official docs mapped to attack context |

---

## About This Project

This repository is part of an ongoing focus on cloud security engineering — specifically the intersection of identity architecture, threat modeling, and real-world attack path analysis in AWS environments.

The goal is not to be a checklist. It is to build the mental model that makes checklists unnecessary.

---

*For educational and security research purposes only.*
