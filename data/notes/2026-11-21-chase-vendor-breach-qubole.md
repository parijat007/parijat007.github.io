---
title: "Chase, Visa and Mastercard vendor breaches: the Qubole trusted-role path and how to hunt it"
date: 2026-11-21
summary: >
  Chase, Visa and Mastercard confirmed that service providers holding their marketing data were breached.
  The n0n extortion group claims the theft and has been tied to a confirmed campaign that abused Qubole's
  trusted AWS roles in customer accounts. Here is what is confirmed, what is only claimed, and how to check
  your own cloud for the same access path.
tlp: CLEAR
tags: [Supply chain, AWS, IAM, Third-party risk, Financial services]
status:
  - {claim: "Chase, Visa and Mastercard vendor incidents", state: confirmed, note: "Each company confirmed a third-party incident between 18 and 19 November 2026"}
  - {claim: "n0n is behind the Chase, Visa and Mastercard data", state: reported, note: "Claimed by n0n; not confirmed by the companies"}
  - {claim: "Chase's vendor was reached through the Qubole campaign", state: reported, note: "Linked in press reporting; Chase has not named its vendors"}
  - {claim: "Qubole trusted-role abuse, 14–26 October 2026", state: confirmed, note: "Documented by Wiz with Sentra and Mandiant"}
  - {claim: "16 November banking outage was an attack", state: refuted, note: "Chase attributes it to an internal technical fault"}
sources:
  - {title: "Wiz: Qubole cross-account access abused in the wild", url: "https://www.wiz.io/blog/qubole-cross-account-access-abused-in-the-wild"}
  - {title: "BleepingComputer: Vendor data breach exposes Chase, Visa, Mastercard customer info", url: "https://www.bleepingcomputer.com/news/security/vendor-data-breach-exposes-chase-visa-mastercard-customer-info/"}
  - {title: "The Hacker News: Hackers exploit Qubole's trusted AWS access", url: "https://thehackernews.com/2026/11/hackers-exploit-quboles-trusted-aws.html"}
  - {title: "The Next Web: Chase, Visa and Mastercard confirm vendor hacks", url: "https://thenextweb.com/news/jpmorgan-chase-visa-mastercard-vendor-breach-n0n-leak"}
  - {title: "Washington Post: Cyberattack may have exposed Chase and Mastercard customer data", url: "https://www.washingtonpost.com/nation/2026/11/19/cyberattack-may-have-exposed-chase-bank-mastercard-customer-data/"}
  - {title: "Ostorlab: n0n's claims against Visa, Mastercard and JPMorgan, what the evidence shows", url: "https://blog.ostorlab.co/n0n-claims-visa-mastercard-jpmorgan.html"}
  - {title: "GovInfoSecurity: Optimizely flaw exposes 178 organizations to web skimmers", url: "https://www.govinfosecurity.com/optimizely-flaw-exposes-178-organizations-to-web-skimmers-a-33422"}
---

## Three incidents, one week

Three separate events landed on Chase customers in the same week. They are easy to conflate, so keep them apart:

| Date (2026) | Event | What it is |
|---|---|---|
| 14–26 Oct | Qubole trusted-role campaign | Confirmed data theft from dozens of Qubole customers' AWS accounts |
| 15–16 Nov | Optimizely web supply-chain attack | Malicious JavaScript served on about 178 major websites; crypto-address swapping and card skimming |
| 16 Nov | Outage at Chase and other US banks | Attributed by Chase to an internal technical fault, not an attack |
| 18–19 Nov | Chase, Visa, Mastercard disclosures | Each confirmed a breach at a service provider holding marketing data |

**What was exposed at Chase:** names and email addresses held by vendors for marketing, according to the bank. The leaked sample reviewed by researchers is about 16,000 records that appear tied to the invitation-only Reserve card, with email addresses, phone numbers and account identifiers. No payment card data has been reported for any of the three companies.

**Why it still matters:** a list of very high-net-worth customers with verified contact details and a real banking relationship is ideal raw material for targeted phishing and fraud calls.

## The access path: dormant vendor roles that still trusted the vendor

The most useful lesson for defenders is the technique behind the campaign n0n has claimed, documented by Wiz with Sentra and Mandiant:

1. Many organizations connected Qubole, a cloud data-lake service, by creating an IAM role in their AWS account that trusts Qubole's AWS account (805246085872) and requires an External ID.
2. Between 14 and 26 October, an attacker used IAM credentials from Qubole's own account to call `sts:AssumeRole` into those customer roles, with valid External IDs. Every attributed attempt succeeded.
3. Most of the roles were dormant. Customers had stopped using Qubole but never removed the trust.
4. Inside, the attacker enumerated storage, databases and IAM, then harvested secrets: Lambda environment variables, Secrets Manager values, SSM parameters, IAM access keys, and Entra ID and Okta client credentials.
5. Stolen keys were validated with TruffleHog, and some S3 buckets were downloaded in full.

How the attacker obtained the External IDs is not public. A source-IP condition on the trust policy would have blocked every observed attempt.

| Stage | Behavior | MITRE ATT&CK |
|---|---|---|
| Initial access | AssumeRole into vendor-trusted roles | T1199 Trusted Relationship; T1078.004 Cloud Accounts |
| Discovery | Storage, data catalog, cluster, EC2, RDS, IAM and KMS enumeration | T1580 Cloud Infrastructure Discovery |
| Credential access | Lambda env vars, Secrets Manager, SSM Parameter Store | T1555.006 Cloud Secrets Management Stores |
| Lateral movement | Stolen keys and client secrets tested against AWS, Entra ID, Okta | T1078 Valid Accounts |
| Collection | Bulk S3 object reads | T1530 Data from Cloud Storage |
| Impact | Leak-site extortion, no encryption | T1657 Financial Theft |

## Hunt for it

Search from 1 October 2026 in every AWS account that has a vendor integration role.

**CloudTrail (Athena):**

```sql
SELECT eventtime, recipientaccountid, useridentity.principalid, sourceipaddress, useragent,
       json_extract_scalar(requestparameters, '$.roleArn')         AS role_arn,
       json_extract_scalar(requestparameters, '$.roleSessionName') AS session_name
FROM cloudtrail_logs
WHERE eventtime >= '2026-10-01T00:00:00Z'
  AND eventname = 'AssumeRole'
  AND ( useridentity.accountid = '805246085872'
        OR useridentity.principalid IN ('AIDA3W7DIFLYOLTK63SFS', 'AIDAJYRRH5Y3A7AAJM2HW')
        OR json_extract_scalar(requestparameters, '$.roleSessionName') LIKE 'quiam-%'
        OR sourceipaddress IN ('45.83.220.211', '57.129.54.120', '185.209.199.73', '89.37.63.175') )
ORDER BY eventtime;
```

Qubole's genuine traffic comes from AWS address space. Treat any assumption from account 805246085872 that originates outside AWS as hostile. Any activity at all by principal `AIDA3W7DIFLYOLTK63SFS` warrants investigation.

**Then, for every session you find:**

- Pivot on everything the session did afterwards, especially `GetSecretValue`, `GetParameter`, `GetFunctionConfiguration` and `GetObject`.
- Check your logging coverage. Management events show the role assumption and bucket listing but not object reads. Without S3 data events or server access logs you cannot prove what was taken.
- Search Entra ID service-principal sign-ins and Okta OAuth token grants since 14 October for the IPs below or a TruffleHog user agent.

**Indicators** (from Wiz; context matters, since the Mullvad addresses are shared VPN exits):

| Type | Value | Note |
|---|---|---|
| AWS account | `805246085872` | Qubole; legitimate traffic comes from AWS ranges |
| IAM principal | `AIDA3W7DIFLYOLTK63SFS` | Seen only in attacker activity |
| IAM principal | `AIDAJYRRH5Y3A7AAJM2HW` | Also carries legitimate traffic; suspicious from non-AWS IPs |
| IPv4 | `57.129.54[.]120` | OVH; primary attacker address, 15–26 Oct |
| IPv6 | `2001:41d0:70d[:]7800::` | OVH; enumeration and credential checks |
| IPv4 | `45.83.220[.]211`, `185.209.199[.]73`, `89.37.63[.]175` | Mullvad VPN exits |
| Session name | `quiam-*` | e.g. `quiam-enum`, `quiam-scope-full` |
| File | `sso_agent.iso` | SHA-256 `65f061281c9a712e9502793dc4c5035cae490b84da05f7d4223cefa65ad396e4` |

## Close the path

1. **Inventory** every IAM role whose trust policy allows an external account. Delete roles for vendors you no longer use. Dormant trust was the root cause here.
2. **Pin the trust** to the vendor's network with `aws:SourceIp` or `aws:SourceVpce` conditions, and name the vendor's specific principal instead of `:root`.
3. **Stop treating the External ID as a secret.** It appears in plaintext in CloudTrail and in vendor and infrastructure-as-code storage. Rotate it per role with the vendor.
4. **Shrink vendor permissions.** No Secrets Manager, SSM, Lambda configuration or broad S3 read unless the integration truly needs them.
5. **If a role was assumed:** rotate everything it could read, and revoke the role's active sessions. Rotating a credential does not end sessions already issued.
6. **Detect continuously:** alert on third-party `AssumeRole` from networks the vendor has never used, and enable S3 data events on sensitive buckets.

## If you are a Chase, Visa or Mastercard customer

- Expect convincing phishing that uses your real name, email and card relationship. Banks will not ask for passwords, one-time codes or card numbers by email, text or phone.
- Reach the bank only through the number on your card or the official app.
- If you shopped or banked online on 15–16 November, review your statements: that is the Optimizely skimming window, a separate incident.

## Assessment

This is a third-party trust failure, not a breach of core banking systems. The confirmed facts are a vendor-side marketing data exposure at three payment brands and a documented campaign abusing dormant AWS cross-account roles. The link between the two rests on the attacker's own claims and press reporting. The defensive action is the same either way: inventory and constrain every external trust relationship in your cloud accounts.
