# Graph Probe

`npm run graph:probe` asks **your own** Microsoft 365 tenant which Microsoft Graph calls work there, with which permissions and licences. You run it locally, before any Phishy feature depends on those calls.

It exists because Microsoft's reference documentation leaves several behaviours unstated ([the list is below](#what-microsofts-documentation-leaves-unstated)). Phishy's Graph features (fetching a reporter's original message, the sender-relationship check, finding who else received an email, the fan-out scan) are built on the answers. The probe gets the answers from your tenant instead of guessing.

## It is read-only

- Every Graph request is a `GET`. The probe never creates, moves, changes or deletes anything, and never provisions a service principal. (The only `POST` is the token request to `login.microsoftonline.com`, which every OAuth client makes.)
- It runs on your machine with a certificate you hold. Nothing is sent anywhere except Microsoft's token endpoint and `graph.microsoft.com`.
- It is not part of the email pipeline, and running it does not turn any Graph feature on in the deployed Lambda.
- It prints **no** message bodies, attachment content or header values. See [Privacy of the output](#privacy-of-the-output).

A test fails the build if the probe or the operations library it uses ever issues anything but `GET`.

## Setup

### 1. Certificate

Create a key pair and a self-signed certificate. The key must be RSA and not passphrase-protected:

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -days 90 -nodes \
  -keyout phishy-graph-probe.key -out phishy-graph-probe.crt \
  -subj "/CN=phishy-graph-probe"
cat phishy-graph-probe.key phishy-graph-probe.crt > phishy-graph-probe.pem
chmod 600 phishy-graph-probe.pem phishy-graph-probe.key
```

`phishy-graph-probe.pem` (private key followed by certificate) is what you pass to `--certificate`. Keep it out of the repository and delete it when you are done.

### 2. App registration

Use a registration dedicated to probing, or the read-only registration described in [CONFIGURATION.md](CONFIGURATION.md#microsoft-graph-optional). Never reuse an app that can write to the tenant.

1. Microsoft Entra admin center → *App registrations* → *New registration*. *Accounts in this organizational directory only*; no redirect URI. Note the **Application (client) ID** and **Directory (tenant) ID**.
2. *Certificates & secrets* → *Certificates* → *Upload certificate* → select `phishy-graph-probe.crt` (the public certificate only). Do not create a client secret.
3. *API permissions* → *Add a permission* → *Microsoft Graph* → *Application permissions* → add the permissions for the checks you want answered (table below) → *Grant admin consent*. Grant the mailbox permissions through Exchange instead — [step 3 below](#3-scope-mailbox-access-to-a-test-mailbox).

You do not need every permission. A check whose permission is missing reports `FAIL` with the permission's name and the run continues — that is itself an answer.

### Permissions per check

All are **application** permissions. Where two are listed, either one is enough.

| Check | Permission | Notes |
|---|---|---|
| Token acquired | none | Lists the application roles in the token |
| Licence capabilities | `LicenseAssignment.Read.All` (least privileged) or `Organization.Read.All` | `GET /subscribedSkus` |
| List users | `User.Read.All` | `GET /users` |
| Read mailbox metadata | `Mail.ReadBasic.All` or `Mail.Read` | Newest inbox message, metadata only |
| Find by internetMessageId | `Mail.ReadBasic.All` or `Mail.Read` | |
| /messages covers Junk Email | `Mail.ReadBasic.All` or `Mail.Read` | |
| /messages covers Recoverable Items | `Mail.ReadBasic.All` or `Mail.Read` | |
| Sender + time-window filter | `Mail.ReadBasic.All` or `Mail.Read` | |
| $search | `Mail.ReadBasic.All` or `Mail.Read` | |
| $search combined with $filter | `Mail.ReadBasic.All` or `Mail.Read` | |
| Internet headers via $select | `Mail.ReadBasic.All` or `Mail.Read` | |
| MIME download | `Mail.Read` | Run it with only `Mail.ReadBasic.All` to learn whether that is enough |
| Last-verb extended property | `Mail.Read` | `Mail.ReadBasic.All` excludes extended properties |
| Immutable ID header | `Mail.ReadBasic.All` or `Mail.Read` | |
| Message trace reachable | `ExchangeMessageTrace.Read.All` | Also needs Microsoft's message-trace service principal in the tenant (below) |
| Message trace by messageId (with `<>`) | `ExchangeMessageTrace.Read.All` | |
| Message trace by messageId (without `<>`) | `ExchangeMessageTrace.Read.All` | |
| Message trace by sender + subject | `ExchangeMessageTrace.Read.All` | |

A useful first run grants `Mail.ReadBasic.All` only; a second run with `Mail.Read` then shows exactly which checks need the larger permission.

**Message trace service principal.** Message trace through Graph depends on a Microsoft first-party application (app ID `8bd644d1-64a1-4d4b-ae52-2e0cbf64e373`) having a service principal in your tenant. Until it does, calls fail with 401/403 and the probe reports `service principal not provisioned`. Creating it is a one-time change an administrator makes by following Microsoft's message trace documentation (with Microsoft Graph PowerShell this is typically `New-MgServicePrincipal -AppId 8bd644d1-64a1-4d4b-ae52-2e0cbf64e373`). The probe will not do it for you. Message trace through Graph is available in the global cloud only and is throttled to 100 requests per 5 minutes per tenant; the probe normally makes four. Message trace applies `eq` on `senderAddress` and `recipientAddress`, but accepts `endswith(...)` and `contains(...)` on an address with HTTP 200 and does not apply them (the rows come back unfiltered), so a filter being accepted is not evidence that it works; Phishy filters addresses with `eq` only and checks the returned rows.

### 3. Scope mailbox access to a test mailbox

A mailbox permission consented in Entra (`Mail.Read`, `Mail.ReadBasic.All`) applies to **every mailbox in the tenant**. For the probe, grant it to one test mailbox instead, with Exchange Online [RBAC for Applications](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac):

```powershell
Connect-ExchangeOnline

# IDs come from Entra > Enterprise applications (not App registrations)
New-ServicePrincipal -AppId <application-id> -ObjectId <enterprise-app-object-id> -DisplayName "Phishy Graph probe"

# One mailbox
New-ManagementScope -Name "Phishy probe mailbox" `
  -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'probe-test@example.com'"

# Start with the basic role; add "Application Mail.Read" for a second run
New-ManagementRoleAssignment -App <application-id> -Role "Application Mail.ReadBasic" `
  -CustomResourceScope "Phishy probe mailbox"

Test-ServicePrincipalAuthorization -Identity <application-id> -Resource probe-test@example.com
```

Things to know:

- **Do not also consent the same permission in Entra.** Effective access is the union of the Entra grant and the Exchange assignment; an unscoped Entra grant makes the scope meaningless.
- Permissions granted this way do **not** appear in the token. The first check will list no `Mail.*` role and the mail checks still pass — that is expected.
- Changes take 30 minutes to 2 hours to take effect. A `FAIL` straight after an assignment may just be the cache.
- Directory and message-trace permissions (`User.Read.All`, `LicenseAssignment.Read.All`, `ExchangeMessageTrace.Read.All`) are not mailbox permissions and cannot be scoped this way; they are consented in Entra.

Use a mailbox whose content you are comfortable having the probe read metadata from. To get answers from every check, put at least one message in its Junk Email folder, delete one and then remove it from Deleted Items (so it sits in Recoverable Items), and reply to or forward one.

## Running it

```bash
npm run graph:probe -- \
  --tenant-id <directory-tenant-id> \
  --client-id <application-client-id> \
  --certificate ./phishy-graph-probe.pem \
  --mailbox probe-test@example.com
```

| Option | Meaning |
|---|---|
| `--tenant-id <id>` | Directory (tenant) ID or a verified domain. Falls back to `PHISHY_GRAPH_TENANT_ID` |
| `--client-id <id>` | Application (client) ID. Falls back to `PHISHY_GRAPH_READ_CLIENT_ID` |
| `--certificate <path>` | Path to a PEM file holding the private key and certificate. Without it, `PHISHY_GRAPH_READ_CERTIFICATE` is used — that variable holds the PEM itself or a Secrets Manager ARN, as in the deployed configuration |
| `--mailbox <upn>` | The test mailbox. Without it the mail checks are `SKIPPED` and the directory and message-trace checks still run |
| `--message-id <id>` | Internet message ID of the message to test with, including its angle brackets. Default: the newest message in the mailbox's inbox |
| `--show-identifiers` | Print addresses, subjects and message IDs in clear instead of hashes |
| `--json` | Machine-readable output, with the same redaction |
| `-h`, `--help` | Usage |

For clean JSON on stdout, run the built file directly (`npm run` prints its own banner lines):

```bash
npm run build
node dist/cli/graph-probe.js --tenant-id ... --client-id ... --certificate ... --json > probe.json
```

**Exit code:** `0` when the run completes, even if checks failed; `1` for a credential error (unreadable or invalid certificate, token refused); `2` for a usage error.

The run makes roughly 25 requests and takes a few seconds — far below the Outlook limits (10,000 requests per 10 minutes and 4 concurrent requests per app per mailbox; the probe is sequential).

## Reading the output

```
RESULT   CHECK
         question / detail
------------------------------------------------------------------------
PASS     Token acquired
         Q: Can the app authenticate with its certificate, and which application roles does it hold?
         -> token acquired; application roles: ExchangeMessageTrace.Read.All, User.Read.All
PASS     Find by internetMessageId
         Q: Does $filter=internetMessageId eq ... work on /messages (not documented as supported)?
         -> filter accepted; 1 message(s) matched message-id#3fa91c20
FAIL     MIME download
         Q: Does /messages/{id}/$value work (unstated whether Mail.ReadBasic.All is enough)?
         -> permission missing or not consented: needs Mail.Read (HTTP 403 ErrorAccessDenied)
         needs: Mail.Read
SKIPPED  /messages covers Junk Email
         Q: Does /users/{id}/messages include items in Junk Email (not stated)?
         -> could not determine: junkemail is empty (put a message there and re-run)
```

- **PASS** — the call works in your tenant as the check describes. The detail carries the facts (counts, sizes, header names).
- **FAIL** — the call did not work, or worked and gave the wrong answer. Read the detail:
  - `permission missing or not consented: needs X (HTTP 403 Code)` — grant X (or wait for an Exchange RBAC change to take effect). `not in the token roles` is added when the token confirms an Entra permission is absent.
  - `service principal not provisioned` — message trace's prerequisite is missing; see above.
  - `filter accepted but matched nothing` / `not covered` / `not supported` — Graph answered, and the answer is "this does not work here". These are the findings the probe exists for. For the two message-trace `messageId` checks, expect one form to pass and the other to fail.
  - `Graph rejected the request (HTTP 400 Code)` — the request shape is not accepted; please report it.
  - `throttled by Graph` / `request did not complete (timeout)` — re-run later.
- **SKIPPED** — the check could not give an answer: no `--mailbox`, an empty folder, a property that is not set on the test message, a message too old for message trace (90 days), or a dependency that failed. `could not determine` means exactly that; it is never reported as a pass.

A failed or skipped check never stops the run.

## Privacy of the output

The default output is meant to be safe to paste into a public issue:

- **Never printed:** message bodies, attachment content, header values, Graph's free-text error messages (they can echo request input), the mailbox name, user names, IP addresses, Graph message IDs, the access token, the client assertion, the private key.
- **Printed:** counts, sizes, booleans, dates (day only), header *names*, message-trace status values, licence capability flags, application role names, HTTP statuses and Graph error codes.
- **Hashed by default:** addresses, subjects and Internet message IDs appear as `address#1a2b3c4d`, `subject#…`, `message-id#…`. The hash is salted with a random value per run: the same value gets the same label within one report, but labels cannot be compared across runs or used to confirm a guess. `--show-identifiers` prints them in clear; do not post that output.

Header names are chosen by whoever sent the test message and by your mail-security products (`X-…` headers often name a vendor). Only names made of letters, digits and hyphens are shown, at most 40; skim them before posting.

## What Microsoft's documentation leaves unstated

Each of these is answered by a check:

| Behaviour | What the docs say | Check |
|---|---|---|
| `$filter` on `internetMessageId` | Not documented as a supported filter (it works in community reports) | Find by internetMessageId |
| Whether `/users/{id}/messages` includes Junk Email | Deleted Items and Clutter are stated; Junk Email is not | /messages covers Junk Email |
| Whether it includes Recoverable Items | Not stated | /messages covers Recoverable Items |
| Whether `$search` on messages needs `ConsistencyLevel` | Not stated | $search |
| Whether `$search` can be combined with `$filter` on messages | Not in the reference (community reports say no) | $search combined with $filter |
| Whether `/$value` (MIME) works with only `Mail.ReadBasic.All` | Both permissions are listed for *Get message*; `ReadBasic` excludes body and attachments | MIME download |
| The extended-property id for "replied / forwarded" | Microsoft documents the `"{type} {proptag}"` format; `Integer 0x1081` (PidTagLastVerbExecuted) is constructed from it, not quoted | Last-verb extended property |
| Whether message trace can be filtered by `messageId`, and whether the value keeps its angle brackets | `messageId` is listed as filterable; no example, brackets not stated | Message trace by messageId (both forms) |
| Whether shared mailboxes appear in `/users` and can be told apart | Not stated; no documented filter means "has an Exchange Online mailbox" | List users (counts by `userType`, with `mail`, with an enabled Exchange plan) |

Two design choices in Phishy's request builder are also unverified until a tenant runs the probe, and are exercised by the `$search` check: search values are reduced to plain lower-case words (no quoting or escaping — nothing a value contains can be KQL syntax), and a multi-word value is sent as `property:(word word)`. The check searches by sender (`from:address`) and then by the test message's subject in the grouped form, and reports both.

The last-verb check prints the raw property value. The MAPI definition of PidTagLastVerbExecuted gives 102 (reply), 103 (reply all) and 104 (forward); some references give 261 and 262 for replied and forwarded. Phishy accepts both sets — the value your tenant reports settles it.

## If you share results

Results from different tenants are what turn "not stated" into "known". If you open an issue with your output, use the default (hashed) form, and add which permissions were granted and whether they were granted in Entra or through Exchange RBAC.

## The operations library

The probe calls the same typed, read-only functions pipeline features use (`src/services/graph/mail.operations.ts`, `trace.operations.ts`, `directory.operations.ts`). They follow the rules in [ARCHITECTURE.md](ARCHITECTURE.md#microsoft-graph-optional-foundation): fixed endpoints, every value from data escaped by the request builder, bounded results that report truncation, and metadata only for lookups across mailboxes. The pipeline features that call them — the [original-message lookup](ARCHITECTURE.md#original-message-lookup), the [sender-relationship check](ARCHITECTURE.md#sender-relationship-check), [blast radius](ARCHITECTURE.md#blast-radius-optional) and the [scheduled fan-out scan](ARCHITECTURE.md#scheduled-fan-out-scan) — are each off by default.
