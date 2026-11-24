# Phishy with Microsoft 365: setup from start to finish

This guide wires Phishy into a Microsoft 365 organization in the order that works, with a test at the end of each stage. It links to the reference pages for the detail and does not repeat them:

- [AWS.md](../AWS.md): the deployment parameters
- [CONFIGURATION.md](CONFIGURATION.md): every setting
- [GRAPH_PROBE.md](GRAPH_PROBE.md): checking what Microsoft Graph allows in your tenant

Every stage after the first is optional and off by default. Stop at any stage; each one works without the ones after it.

| Stage | What you get | Needs in Microsoft 365 |
|---|---|---|
| [1. Forwarding](#stage-1-employees-forward-to-phishy) | Employees forward a suspicious email and get a report back | Nothing (optionally a mail contact) |
| [2. Security team](#stage-2-the-security-team-replies-to-phishy) | The security team confirms or overturns verdicts by replying | Nothing |
| [3. Graph reads](#stage-3-microsoft-graph-reads) | Real headers of the reported email, who else received it, sender history | An Entra app registration (read) |
| [4. Campaign response](#stage-4-campaign-response) | One incident email per campaign, warnings to the people who received it, approvals | Nothing new |
| [5. Report button](#stage-5-the-outlook-report-button) | Reports made with Outlook's Report button reach Phishy | A shared mailbox, a Defender setting, a mail-flow rule |
| [6. Removal](#stage-6-approved-removal-from-mailboxes) | An approved removal moves the phishing email to Deleted Items | A second Entra app registration (write) |

Examples below use `example.com` for your organization, `phishy@reports.example.com` for the address Phishy receives mail on, and `security@example.com` for the security team.

## What you need

- An AWS account and a deployed Phishy stack, or the readiness to deploy one ([QUICK_START.md](QUICK_START.md)).
- A domain or subdomain whose MX record you can point at Amazon SES. A subdomain such as `reports.example.com` leaves your organization's own mail routing untouched.
- For stages 3 and 6: an Entra role that can register applications and grant admin consent.
- For stage 5: access to the Microsoft Defender portal and the Exchange admin center.

## Stage 1: Employees forward to Phishy

1. **Deploy the core.** Follow [QUICK_START.md](QUICK_START.md): deploy the stack, verify the receiving domain in SES with DKIM, point its MX record at SES, and activate the receipt rule set. Set `SafeDomains` to your organization's mail domain (`example.com`), not the receiving subdomain: it is the list of domains Phishy accepts reports from.
2. **Optional: give employees a familiar address.** In the Exchange admin center, create a **mail contact** (*Recipients* → *Contacts* → *Add a mail contact*) named, for example, *Phishy*, with the external address `phishy@reports.example.com`. Employees can then pick it from the address book.
3. **Make sure your outbound mail is authenticated.** Security-team commands, approvals and the original-message lookup are accepted only for mail that SES reports as SPF or DKIM `PASS`. Mail sent from Exchange Online passes when your domain's SPF record includes Microsoft 365; enable [DKIM signing for your domain](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure) as well. Stages 2, 3, 4 and 6 depend on this.

**Test.** Forward any email to Phishy's address from a mailbox on `example.com`. A report arrives within a minute or two. If nothing arrives, see the troubleshooting section of [QUICK_START.md](QUICK_START.md#troubleshooting).

## Stage 2: The security team replies to Phishy

With the command channel on, a reply of "confirmed phishing" or "false positive" to a report records the security team's ruling. The same channel carries approvals in stages 4 and 6.

1. Set up the intelligence database and apply `migrations/002_analysis_feedback.sql` ([AWS.md](../AWS.md#optional-the-intelligence-database)).
2. Deploy with `EmailCommandsEnabled=true`, `SecurityTeamDistribution=security@example.com`, and `SecurityTeamMembers` listing each person who will reply from their own mailbox.

`SecurityTeamMembers` matters in Microsoft 365. When `security@example.com` is a distribution list or shared mailbox, a team member's reply comes from that person's own address, not the list's, and Phishy does not act on it unless the person is listed. See [Who can issue commands](CONFIGURATION.md#who-can-issue-commands).

**Test.** Have a listed team member reply "false positive" to a report. Phishy answers that person with what it recorded. Then reply from a mailbox that is not listed: nothing is recorded.

## Stage 3: Microsoft Graph reads

Phishy reads from your tenant through a second Lambda function, the Graph broker, so the function that parses hostile email holds no Microsoft credential.

1. **Create a certificate** and store it in Secrets Manager: [The certificate](CONFIGURATION.md#the-certificate).
2. **Register the read app** in Entra and upload the certificate: [Entra app registration](CONFIGURATION.md#entra-app-registration). Never create a client secret.
3. **Grant only the permissions for the features you want**, with admin consent:

   | Feature | Deployment parameter | Application permission |
   |---|---|---|
   | [Original-message lookup](CONFIGURATION.md#original-message-lookup): the reported email's real headers, read from the reporter's own mailbox | `GraphOriginalFetchEnabled` | `Mail.Read` |
   | [Blast radius](CONFIGURATION.md#blast-radius-optional): who else received it, and whether they opened it | `GraphBlastRadiusEnabled` | `User.Read.All`, `Mail.ReadBasic.All`, `Mail.Read`, `ExchangeMessageTrace.Read.All` (each optional; that section says what is lost without it) |
   | [Sender-relationship check](CONFIGURATION.md#sender-relationship-check-optional): has this sender written to you before | `GraphSenderHistoryEnabled` | `ExchangeMessageTrace.Read.All` |
   | [Fan-out scan](CONFIGURATION.md#scheduled-fan-out-scan-optional): one outside sender suddenly reaching many mailboxes, before anyone reports it | `GraphFanoutScanEnabled` | `ExchangeMessageTrace.Read.All` (also needs the intelligence database and migration 005) |

   A mailbox permission granted in Entra covers every mailbox in the tenant. To limit it, grant it through Exchange Online instead; the Entra app registration section above explains how and what the pitfall is.
4. **Check what your tenant allows** before relying on it: run the read-only probe in [GRAPH_PROBE.md](GRAPH_PROBE.md). Message trace in particular depends on your licences and on a Microsoft service principal existing in the tenant.
5. **Deploy** with `GraphEnabled=true`, `GraphTenantId`, `GraphReadClientId`, `GraphCertificateSecretArn` and the feature parameters you chose ([AWS.md](../AWS.md#optional-microsoft-graph-the-graph-broker-function)).

**Test.** Send yourself an email from an outside account and forward it to Phishy. With the original-message lookup on, the report reflects the email's real authentication results, not only what the forward pasted in. With blast radius on, a report judged malicious adds a section to the security team's copy listing who else received it; it always says how many mailboxes were checked.

## Stage 4: Campaign response

When several people report the same email, or one malicious report turns out to have reached many people, Phishy opens an incident: one email to the security team with the proposed actions, each approved by replying with an exact line.

1. Apply `migrations/006_campaign_response.sql` (and 003 if you want a "false positive" reply to close an incident).
2. Deploy with `CampaignAlertsEnabled=true`, `CampaignResponseEnabled=true` and `CampaignResponseAudience=recipients`, so warnings go to the people blast radius found and not to a company-wide list ([AWS.md](../AWS.md#optional-campaign-response-the-command-channel-and-attachment-analysis)).
3. Replace the default "if you already clicked" text with your own instructions, and set the time zone ([Campaign Response](CONFIGURATION.md#campaign-response-optional)).

Leave `CampaignResponseEmployeeWarning` at `approve` to begin with: nobody is warned until a security-team member replies with the `APPROVE WARNING` line from the incident email.

**Test.** Send a harmless test email from an outside account to a handful of colleagues who have agreed to help, and have two of them forward it to Phishy. Whether an incident opens depends on the verdict, so a test that reads as an ordinary email will not open one; the practical proof is the first real campaign. Until then, confirm in the function's log that campaign response started without a missing-migration warning.

## Stage 5: The Outlook Report button

Outlook's built-in **Report** button sends each report to a *reporting mailbox* you choose. That mailbox must be in Exchange Online: **Defender does not deliver user reports to an outside address, and a mail contact pointing at Phishy does not work as the reporting mailbox either.** So the route is: reporting mailbox first, then a mail-flow rule that copies each report to Phishy.

1. **Create the reporting mailbox.** Exchange admin center → *Recipients* → *Mailboxes* → *Add a shared mailbox*, for example `phishing-reports@example.com`. A shared mailbox needs no licence. If you already have a reporting mailbox, keep it.
2. **Point the Report button at it.** [Microsoft Defender portal](https://security.microsoft.com) → *Settings* → *Email & collaboration* → *User reported settings*:
   - turn on *Monitor reported messages in Outlook* and choose the built-in Report button;
   - under *Reported message destinations*, choose a destination that includes *My reporting mailbox* and enter the mailbox from step 1.

   Whether reports also go to Microsoft is your choice and does not affect Phishy. Microsoft's own requirements for the reporting mailbox, including identifying it as a SecOps mailbox so reports are not filtered on the way in, are in [User reported settings](https://learn.microsoft.com/en-us/defender-office-365/submissions-user-reported-messages-custom-mailbox).
3. **Copy each report to Phishy.** Exchange admin center → *Mail flow* → *Rules* → *Add a rule* → *Create a new rule*:
   - **Name:** for example *Phishy: copy button reports*
   - **Apply this rule if:** *The recipient* → *is this person* → the reporting mailbox
   - **Do the following:** *Add recipients* → *to the Bcc box* → `phishy@reports.example.com`
   - Save it, then **enable** it: a new rule is created disabled.

   A Bcc leaves the report in the reporting mailbox, so anything else that reads that mailbox keeps working.
4. **Tell Phishy to handle button reports silently.** Deploy with `ReportButtonEnabled=true`. Without it, a button report is treated like a forward and the reporter gets a reply they were not expecting.

What then happens ([Outlook Report Button Intake](CONFIGURATION.md#outlook-report-button-intake)): an email reported as **phishing** is analyzed and counted toward campaigns like a forward, the reporter is not emailed, and the security team hears about it only when the verdict is malicious or suspicious. An email reported as **junk** or **not junk** is counted and skipped.

**Test.** In Outlook, report a harmless email as phishing, then another as junk. For each, the function's log shows one report received, and the `UserReports` metric (namespace `Phishy`, dimension `ReportedAs`) counts it. You, the reporter, receive nothing from Phishy. A new mail-flow rule can take a while to start applying; if the first report does not arrive, wait and report another.

**If reports do not arrive:**

- Check the report reached the reporting mailbox. If it did not, the problem is the Defender setting, not Phishy.
- Run a message trace (Exchange admin center → *Mail flow* → *Message trace*) for the reporting mailbox as recipient, and look for the copy to Phishy's address leaving your organization.
- Check the rule is enabled and its condition names the reporting mailbox exactly.
- Delivery depends on settings Phishy cannot see, so set a CloudWatch alarm on `UserReports` going quiet.

## Stage 6: Approved removal from mailboxes

By default, approving a removal runs a dry run: Phishy replies with what it would remove and changes nothing. With the write tier on, the approved copies are moved to each person's Deleted Items, nothing is permanently deleted, and each person is told.

This is the only way Phishy changes a mailbox. It uses a third function with its own Entra app registration and certificate that no other part of Phishy holds. Read [Mailbox write tier](CONFIGURATION.md#mailbox-write-tier-optional) in full first; in outline:

1. **Register a second app** in Entra, for example *Phishy Graph (write)*, with a new certificate in a new secret. Grant it `Mail.ReadWrite` (application) with admin consent and nothing else. Do not reuse the read app.
2. **Deploy with the switch off:** `GraphWriteClientId`, `GraphWriteCertificateSecretArn`, `GraphWriteEnabled=false`, `CampaignRemovalMode=live` ([AWS.md](../AWS.md#optional-the-mailbox-write-tier-live-campaign-removal)).
3. **Rehearse** by following [Before turning live removal on](CONFIGURATION.md#mailbox-write-tier-optional), step by step: an approval refused while the switch is off, then one test mailbox on the allowlist (`GraphWriteAllowedMailboxIds`), a real move, the removal notice, and a second approval that does nothing.
4. **Brief the approvers**, then remove the allowlist.

Two things to know before you rely on it:

- **A live removal is proposed only when Phishy can tie it to one exact message.** That needs the original-message lookup (stage 3) and a report made by forwarding from a mail client that names the forwarded message in its headers, as Outlook does. Other incidents still get a dry-run proposal. Test the clients your staff use, including the Report button, before expecting a live proposal from them.
- **Only copies of that exact message move.** A wave sent as several separate messages is covered one message at a time.

**Test.** The rehearsal in step 3 is the test. Do it on a non-production deployment if you have one.

## After setup

- **Alarms worth having:** `UserReports` going quiet (stage 5), and the Graph broker's error outcomes ([Graph broker](CONFIGURATION.md#graph-broker-optional)).
- **Certificates expire.** Phishy warns in its log from 30 days before expiry and refuses an expired one. Rotation is described under [The certificate](CONFIGURATION.md#the-certificate).
- **Who can approve** is the `SecurityTeamMembers` list. Keep it current as the team changes.
- **How it all works**, and why it is built this way: [ARCHITECTURE.md](ARCHITECTURE.md).
