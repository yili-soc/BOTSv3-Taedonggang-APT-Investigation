# Taedonggang Intrusion at Frothly Brewing Co.

Incident analysis of a two-host intrusion, reconstructed from endpoint, cloud-audit and network
telemetry in Splunk, with deployable detection analytics.

Dataset: Splunk BOTSv3 · Incident date: 2018-08-20 · All times UTC

---

## Summary

One threat actor moved from a stolen cloud credential to root on an internal Linux application server
in under two hours. A hijacked internal O365 account built a lure in its own OneDrive and shared it
through an anonymous link. A user downloaded the shortcut file, and Windows handed it to PowerShell
with no second user action, starting a PowerShell Empire implant. The operator bypassed UAC, created a
local backdoor account, planted a persistence mechanism whose payload never touched disk, disabled the
Windows Firewall, and mapped the server segment in 34 seconds. One discovered host, `hoth`, was
exploited through Struts2 OGNL RCE (CVE-2017-5638). A first attempt to create a UID 0 account there
failed in the unprivileged service context; the operator compiled a kernel exploit on the victim,
obtained root, and re-issued it successfully.

Both halves of the operation reported to one external address. That is the basis for attributing all
of it to a single actor, and the attribution is a conclusion from the telemetry, not an assumption
carried into it.

## Timeline

| Time | Event |
|------|-------|
| 09:51:09 | `bgist@froth.ly` signs in from Hong Kong, 52 seconds after a legitimate Denver session |
| 09:56–09:58 | Lure built in `bgist`'s OneDrive; anonymous sharing link created, permission inheritance broken |
| 10:01:41 | FYODOR-L: `browser_broker.exe` hands the downloaded `.lnk` to `powershell.exe`, no second user action |
| 10:01:46 | Empire stager beacons to `45.77.53.176:443` |
| 10:07:05 | UAC bypass via `fodhelper.exe`; elevated agent online at 10:07:08 |
| 10:08:17 | Local backdoor account `svcvnc` created, password in plaintext on the command line; added to Administrators at 10:08:35 |
| 10:09:44 | Scheduled task `Updater` registered; payload staged in the registry, not on disk |
| 10:11:00 | Task auto-fires and delivers a resident SYSTEM implant |
| 10:16:54 | `Updater` deleted; the implant it delivered continues beaconing for a further 108 minutes |
| 10:43:31–10:44:05 | `hdoor.exe` sweeps `192.168.9.0/24` from the second interface: six live hosts in 34 seconds |
| 10:46:29 | Windows Firewall disabled on all three profiles |
| 11:05:40 | First command reaches `hoth` through Struts2 OGNL RCE (CVE-2017-5638) |
| 11:07:03 | First UID 0 account attempt fails under the Tomcat 8 service account (uid 111) |
| 11:13:56 | netcat reverse shell: `hoth` → `45.77.53.176:8088` |
| 11:15:01–11:16:58 | `colonel.c` compiled on the victim; eBPF kernel exploit (CVE-2017-16995) yields root |
| 11:24:44 | `tomcat7` (UID 0) backdoor account created successfully under root |
| 11:32:12–11:34:00 | UAC bypass repeated; second elevated agent establishes a second reverse shell |
| 11:52:16 | `tar.exe` archives files on FYODOR-L — the only data-collection action evidenced |
| 11:59:33–11:59:36 | The three long-running Empire sessions are last observed beaconing |

## Scope of impact

Two hosts were compromised.

- **FYODOR-L** (Windows, dual-homed pivot host): initial access, execution, privilege escalation,
  backdoor account, persistence, internal reconnaissance, data collection.
- **hoth** (Ubuntu 16.04, Java application server): remote exploitation, kernel privilege escalation,
  backdoor account, reverse shell.

A second user, `bstoll`, is **Confirmed** to have clicked and downloaded the lure twice. No execution
evidence exists on BSTOLL-L, and two further recipients show no participation evidence at all.
Execution evidence exists on exactly two hosts, so the affected-host count is two.

## Four findings that took work

**The scheduled task was not the persistence.** `Updater` was a delivery vehicle. It was registered at
10:09:44, fired once at 10:11:00, and was deleted at 10:16:54 — while the SYSTEM-context implant it had
delivered kept beaconing for another 103 minutes after that deletion. An analyst who responds to this host by
enumerating scheduled tasks and registry autoruns finds a clean system.

**Five Empire sessions, not one.** Aggregating Sysmon EventID 3 by `ProcessGuid` across 09:00–18:00
resolves this host's C2 traffic into five sessions in three roles: a base implant that only spawns,
two disposable elevated agents that carry every operator action, and two resident SYSTEM implants that
hold standing access. An earlier count of 2,074 connections in a narrower window was four sessions
summed, with a fifth truncated out entirely.

**The UID 0 account on `hoth` is a two-stage sequence.** Read as a single attempt it looks like a
failure. The failure under uid 111, the kernel escalation, and the successful re-issue under root are
the causal spine of the Linux half of the intrusion.

**One attractive correlation failed one field comparison.** `chrome.exe` reached `hoth` 28 times inside
the exploitation window, which suggested the operator mined the user's browser history for a target.
The exploited endpoint appears nowhere in that browsing session. The correlation was real; the causal
claim was not.

## Detection

Nine deployable SPL analytics are delivered for the Windows side of the chain. The three with the best
leverage:

- **Beacon detection by interval regularity, aggregated per `ProcessGuid`.** At the time of the
  incident `45.77.53.176` carried no reputation signal, and the beacon shared egress interface, port
  and transport with legitimate Microsoft cloud traffic. Reputation and tuple-based logic are blind
  here; interval regularity is not. Per-`ProcessGuid` aggregation is also what keeps all five sessions
  from collapsing into one.
- **`fodhelper.exe` UAC bypass, including a registry stanza that fires before elevation succeeds.**
  Catches both instances, at 10:07 and at 11:32.
- **A browser-delivered file executing a scripting host with no intervening user action.** This is the
  earliest point in the chain where a single event is sufficient on its own.

Coverage is deliberately scoped to the Windows endpoint. Linux and network-layer techniques receive
full narrative analysis and named detection opportunities but no delivered rules. The coverage
assessment in the detection pack lists every step in the chain that has no delivered rule, including
three Windows-side actions that surfaced late in the evidence review.

## Three controls that would have truncated this

1. **Segment the user network from the server network.** The sweep crossed from `192.168.8.0/24` into
   `192.168.9.0/24` because nothing prevented it. Everything after 10:43 depended on that traversal.
2. **Remove build toolchains from production application servers.** The kernel exploit was compiled on
   the victim by the Tomcat service account. Without a usable compiler the operator has to
   cross-compile and transfer a binary, which is slower and noisier.
3. **Remove standing local administrator rights from interactive users.** The UAC bypass needed no
   exploit and no credential, only Administrators membership that the interactive user already held.

## What this analysis does not establish

- How `bgist`'s credentials were stolen. The theft precedes the observed window.
- The mechanism that launched the second resident SYSTEM implant at 10:15:27. Attribution is
  Confirmed; the trigger is **Parked**.
- Whether `svcvnc` was ever used to authenticate.
- What `tar.exe` archived, and whether anything was transmitted. Collection is **Confirmed**;
  exfiltration is not evidenced.
- Who created the `tomcat7` (UID 0) account that already existed on `hoth` before the Struts2 chain
  began, by a method that left no `useradd` record. Identified and **Parked**; not investigated in
  this analysis.

## Documents

| | Contents | Read time |
|---|---|---|
| **Incident report** | The full chain, Phases 1–3, with evidence and coverage boundaries | ~40 min |

Detection analytics and IOC bundle are included in the incident report for now and will move to a
standalone detection pack in a later update.

## Environment

Splunk with the BOTSv3 dataset (2,030,269 events). The Splunk account timezone is set to UTC, so
`_time` equals the in-event `UtcTime` and no offset conversion is applied anywhere in this analysis.
The Sysmon XML sourcetype carries no automatic field extraction; all fields are extracted with `rex`
from `_raw`. Environment-specific query behaviour that affects result correctness is documented in the
incident report's methodology section.
