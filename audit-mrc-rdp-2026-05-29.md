# AUDIT MEMO — MRC.exe / "Nov 16 RDP session" narrative is WRONG

**Date:** 2026-05-29 · **Examiner:** hermes-agent · **Case:** rocba-drive-20260526-1417 · **Host:** srl-forge
**TODO:** TODO-hermes-agent-004 (part 1 of 2 — MRC attacker-vs-responder). Part 2 (EDT/UTC normalization) still open.

## Verdict
Three inherited DRAFT findings — **F-claude-004, F-claude-012, F-claude-013** — assert the Nov 16
02:31 Magnet RAM Capture (MRC.exe) was run by the **remote attacker via an active RDP session with
USB drive redirection**. Primary evidence shows this is **false**. The Nov 16 RAM capture and USB
activity were **hands-on-keyboard at the physical console**. No RDP session existed on Nov 16.
**Attribution of the local actor = OPEN** (not provably the sanctioned IR team — see below).

## Evidence (all from indexed artifacts this session)

1. **No RDP logon exists on Nov 16.** All 12 EID 4624 Type-10 (RemoteInteractive) logons in the
   entire case are:
   - Nov 10 13:26:11 — `srl-helpdesk@outlook.com` from **174.196.200.9** (2 sessions, LID 0x21f2c0/0x21f2ef)
   - Nov 14 12:31:26 — `fred.rocba@outlook.com` from **52.249.198.56** (LID 0xe9d8981/0xe9d8a05)
   - Nov 14 12:52:03 — `fred.rocba@outlook.com` from **52.249.198.56** (LID 0xef01b99/0xef01c24)
   The last remote RDP was **Nov 14 12:52**. None on Nov 16. (audit opensearch-examiner-20260529-027/028)

2. **The Nov 16 02:29:36 4778 was a LOCAL console reconnect**, not remote. Control: this same host
   logs the *remote* client IP on every Nov 14 reconnect (`SrcIP: 52.249.198.56 ¦ SrcComp: cobra`),
   but the Nov 16 reconnect is `SrcIP: LOCAL ¦ SrcComp: Unknown` (TgtUser fredr, LID 0xa5d65).
   Someone resumed the leftover disconnected session 0xa5d65 from the physical console.
   (audit opensearch-examiner-20260529-019)

3. **MRC ran in the local console session.** vol3: MRC.exe PID 29440, **PPID 7464 = explorer.exe**
   (C:\WINDOWS\Explorer.EXE, started Nov 11 08:13), **SessionId 1**, created 2020-11-16 02:31:15,
   cmdline `"D:\Tools\MRC.exe"`. Interactive double-click from the desktop, not a service/script.
   BAM records it under fredr's SID at `\Device\HarddiskVolume7\Tools\MRC.exe`, exec 02:39:23.
   (audit opensearch-examiner-20260529-014, -017)

4. **ArbcoCircus (D:) was a PHYSICALLY-attached USB, not an RDP-redirected drive.**
   Windows Portable Devices: FriendlyName **ArbcoCircus**, `DISK&VEN_IS917&PROD_INNOSTOR&REV_1.00`,
   SN `201207220009&0`, first connected **2020-11-10 12:49:59**. Matches USBSTOR + MountedDevices
   `\DosDevices\D:`. RDP-redirected drives appear as `\\tsclient\X` / `\Device\RdpDr` and create
   **no** USBSTOR/`\Device\HarddiskVolumeN` entry — so F-013's "drive redirection" mechanism is
   physically impossible here. (audit opensearch-examiner-20260529-018, -020)

## Why this matters (the deeper layer)
The whole confirmed intrusion is **remote RDP** (Azure 52.249.198.56 / WIIT-AG / Verizon IPs). A
remote attacker **cannot physically insert a USB**. Yet ArbcoCircus (carrying the BitLocker recovery
key in a folder literally named `secret key`, and later MRC.exe) was physically plugged into
SRL-FORGE on **Nov 10 12:49** — *before* the Nov 14 exfil that would trigger any IR engagement — and
again present Nov 16. The sanctioned SRL IR was **remote**, so a local/physical RAM capture is not
obviously the IR team. ⇒ **A physical-access actor was present Nov 10 + Nov 16 that the remote-only
narrative cannot explain.** This is a Thread-C (insider / physical-access) signal, attribution OPEN.

## Specific corrections to inherited findings
- **F-claude-004** ("...via attacker RDP session"): process facts are correct (PID/PPID/path);
  the *interpretation* "attacker / active RDP session" is wrong → local console.
- **F-claude-012** ("Nov 16 RDP Session..."): there was no Nov 16 RDP session. Also its 5379
  "credential extraction confirmed" is an **over-read** — EID 5379 is routine Credential Manager
  enumeration on session resume, not proof of harvesting.
- **F-claude-013** ("Both USBs Operated Remotely / RDP Drive Redirection"): refuted by USBSTOR/WPD.
  Six identical-second jumplist LNKs are explained by a single shell enumeration on mount, not
  redirection.
- **F-lms-001** (refine, not refute): 213.202.233.104 is an **NTLM RDP brute-forcer** (EID 4625,
  Type 3, hundreds of bogus usernames, spoofed SrcComp, Nov 15 ~23:53) — not a clean "second RDP
  endpoint." 81.30.144.115 attribution unchanged pending.

## Still OPEN
- Who is the physical-access actor (Fred? SRL staff? IR? accomplice)? Needs IR-engagement records /
  briefing — out of image scope.
- `srl-helpdesk@outlook.com` RDP from 174.196.200.9 on Nov 10 — legit helpdesk or attacker account?
- TODO-004 part 2: EDT/UTC normalization sweep across all timing claims.
