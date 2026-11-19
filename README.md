# EMS

Employee activity tracking and site blocking for company-owned Windows
computers. A rewrite of `cf_tracking` in Rust, built so the backend runs on
a small VPS and the client installs with a double-click.

- **`ems-server`**: one program holding the database and the admin web
  console. Runs on Linux or Windows. One server looks after any number of
  client companies ("organisations"), each kept apart from the others.
- **`ems-agent.exe`**: one 2.6 MB program for each Windows computer. It
  keeps itself up to date from the server.

The agent shows a tray icon while it runs, and clicking it opens a plain
status window (connection and version). It does not, by itself, display a
notice that activity is recorded or that sites may be blocked: giving staff
that notice before deploying it is the organisation's responsibility, and it
is legally required in many places. Check what the law requires where the
client operates. (The `ems-agent status` command still shows the full
picture, including blocked sites, for whoever administers the computer.)

## Set it up

### 1. The server (once)

Copy the `dist/server-linux` folder to the VPS (Debian or Ubuntu) and run:

```sh
sudo ./install-server.sh ems.example.com
```

That installs the server as a service, sets up HTTPS for that name with
Caddy, and prints the administrator password. Point the DNS name at the VPS
first. Without a name (`sudo ./install-server.sh`) it runs on plain HTTP
port 2021, which is fine for a LAN or a trial but is not encrypted.

Run the same command again to upgrade; the database is kept.

**On a hosting panel without root** (CloudPanel and similar, where you get a
site user and the panel already serves the domain over HTTPS and forwards
it to a local "app port"): create the site as a Node.js or reverse-proxy
site, issue its Let's Encrypt certificate in the panel, copy the same
folder to the site user's home, and run this instead, giving the site's
app port:

```sh
./install-server-user.sh 2020
```

It installs into `~/ems`, listens on that port on the machine only, and
adds a cron entry that starts the server after a reboot and restarts it
within a minute if it ever stops. Logs are in `~/ems/logs/server.log`.
Agents refuse a self-signed certificate, so the Let's Encrypt step matters.

### 2. Each client company

1. Sign in to the console and open **Organisations**.
2. Type the company's name and click **Create and download installer**.
   The name must be unique.

The file that downloads (`EMS-Agent-<name>.exe`) is that organisation's
installer. It can be downloaded again at any time from the same page, or
from **Settings** while the organisation is selected.

### 3. Each computer

Run the organisation's installer on each of its computers and choose
**Yes** when Windows asks for permission.

The installer already knows which server to use and which organisation it
belongs to. It installs itself, starts, and shows a message saying whether
it reached the server. The computer then appears under **Computers** for
that organisation, by its name.

To remove it: Windows Settings → Installed apps → EMS Agent → Uninstall.
This also lifts every block the agent applied.

### Working in the console

The **Organisation** picker at the top left decides which client every page
shows: its computers, activity, blocked sites, blacklist words, categories,
settings and report key. Nothing is shared between organisations, and two
of them can each have a computer with the same name.

On the **Organisations** page an organisation can be renamed (installed
computers are not affected) or removed. Removing one deletes its computers
and everything recorded for them, after you type its name to confirm, and
its agents are turned away from then on.

## How it works

```
 Employee PC                                        VPS
┌──────────────────────────────────────┐          ┌───────────────────────────┐
│ Tray helper (runs as the user)       │          │ Caddy (HTTPS)             │
│  sees the window in front, reads the │          │      │                    │
│  address, closes blocked tabs        │          │ ems-server                │
│            │ local pipe              │  HTTPS   │  check-in endpoint        │
│ Service (runs as SYSTEM)             │─────────►│  SQLite database          │
│  upload queue, hosts file,           │ every 5  │  admin console            │
│  browser block list                  │ minutes  └───────────────────────────┘
└──────────────────────────────────────┘                    ▲ admin's browser
```

**Check-in.** Every 5 minutes (changeable under Settings) each computer
makes one HTTPS request. It says "I am here", uploads the activity recorded
since last time, and gets back the blocking list and settings only if they
have changed. In between, activity is kept on the computer and the server
is not contacted at all.

**Identity.** A computer is known by its organisation and its name. There
is nothing to enroll and no per-computer secret. The console shows the
name, the computer's network address, the signed-in user and the Windows
version.

**Organisation.** Each organisation has a key, created with it and never
changed. The server attaches that key (with its own address and the
organisation's name) to the agent program when an installer is downloaded,
so the installer needs nothing typed in. Every check-in carries the key:
it is what places the computer under its organisation, and a check-in
without a known key is refused. The key is not shown in the console.

**Updates.** With each check-in the agent says which program it is
running. When the server holds a different one, the agent downloads it,
checks it is exactly the file the server described, runs it once to see
that it starts, and then restarts itself on it. If the new agent does not
stay up, the previous one is put back. A program that cannot be installed
is tried three times and then left alone until the server has a different
one. To update every computer, upload the new `ems-agent.exe` on the
Organisations page (see "Releasing a new agent" below); nobody visits the
computers.

An update never moves a computer between organisations. The program is the
same file for everyone and contains no organisation's key. The key lives on
each computer, in `C:\ProgramData\EMS\agent.json`, written once when the
organisation's installer ran, and an update does not touch that file. So
one release reaches the computers of every organisation and each stays
where it was.

**What is recorded.**

- The application in the foreground and its window title.
- In a browser, the site and address of the tab in front.
- Nothing while the computer is locked, asleep or left idle. Watching a
  video or sitting in a call counts as activity even with no input.
- Attempts to open a blocked site, and pages closed for a blacklist word.

Settings can turn website or application tracking off, and store addresses
without their query string or as the domain only.

**System inventory.** Once a day (and whenever it changes) each computer
reports a slow-changing snapshot of itself, uploaded only when it differs
from the last one so it costs almost nothing. It is gathered once a day, not
on every check-in, because none of it changes minute to minute:

- A system summary: Windows edition and build, when that build was installed
  (the last feature update), processor, memory, system-drive space, uptime,
  make and model, and whether a restart is pending to finish a Windows update.
- Network: the computer's local address, the public address the server saw
  the check-in come from, the active adapter's hardware (MAC) address, and
  whether it is on Wi-Fi or Ethernet.
- The printers the computer can print to.
- The full list of installed programs (name, version, publisher, install
  date), read from the registry — the same list as Windows "Installed apps",
  across the machine-wide and per-user locations.
- The last ~150 lines of the agent's own log, for troubleshooting.

The console shows the summary on the **Overview** page when a computer is
selected (with a fleet line — how many need a restart — when none is), the
installed-programs list behind the **Installed programs** button on the
**Applications** page, and the agent log behind **View logs** on the system
card. A precise "updates available" count is deliberately not gathered: it
needs a slow Windows Update scan on every machine. The reboot-pending flag
and the last feature-update date cover the common need cheaply.

**Lock, restart and shut down.** From the **Computers** page an administrator
can lock the screen of, restart, or shut down any computer. The instruction
rides on the next check-in (so it reaches the computer within one check-in
interval, or when it next connects if it is offline). A restart or shutdown
shows the person a 60-second warning to save their work and then closes
programs itself; a lock takes effect at once, so they must sign in again.
Each instruction is handed over exactly once — so a restart can never loop —
and a queued one can be cancelled from the console before the computer picks
it up. The agent service holds the Windows shutdown right and starts the
lock in the signed-in session itself, so nothing extra has to be installed.

**Blocking.** A block is picked up at the next check-in. Then:

1. **Hosts file.** The blocked name, its `www.` form and every subdomain
   that has been seen in the fleet stop resolving, for every program.
2. **Tab closer.** If a blocked page is in front anyway (it was already
   open, the browser had it cached, it is a subdomain the hosts file does
   not list, or the user goes through a proxy), its tab is closed. This is
   also the only thing that enforces blacklist words, which are not sites.

Both take effect at once and are undone at once: unblock a site, or remove
the agent, and the site opens again straight away.

A third layer is optional and off by default (Settings → Blocking → "Also
give browsers their own block list"). With it on, Chrome, Edge, Brave,
Vivaldi and Firefox refuse blocked sites and all their subdomains
themselves, even if the tray helper is stopped. The cost is that an open
browser re-reads that list only every 15 minutes or when restarted, so a
site stays blocked for up to 15 minutes after it is unblocked or the agent
is removed (`chrome://policy` → Reload policies clears it at once), and the
browser shows "managed by your organization".

Blocking by IP address in the Windows firewall is deliberately not used:
large sites share addresses with unrelated ones, so an address rule for one
site breaks others.

The agent never blocks its own server's address, and the console refuses
such a block.

**Offline.** Records wait in `C:\ProgramData\EMS\spool` and are sent when
the server is reachable again. The last blocking list stays in force.

## Options

All of these are set per organisation, under Settings.

- **Agent updates** (Settings). On by default. Turn it off for an
  organisation to keep its computers on the agent they have; the Computers
  page then marks them "updates off" when the server holds a newer agent.
  Turning it off for all but one organisation is a way to try a new agent
  on one client first.
- **Notice when something is blocked** (Settings). Off by default: the tab
  simply closes and the attempt is listed in the console. Turn it on to
  show the user a short "blocked by your organization" notice.
- **Browsers' own block list** (Settings). Off by default; see Blocking
  above for what it adds and what it costs.
- **Check-in interval** (Settings, 15 to 3600 seconds, 300 by default).
  Shorter applies blocks sooner; longer means fewer requests.
- **Retention** (Settings). Activity older than 90 days is deleted
  automatically; change the number of days (e.g. 7) or set 0 to keep
  everything. Only recorded activity is pruned — website visits, application
  usage, and the blocked-attempt and word-hit logs. Block lists, blacklist
  words, categories, computers and their system inventory are always kept.
  A **Clear recorded activity now** button under Settings → Data does the
  same deletion on demand.

## Users and permissions

The first administrator is an **owner**: they see and manage every
organisation, and manage users. Under **Users**, an owner can create more
logins and decide, per person, which organisations they reach and what they
may do there:

- **View** (always, once an organisation is granted): reports, computers,
  system info and logs.
- **Blocking**: add and remove blocked sites, blacklist words and categories.
- **Settings**: change the organisation's settings, its report API key, and
  clear its activity.
- **Control**: lock, restart, shut down and remove computers.
- **Installer**: download the organisation's installer.

A **member** sees only the organisations granted to them, with only the
permissions ticked; the console hides what they cannot use, and the server
refuses it regardless. Another owner can be created for a trusted colleague
who should manage everything. The per-organisation report API key remains a
separate, read-only way in for scripts.

## Report API

`GET /api/visits/report/suspicious?date=YYYY-MM-DD[&machine_uuid=][&min_sec=]`
returns the day's suspicious visits, each marked blocked or unblocked.
`machine_uuid` is the computer's name. Create a key under **Settings →
Report API key** and send `Authorization: Bearer <key>`. A key belongs to
the organisation that was selected when it was created: it reads that
organisation's activity and list of computers and nothing else, and cannot
change anything. Calendar days follow the organisation's reporting time
zone.

## Load, measured

Release build of version 1.1.1 on a desktop PC, with `ems-loadtest`
simulating 1,000 computers split over two organisations (500 each, with the
same computer names in both):

| Situation | Server CPU | Server memory |
|---|---|---|
| Default 5-minute check-in, 50 rows each | 0.9% of one core | about 30 MB |
| 60 s check-in, 40 rows each | 2.5% of one core | about 30 MB |
| Stress: 200 check-ins and 4,000 rows per second | 21% of one core | 34 MB |

No check-in failed in any run, and the median check-in took 2 ms. A block
added for one organisation reached all 500 of its computers within one
interval (at 60 s: median 29 s, last 60 s; at the default: median about
2.5 minutes, last 5 minutes). A 1 vCPU / 1 GB VPS has ample room for
several hundred computers. Memory is the highest figure seen while the
three runs were made one after another on the same server process.

On each computer the agent's two processes together used about 25 MB of
memory and about 0.1% of one CPU core.

Disk: 135 bytes per stored row was measured with short test addresses; real
addresses and window titles are longer, so plan for 250–300 bytes. At an
estimated 1,500 rows per computer per working day that is about 40 MB a day
per 100 computers, or under 4 GB for the default 90 days.

## For developers

```sh
cargo test --workspace     # 100 tests
cargo build --release      # server, agent, load tester
```

Building the server needs a C compiler (`build-essential` on Debian or
Ubuntu) because SQLite is compiled in. `dist/server-linux/ems-server` was
built on Ubuntu 24.04 and needs glibc 2.34 or newer (Ubuntu 22.04+,
Debian 12+); for an older system build on the VPS or use `deploy/Dockerfile`.

**How an installer finds its server and organisation**, first match wins:

1. `--server` and `--key` on the command line;
2. settings attached to the file itself (what **Download installer** produces);
3. `ems-agent.json` in the same folder (the console offers this file when
   the agent program is not on the server);
4. values compiled in: build the agent with the `EMS_SERVER` and `EMS_KEY`
   environment variables set to the server and to the organisation's key;
5. the installation already on the computer (an upgrade).

`ems-agent.exe settings` prints which one a given file will use and whose
installer it is. `ems-server orgs` lists the organisations with their keys,
for the command-line and compiled-in cases.

**Releasing a new agent.** Raise `version` in `Cargo.toml` and build. Then,
in the console, open **Organisations → Update the agent on all computers**,
choose the new `ems-agent.exe`, type your password and click **Upload and
roll out**. The password is asked for again because this one action reaches
every computer of every organisation. The server refuses a file that is not
an EMS agent of version 1.1 or later, and if an organisation's installer is
uploaded by mistake it keeps only the program, not that organisation's key.

Each computer moves to the new program at its next check-in. The **Agent**
column on the Organisations page shows how many computers of each
organisation have, and the Computers page marks the ones still to go. To
try a release on one client first, turn "Update the agent automatically"
off under Settings for the others, upload, and turn it back on when you
are satisfied.

Without the console, replacing `ems-agent.exe` in the server's data folder
does the same (copy it under another name first and rename it into place,
as the install scripts do); the server notices within half a minute. A web
server in front of EMS may limit upload size: the file is about 2.6 MB, so
nginx's default of 1 MB (`client_max_body_size`) is too small, and the
console says so if the upload is refused.

Computers are compared by the program's fingerprint, not its version
number, so the file on the server is always what they end up running:
uploading an older file moves them back.

Agents take an update only from an `https://` server. The update itself is
not signed: it is trusted because it comes from the server over a checked
certificate, so whoever controls the server controls what runs on the
computers. Keep access to the server and its data folder tight.

**Upgrading a server from 1.0.** Start the new program on the old data
folder. The database is converted on first start, and a copy of the old
file is kept next to it as `ems.db.before-organisations`. Everything
recorded so far goes to one organisation named "Default", which keeps the
old agent key, so computers that are already installed carry on reporting.
Rename it on the Organisations page.

**Server settings** (environment variables, or a `.env` file):

| Variable | Default | Meaning |
|---|---|---|
| `EMS_BIND` | `0.0.0.0:2021` | Listen address. |
| `EMS_DATA_DIR` | `./data` | Holds `ems.db`, and `ems-agent.exe` for installers and updates. Back this folder up. |
| `EMS_TRUST_PROXY` | off | Set to `1` behind a TLS proxy. |
| `EMS_ADMIN_USER`, `EMS_ADMIN_PASSWORD` | `admin`, generated | First-run administrator. |

`ems-server set-password <user> [password]` resets a password.

**Agent commands**, for scripts (run elevated):

```bat
ems-agent.exe install [--server <address>] [--key <agent-key>]
ems-agent.exe uninstall [--keep-data]
ems-agent.exe status
```

`deploy/install-agent.cmd` wraps a silent install for a deployment tool.
Logs: `C:\ProgramData\EMS\logs\agent.log` (service) and
`%LOCALAPPDATA%\EMS\session.log` (tray helper).

**Trying it without installing anything:**

```sh
EMS_BIND=127.0.0.1:2021 EMS_ADMIN_PASSWORD=change-me-now target/release/ems-server
# create an organisation in the console (http://127.0.0.1:2021), then:
target/release/ems-server orgs        # id, agent key, name
target/release/ems-agent run --data-dir ./dev-agent --server http://127.0.0.1:2021 --key <key> --pipe dev
target/release/ems-agent session --pipe dev
target/release/ems-loadtest --server 127.0.0.1:2021 --agents 500 --admin admin:change-me-now
```

The load tester signs in and uses an organisation named "Load test",
creating it if needed (`--org` picks another name).

A development run does not touch the real hosts file or browser policy, and
does not update itself unless started with `--self-update`.

```
crates/proto      messages and rules both sides share
crates/server     check-in endpoint, storage, admin API, console (crates/server/ui)
crates/agent      service, blocking (guard/), tray helper (session/), installer
crates/loadtest   simulated computers
deploy/           VPS setup script, Caddyfile, Dockerfile, silent-install wrapper
```

## Tested, and not yet tested

Tested on this development PC (Windows 11) and in WSL (Ubuntu):

- The 100 unit tests, on Windows; the server's also on Linux.
- Releasing an agent from the console, against a local server: a wrong
  password, a text file, another Windows program and a request without
  signing in were all refused; the real agent was accepted, stored exactly
  and used for the next installer; the form itself was driven in Chrome.
- Organisations, with a real server and real agents on this PC: two
  organisations each with a computer of the same name, a different block
  for each arriving only at its own computer, a report key unable to read
  the other organisation, a removed organisation's agent being turned
  away, and the console's pages in Chrome.
- A database from version 1.0 (made by the 1.0 server, which was then
  killed) converted by the new server: every computer, visit, application
  row, block, word, category and setting was still there, and agents with
  the old key kept reporting.
- The agent updating itself, in a development run: a 1.1.0 agent refused a
  file that was not a working program and carried on; then moved itself to
  a real 1.1.1 a few seconds after the server offered it, keeping its
  blocks and settings; an organisation with updates off was left alone.
- A real agent against a real server over the check-in: the computer
  registering itself by name, a block arriving at the next check-in and
  being written to a hosts file, queued activity uploaded and acknowledged,
  and the agent recovering by itself.
- The key: a fresh server requiring one, check-ins without it refused, and
  the downloaded installer carrying the same key.
- A live server on a VPS (CloudPanel, behind its nginx, Let's Encrypt
  certificate): the console and sign-in over HTTPS, cron restarting the
  server after it was stopped, and a real agent on this PC registering and
  uploading to it with full certificate checking.
- The downloaded installer finding its server from itself, from
  `ems-agent.json`, and explaining itself when it has neither.
- Reading the address bar of a real Chrome and closing a tab in it.
- The console in Chrome, light and dark, desktop and phone width.
- The load figures above; the Linux server starting and answering.

**Tested only once, or not yet:**

- An update of an installed computer has been done once for real: a PC
  with 1.1.0 installed from an organisation's installer, and 1.1.1 released
  from the console on the VPS. About 30 seconds after its check-in the PC
  was running 1.1.1 as a service: the service had been stopped, swapped and
  started, the tray helper was started again by the service 8 seconds
  later, records that had been waiting were uploaded, "Installed apps"
  showed 1.1.1, and the computer was still in its own organisation. The
  path where the new agent fails to stay up and the old one is put back has
  only been run on stand-in files, not on an installed service.
- Agents installed before 1.1.0 cannot update themselves; they have to be
  installed once more by hand with a 1.1.0 or later installer.

- The install has now been done for real on one PC (double-click, with the
  Windows prompt): the computer registered with the server, a blocked tab
  was closed at once, and uninstalling left nothing behind. It has not
  been tried on other Windows versions or signed in as a standard
  (non-administrator) user. Try it on one more computer before a wide
  roll-out.
- `install-server.sh` (the root version, with Caddy) on a real VPS. It has
  only been syntax-checked. `install-server-user.sh` has been run for real,
  on a CloudPanel site on Ubuntu 24.04.
- Edge and Firefox. Only Chrome was read live.

Known limits:

- Within an organisation a computer is its name. Two computers of one
  organisation with the same name are recorded as one, and renaming a
  computer makes it appear as a new one.
- An organisation's key cannot be replaced. If an installer falls into the
  wrong hands, the remedy is a new organisation and reinstalling.
- The installer is not code-signed, so Windows SmartScreen may warn about an
  unrecognised app when it was downloaded from the internet. Choose
  "More info" then "Run anyway", or sign the file.
- A block, and anything else changed in the console, takes up to one
  check-in interval to arrive (5 minutes by default). Activity appears in
  the console with the same delay.
- With the optional browser block list on, Firefox applies it only when
  it starts.
- A tab is closed by pressing its own close button. For a browser whose tab
  strip cannot be read the agent falls back to sending Ctrl+W; that
  fallback did not close the tab in the live attempts made here.
- The agent connects directly; an authenticating outbound web proxy is not
  supported.
