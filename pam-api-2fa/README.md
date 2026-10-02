# PAM API + TOTP for Debian/Ubuntu VMs

This directory is a separate VM integration for the Flask API in the parent
folder. It authenticates API-backed users with their API password first and a
TOTP code second, for both SSH and sudo. Local users below `base_uid` continue
through the VM's existing PAM configuration. API users are virtual NSS users;
they do not need a local `/etc/passwd` account.

The API must be reachable from each VM over HTTP or HTTPS. HTTPS is strongly
recommended. HTTP is supported for trusted, isolated networks only: passwords,
TOTP codes, and login challenges are sent without transport encryption and can
be read or altered by anyone able to observe the network. For HTTPS, the VM
must trust the server certificate. The PAM module refuses redirects, timeouts,
malformed responses, and API errors. It uses the existing JSON API: `POST
/api/login`, followed by `POST /api/2fa`.

## Before installing

1. Keep the VM provider console open and confirm you have a working local
   administrator account. The SSH settings below require PAM keyboard-interactive
   and disable SSH public-key/password methods so API users cannot skip the OTP.
   Do not proceed without console recovery access.
2. Install and run the Flask API separately. Prefer an HTTPS reverse proxy; do
   not expose Flask's development server directly to the Internet. If using
   HTTP, restrict traffic to a trusted isolated network or VPN and firewall the
   API so it is not reachable from untrusted networks.
3. Create API users at the API's `/manage` page and scan each user's QR code into
   an authenticator app. The username must match the userdb name rules below.
4. Record the current files before editing:

   ```sh
   cp -a /etc/pam.d/sshd /etc/pam.d/sshd.before-api-2fa
   cp -a /etc/pam.d/sudo /etc/pam.d/sudo.before-api-2fa
   cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.before-api-2fa
   ```

## Install module

On each Debian/Ubuntu VM:

```sh
apt update
apt install -y build-essential pkg-config libpam0g-dev libcurl4-openssl-dev libjson-c-dev jq libnss-systemd libpam-modules
```

Copy this `pam-api-2fa` directory to the VM, then build and install:

```sh
make
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now io.local.apiuser.socket
```

The installer places the PAM module in the architecture-specific PAM module
directory, installs the systemd userdb helper and socket, and creates
`/var/lib/apiusers` as a root-owned directory with mode `0700`.

Check `/etc/nsswitch.conf`. Ensure `systemd` appears on the `passwd` and `group`
lines, without removing existing sources such as `files`, for example:

```text
passwd:         files systemd
group:          files systemd
```

API names accepted by the virtual user database match:
`[a-z0-9_][a-z0-9_.+-]{0,62}` with an optional `@domain` suffix. For SSH
portability, prefer names without `@`. The UID is deterministic in the range
starting at `1000000000`; a root-owned registry detects two names resolving to
the same UID.

## Configure PAM

Replace `https://auth.example.com` below with the API's base URL. Both
`https://` and `http://` are accepted; do not include `/api/login` in the base
URL. Add the auth line before
`@include common-auth` in `/etc/pam.d/sshd` and `/etc/pam.d/sudo`:

```text
auth [success=done ignore=ignore user_unknown=ignore default=die] pam_api_2fa.so base_url=https://auth.example.com base_uid=1000000000 timeout=5
```

Keep every existing `@include` and other PAM line. The API module short-circuits
on a successful password+OTP, rejects failed API authentication, and returns
`PAM_IGNORE` for local accounts so the existing `common-auth` handles them.

In `/etc/pam.d/sshd`, also add this account line immediately before
`@include common-account`:

```text
account sufficient pam_succeed_if.so uid >= 1000000000 quiet
```

Add this session line before `@include common-session` so the home exists before
the SSH session opens:

```text
session required pam_mkhomedir.so skel=/etc/skel umask=0077
```

In `/etc/pam.d/sudo`, add the same account line immediately before
`@include common-account`. Do not remove `@include common-session-noninteractive`
or any other existing sudo PAM entries.

The account rule allows virtual API users through account management; their
enabled/disabled state is checked by `/api/login`. Local accounts still use the
existing common-account rules.

## Configure SSH

Create `/etc/ssh/sshd_config.d/50-api-2fa.conf`:

```text
UsePAM yes
PasswordAuthentication no
KbdInteractiveAuthentication yes
AuthenticationMethods keyboard-interactive:pam
```

This requires all SSH logins to use the PAM conversation, which asks for the
API password and then the authenticator code. It also means SSH public-key
login is not available under this policy. Keep console/provider recovery
available and test in a second SSH session before closing the current one.
Check for earlier SSH configuration snippets that override these values.

Validate before applying:

```sh
sshd -t
sshd -T | grep -Ei '^(usepam|passwordauthentication|kbdinteractiveauthentication|authenticationmethods)'
systemctl reload ssh
```

Expected effective values include `usepam yes`, `passwordauthentication no`,
`kbdinteractiveauthentication yes`, and `authenticationmethods
keyboard-interactive:pam`.

## Grant sudo separately

Authentication does not grant sudo privileges. Create
`/etc/sudoers.d/90-api-sudo` with only the API users who need access, for
example:

```text
User_Alias APIADMINS = alice, bob
APIADMINS ALL=(ALL:ALL) ALL
Defaults timestamp_timeout=0
```

`timestamp_timeout=0` requires password and OTP for every sudo authentication.
Choose a nonzero timeout only if cached sudo authentication is acceptable.
Validate and set permissions:

```sh
visudo -cf /etc/sudoers.d/90-api-sudo
chmod 0440 /etc/sudoers.d/90-api-sudo
```

Do not grant all API users unrestricted sudo unless that is intentional. Sudo
authorization remains controlled by sudoers, not by the successful API login.

## Test and recover

Before testing SSH or sudo, verify the virtual user lookup:

```sh
getent passwd alice
id alice
```

Then test from a second terminal: SSH should ask for the API password followed
by the TOTP code; `sudo -k; sudo -v` should ask for both again. Confirm a local
administrator still authenticates with the local password and that an API user
not listed in sudoers cannot run sudo. Check logs with:

```sh
journalctl -g pam_api_2fa -n 30 --no-pager
journalctl -u io.local.apiuser.socket -n 30 --no-pager
```

Authentication fails closed for API users if the API is unreachable. Local
accounts below `base_uid` remain the recovery path through local PAM; do not
change their UID range without changing the module configuration.

Rollback from the provider console or an already-open root session:

1. Restore `/etc/pam.d/sshd`, `/etc/pam.d/sudo`, and SSH configuration from the
   backups above; run `sshd -t` before reloading SSH.
2. Remove `/etc/sudoers.d/90-api-sudo` if created and run `visudo -c`.
3. Stop the virtual user database and remove the integration:

   ```sh
   systemctl disable --now io.local.apiuser.socket
   rm -f /etc/systemd/system/io.local.apiuser.socket /etc/systemd/system/io.local.apiuser@.service
   rm -f /usr/sbin/apiuser-userdb
   systemctl daemon-reload
   ```

4. Remove `/var/lib/apiusers` only if its contents are no longer needed. The
   PAM shared object may be removed from the architecture-specific
   `security/pam_api_2fa.so` directory after it has been removed from all PAM
   files.

## Security notes

- HTTP is unencrypted. Anyone with access to the VM-to-API network path can
   capture or modify the API password, OTP, and challenge. Use HTTPS wherever
   possible; otherwise isolate the network and use a trusted VPN.
- Anyone who can use an API identity listed in sudoers can obtain that VM's
  granted sudo privileges. Keep sudoers restrictive and protect the API.
- The TOTP secret is held by the API and the authenticator app. Never put it in
  VM logs, PAM options, or source control.
- Use API rate limiting and monitoring. The five-second timeout is per API
  request, so a complete login can take up to about ten seconds on a slow
  connection.
- The deterministic UID uses a truncated MD5 digest only for stable UID
  assignment, not for authentication. The registry rejects a UID already
  associated with another username.