
                    _______________________________________________
                   |                                               |
                   |  NETHSECURITY: A LOVE LETTER IN FIVE PARTS   |
                   |                                               |
                   |     or: how i mass-owned every nethsec box    |
                   |     on the internet with a password from      |
                   |              their github repo                |
                   |_______________________________________________|

                              by s e g a
                              august 2026

              "please refrain from opening security issues
               that have not been verified by a human"
                    -- the vendor, mass-deploying a fix
                       written by Claude Code

------------------------------------------------------------------------

[0x00] TABLE OF CONTENTS

      0x00 .... table of contents
      0x01 .... what is this
      0x02 .... the target
      0x03 .... the chain (summary for the impatient)
      0x04 .... finding 1: the password is on github
      0x05 .... finding 2: the front door is open
      0x06 .... finding 3: everybody is admin
      0x07 .... finding 4: the pretty one
      0x08 .... finding 5: redundancy as a weapon
      0x09 .... what root on a firewall actually means
      0x0A .... the things that DIDN'T work
      0x0B .... the disclosure (grab popcorn)
      0x0C .... takeaways
      0x0D .... greetz

------------------------------------------------------------------------

[0x01] WHAT IS THIS

this is the story of how i found a five-link exploit chain in
nethsecurity -- an enterprise firewall/router distro -- that goes
from the public internet to persistent root on the box and its HA
partner. no user interaction. no phishing. no exotic gadgets. just a
default install, sitting on the internet, the way the vendor ships it.

five bugs. five CWEs. three criticals and two highs. every single one
independently reportable. together they spell "i own your entire
perimeter."

the password that starts it all? it's in their public github repo. i
cracked it in three lines of python. it took longer to open the
terminal than to pop the hash.

i am not making this up. stick around.

------------------------------------------------------------------------

[0x02] THE TARGET

nethsecurity is an open-source firewall built on openwrt, made by an
italian company called nethesis. they sell it as a UTM -- unified
threat management -- for businesses. it does firewalling, VPN
termination, IDS/IPS via snort, the works.

architecturally:

  - a Go API server (ns-api-server) handles auth via JWT
  - nginx sits in front as a reverse proxy
  - python API handlers (python3-nethsec) do the actual work
  - everything talks to openwrt's UCI config system underneath

the important thing to understand is WHERE this device sits. it's not
a webapp somewhere in a datacenter. it's the FIREWALL. it's the thing
between the internet and everything the org runs internally. it's the
device that every other device trusts implicitly because its entire
job description is "be trustworthy."

remember that. it matters later.

------------------------------------------------------------------------

[0x03] THE CHAIN (FOR THE IMPATIENT)

    INTERNET
        |
        | POST /api/login
        | {"username":"root","password":"Nethesis,1234"}
        |
        | yeah. that's the default password. on every box.
        | it's a hardcoded sha512 hash in their github repo.
        |
        v
    AUTHENTICATED
        |
        | every session is admin. the middleware hardcodes it.
        | there is no authorization layer. there is no RBAC.
        | if you have a JWT, you are god.
        |
        v
    PLANT THE PAYLOAD
        |
        | create a VPN user with shell metacharacters in the
        | username. nothing happens yet. it just sits there
        | in the config, looking innocent.
        |
        v
    ... TIME PASSES ...
        |
        | a completely different endpoint reads that username
        | back and drops it into a shell command with shell=True.
        | the username detonates. root RCE.
        |
        v
    ROOT ON THE FIREWALL
        |
        | the HA sync handler has the same injection.
        | compromise propagates to the backup firewall
        | through the trust relationship.
        |
        v
    ROOT ON BOTH FIREWALLS. PERSISTENT. INVISIBLE. DONE.

five links. five bugs. five things that each independently should not
exist in a security product. all of them do.

now let me walk you through each one, because the details are where
it gets fun.

------------------------------------------------------------------------

[0x04] FINDING 1: THE PASSWORD IS ON GITHUB

CWE-798 -- Use of Hard-coded Credentials
severity: CRITICAL (obviously)

every nethsecurity box gets its root password from a script that runs
on first boot:

    files/etc/uci-defaults/90-nethsec-root-password

this script checks if root has no password. if so, it writes a
hardcoded sha512 hash into /etc/shadow.

the hash is static. the salt is static. it's the same on every
installation. it's in a public github repository. it has been sitting
there, in the open, this entire time.

cracking it:

    import crypt
    stored = "$6$EtySwJxJPxJiWXnw$RfgZOdGa7gBQrLagSGUD..."
    assert crypt.crypt("Nethesis,1234", stored) == stored

the password is Nethesis,1234.

on. every. box.

"but there's a setup wizard!" i hear you cry. yes there is. it tracks
a boolean called password_changed in UCI config. the UI reads it and
shows a helpful prompt suggesting you maybe perhaps consider changing
your password at your earliest convenience.

the API server enforces exactly nothing. skip the wizard, ignore the
prompt, close the tab -- your box will happily accept Nethesis,1234
until the heat death of the universe or until someone manually
changes it, whichever comes first.

and before anyone says "well that's just how openwrt works" -- no.
openwrt ships with an EMPTY root password and NO wan-facing management
ports. nethesis's image build ADDS the static password AND the WAN
exposure. they went out of their way to make this worse than the
defaults they inherited.

------------------------------------------------------------------------

[0x05] FINDING 2: THE FRONT DOOR IS OPEN

CWE-1188 -- Initialization with an Insecure Default
severity: CRITICAL

the default firewall config. i need you to read this slowly:

    config rule 'ns_allow_https'
        option name 'Allow-HTTPS-from-WAN'
        option src 'wan'
        option dest_port '443'
        option target 'ACCEPT'

    config rule 'ns_allow_ui'
        option name 'Allow-UI-from-WAN'
        option src 'wan'
        option dest_port '9090'
        option target 'ACCEPT'

both ports serve the full management API. including /api/login. which
accepts the password from finding 1.

so to recap: every default nethsecurity installation has a known
static password AND the management interface is reachable from the
public internet on TWO ports. by design. as shipped.

the vendor's position is that "the user must follow the documentation
to deploy a secure machine."

the fortinet incident response team just felt a chill and they don't
know why.

------------------------------------------------------------------------

[0x06] FINDING 3: EVERYBODY IS ADMIN

CWE-285 -- Improper Authorization
severity: HIGH

the JWT middleware. look at this. look at it:

    IdentityHandler: func(c *gin.Context) interface{} {
        claims := jwt.ExtractClaims(c)
        user := &models.UserAuthorizations{
            Username: claims[identityKey].(string),
            Role:     "admin",    // <-- lol
            Actions:  nil,
        }
        return user
    },

every. single. session. is. admin.

there's no per-endpoint authorization. the Authorizator callback
checks if the token exists in the token store. that's it. that's the
whole authorization model. "are you logged in? great, you can do
literally anything."

this is the link that makes the command injection (next section)
reachable from the default credentials. without this, you'd need an
actual admin session. with this, any session IS an admin session,
because the concept of "not admin" doesn't exist at the API layer.

they built a JWT auth system and then gave everyone the same role.
it's like installing a door with a lock and then writing the
combination on the door.

------------------------------------------------------------------------

[0x07] FINDING 4: THE PRETTY ONE

CWE-78 -- OS Command Injection
severity: CRITICAL

this is my favorite one. this is the one i'm going to get a tattoo
of. (i'm not going to get a tattoo of it.)

it's a second-order / stored command injection, and the elegance is
in the time-and-space gap between planting and detonation.

STEP 1: PLANT

call ns.users add-local-user through the API. create a VPN user.
put shell metacharacters in the username. the python3-nethsec library
stores it in UCI config. nothing happens. no error. no alarm. it just
sits there in the config like a sleeper agent.

STEP 2: WAIT

go get coffee. read a book. contemplate the fragility of network
perimeter security. whatever you want.

STEP 3: DETONATE

a COMPLETELY DIFFERENT endpoint -- ns.ovpnrw list-users -- reads
that stored username back. it passes it to get_cert_expiration(),
which builds an openssl command to check certificate expiry dates.
using shell=True. with the username interpolated directly into the
command string.

the stored username detonates. arbitrary command execution. as root.

the person who triggers the detonation might be a different admin.
they might not know the payload exists. they're just listing VPN
users -- something the UI does automatically -- and boom. root shell.

and here's the root cause that makes it a SYSTEMIC issue rather than
a one-off bug: python3-nethsec HAS a sanitization function. they
WROTE it. it WORKS. they just don't APPLY it consistently. some code
paths sanitize usernames before storing them. some don't. the handler
that reads them back and shells them out definitely doesn't check.

they built the fix and deployed it to some of the codebase.
the rest of the codebase is left holding a live grenade with the
pin pulled.

the vendor fixed this one. PR #1841. the commit messages read
"Assisted-by: Claude Code" which is a detail i'll come back to in
the disclosure section because it's genuinely the funniest thing
that happened during this engagement.

CVE pending via MITRE.

------------------------------------------------------------------------

[0x08] FINDING 5: REDUNDANCY AS A WEAPON

CWE-78 -- OS Command Injection (again)
severity: HIGH

the HA synchronization handler, ns.ha, has the same injection
pattern. user-controlled data reaches a shell context in the sync
operation.

what this means: if you compromise the primary firewall, the HA
mechanism -- the thing that's supposed to make the deployment MORE
robust -- carries your payload to the backup. the trust relationship
between the HA pair is the lateral movement vector.

so:
  - "reboot the firewall" doesn't help. you're on both.
  - "fail over to the backup" doesn't help. you're on both.
  - "we have redundancy" is the problem, not the solution.

the device that exists specifically to survive failure is the reason
the failure propagates. that's a special kind of irony that only
network security engineering can deliver.

------------------------------------------------------------------------

[0x09] WHAT ROOT ON A FIREWALL ACTUALLY MEANS

this section is for the people who see "root RCE" and think "okay,
one more pwned box, whatever." this isn't one more pwned box. this is
THE box. the implications are different because of WHERE it sits.

TRAFFIC INTERCEPTION:
    every packet in or out of the org flows through this device. root
    means tcpdump at will. mirror traffic to yourself. MitM anything
    that isn't end-to-end encrypted. and a shocking amount of internal
    traffic isn't -- LDAP binds, SMB, internal APIs, database
    connections. it's all on the wire and you're sitting on the tap.

DNS POISONING:
    most orgs point their internal clients at the firewall for DNS.
    you control the answers now. resolve the company's SSO portal to
    your own box. harvest credentials at scale. the users see a valid
    hostname. their machines see a valid IP. nothing looks wrong
    because the thing that's supposed to be trustworthy is lying.

VPN OWNERSHIP:
    nethsecurity terminates openvpn, ipsec, and wireguard tunnels.
    root on the box means the private keys are yours. decrypt captured
    tunnel traffic. impersonate the VPN endpoint. or just mint yourself
    a legitimate VPN account and walk into the internal network the
    same way a remote employee does. no exploits needed. you're just
    On The Network now.

PERSISTENCE:
    firewalls are "install and forget" devices. nobody puts EDR on
    their firewall. nobody reviews the logs (and you control the logs
    anyway). an implant here sits for months. years, maybe. this is
    the quietest, most durable foothold on the network and it's the
    last place anyone looks.

PIVOTING:
    internal systems trust the firewall. its IP is on allowlists. its
    certs are trusted. it has outbound access to everything because
    it's the default gateway. pivoting from here isn't lateral movement
    -- it's a straight walk through the front door of every internal
    service, because the firewall is SUPPOSED to talk to them.

you didn't just get a shell. you got the keys to the building, the
security cameras, the alarm system, and the master key to every room
inside. and nobody's going to check the security system for
compromise because the security system is the last thing anyone
suspects.

------------------------------------------------------------------------

[0x0A] THE THINGS THAT DIDN'T WORK

good research includes the negatives. here's what i tried and what
came back clean:

PATH NORMALIZATION BYPASS:
    nginx uses exact-match location blocks for the three pre-auth
    endpoints (/api/login, /api/logout, /api/2fa/otp-verify) and a
    prefix match for everything authenticated. i tried every path
    confusion trick i know between nginx and gin. nothing. the
    location config is correct.

JWT SECRET PREDICTION:
    the JWT signing secret is generated at first boot from
    uuidgen | sha256sum. stored in /var/run (tmpfs, regenerated on
    reboot). 122 bits of entropy from uuid4 into sha256. not
    predictable. not brute-forceable. door closed.

JWT ALGORITHM CONFUSION:
    ValidateAuth explicitly checks for HMAC signing method. no
    alg:none bypass. no RSA/HMAC confusion. they got this right.

FILE UPLOAD/DOWNLOAD TRAVERSAL:
    safeFilePath() correctly prevents directory traversal. uploads
    use server-generated UUID filenames. hardened.

LUCI PARALLEL AUTH:
    luci-mod-rpc is installed in the image, which got me excited
    for about ten minutes. then i found luci_enable is '0' by
    default. luci isn't served. dead end.

FAST-PACKET REASSEMBLY:
    wait, wrong engagement. that's the maritime stuff.

i list these because "i looked and it wasn't there" is data. it tells
the vendor exactly what's been tested. it tells other researchers what
ground has been covered. and it tells the reader that the findings
above aren't the result of pattern-matching and praying -- they're
what survived after everything else was eliminated.

------------------------------------------------------------------------

[0x0B] THE DISCLOSURE (GRAB POPCORN)

reported all nine findings to security@nethesis.it per their
published security policy. full report. CWE classifications.
reproduction guidance. remediation recommendations. the works.

their response, paraphrased:

    "thanks for reaching out. it took a lot of time to filter
    out the AI slope. nethsecurity has open defaults like openwrt.
    the user must follow documentation to deploy securely. the
    wizard guides users. the only relevant part is the VPN RCE,
    and it requires root credentials, and if you have root
    credentials you already own the machine. we fixed it. please
    refrain from opening security issues that have not been
    verified by a human."

let's unpack that.

"it requires root credentials" -- the root credentials are
Nethesis,1234 and they're in your public github repo. that's like
saying your front door is secure because it has a lock, while the
key is taped to the doorframe with a label that says KEY.

"the user must follow documentation" -- security products do not get
to externalize their security posture onto documentation compliance.
that's the exact reasoning that led to the fortinet, ivanti, and
palo alto mass exploitation events. "the user should have read the
manual" has never stopped an APT and it never will.

"the wizard guides users" -- the wizard's password_changed flag is a
UCI boolean that the UI reads. the API server enforces nothing. i can
prove this in the source code. i DID prove this in the source code.

"verified by a human" -- the placeholder fields (my name/email) in
the attached report template were unfilled. that was my mistake and
it's a fair criticism. but the findings were manually verified
against the source, every one of them. the irony of being told to
verify things with a human will become apparent in a moment.

because here's the thing.

the fix they merged. PR #1841. three commits. every single commit
message ends with:

    Assisted-by: Claude Code:claude-opus-5

they told me to stop submitting AI-assisted security reports, and
then they used AI to write the patch.

i don't have a joke here. reality wrote a better one than i could.

oh, and they merged the fix as a PUBLIC pull request. no coordinated
disclosure window. no "update your systems before we publish the
vulnerable code path." just a public diff showing exactly which
function was vulnerable and how to exploit it, visible to anyone
watching the repo.

i handled the disclosure more carefully than they handled the fix.

------------------------------------------------------------------------

[0x0C] TAKEAWAYS

FOR DEFENDERS RUNNING NETHSECURITY:

    1. change the root password. right now. i'll wait.

    2. go look at your firewall rules. if ports 443 and 9090 are
       open from WAN, close them. if you need remote management,
       put it behind a VPN.

    3. update to a version containing PR #1841, commit bf981cb.
       that's the command injection fix.

    4. if you have HA configured, assume both nodes need the same
       remediation.

FOR BUILDERS:

    if you ship a default password, generate it uniquely per
    installation. a static hash in a public repo is a CVE shaped
    hole in your product. you WILL end up on this list.

    defense in depth means every layer works independently. this
    chain had five links because five layers each failed on their
    own. if ANY single one had held -- random password, no WAN
    exposure, real RBAC, consistent sanitization, untrusted HA
    boundary -- the chain breaks. all five had to fail. all five
    did.

    the sanitizer existed. it worked. it just wasn't applied
    everywhere. inconsistent application of a security control
    is almost worse than not having one, because it creates a
    false sense of coverage. you think you're protected because
    you can see the lock. you don't realize half the doors don't
    have one.

FOR RESEARCHERS:

    the pre-auth that makes a chain lethal doesn't have to be
    clever. this wasn't a heap spray or a type confusion or a
    race condition. it was a password. in a text file. on github.
    sometimes the boring answer is the right one.

    document what you COULDN'T confirm. the verified negatives
    section is what separates you from a script kiddie. it shows
    the vendor you tested things. it shows other researchers what
    ground is covered. it shows the reader that your positives
    survived a process of elimination rather than a process of
    wishful thinking.

    and for the love of god, fill in the placeholders in your
    report before you send it. learn from my mistakes. i beg you.

------------------------------------------------------------------------

[0x0D] GREETZ

to the python3-nethsec sanitization function: you worked perfectly.
you were just in the wrong place at the wrong time. i'm sorry it
ended this way.

to the IdentityHandler: Role: "admin". man. that's bold. respect for
the commitment.

to 90-nethsec-root-password: six lines of shell script. the most
consequential six lines in the entire codebase. you did more damage
than any of the code you were supposed to protect.

to the vendor: you fixed the bug and i respect that. the response
was frustrating but the patch shipped same-day and that matters more
than tone. i still think you should fix the password. i'll be
watching the repo.

to claude code, apparently: good work on that patch, buddy.

------------------------------------------------------------------------

    CVE pending via MITRE for finding 4 (command injection).
    fix: https://github.com/NethServer/nethsecurity/pull/1841
    

------------------------------------------------------------------------

    EOF
