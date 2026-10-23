# User Behaviour Anomaly Detection Without AI

In today’s threat landscape, cyberattacks have accelerated dramatically in both speed and sophistication. Adversaries use AI-assisted offensive tools to rapidly identify attack surfaces, chain living-off-the-land techniques, and weaponize zero-day vulnerabilities at scale. When attacks can spread across enterprise networks within minutes, traditional signature-based detection and static indicators of compromise (IoCs) struggle to keep pace.

## Shift the Focus: Detect What Is Unusual (Uncover the “Unknown Unknowns”)

Rather than attempting to identify every new attack technique, organizations can focus on detecting deviations from normal user and system behaviour.

Most users and systems operate within predictable patterns:

- Employees use the same applications daily.
- Servers communicate with a consistent set of destinations.
- Administrators execute a limited set of commands.
- Business processes follow regular operational routines.
When a user or system suddenly performs an activity that has never, or only rarely, been observed, it may indicate compromise, misuse, lateral movement, malware execution, or insider activity.

## No AI or Commercial Product Required

Establish a simple, rolling history of each user’s or computer’s normal activity, such as processes launched, commands executed, and internal IP addresses contacted. Each new event can then be evaluated against its historical frequency. If an activity has not occurred within a 35-day (five-week) baseline window, treat it as an anomaly that warrants prompt investigation.

This approach can readily highlight activities such as:

- A user downloading and running an unfamiliar tool from a user-writable location.
- A user accessing an internal application they have never used before.
- A user opening a command prompt and running a command copied from the internet.
- A server receiving a connection from a previously unseen IP address.
- A user or local process initiating access to a local network resource it has never contacted before.
## How It Works

### 1. Collect Relevant Events with Sysmon and Group Policy

On Windows, Sysmon records detailed activity with user context, including:

`Event ID 1`: Process creation, including the full command line and associated user

`Event ID 3`: Network connections, including source and destination details

Use Group Policy to include command-line details in process-creation events:

```text
Computer Configuration
 └─ Administrative Templates
     └─ System
         └─ Audit Process Creation
             └─ Include command line in process creation events
```

### 2. Centralize the Logs

Forward endpoint events to a Windows Server using Windows Event Forwarding, then send them to a Linux syslog server, for example, through a Fluent Bit agent.

### 3. Build a Daily Activity Record for Each User or Computer

Parse each syslog event into a simple `user:event` or `computer:``direction``:IP` entry, then write the entries to one file per day. Use `src` for a source address and `dst` for a destination address. For example:

```text
event-20261020.dat

event-20261021.dat

event-20261022.dat
elon:cmd.exe
elon:dst:192.168.2.10
elon:outlook.exe
jensen:excel.exe
eddie:excel.exe
jensen:mstsc.exe
jensen:net use
svrcrm:dst:192.168.201.81
svrcrm:src:192.168.201.81

event-20261023.dat
elon:ping.exe
jensen:dst:192.168.2.102
pc1023:mstsc.exe
eddie:dst:192.168.2.32
svrcrm:src:192.168.201.33
```

### 4. Compare Each New Event Against Historical Activity

For each new event, count how many of the previous N days contain the same behaviour. If it has never appeared, classify it as new. If it appears on only one or two days, classify it as rare.

To calculate a simple rarity score, count the number of matching records within the baseline window:

```text
find event-*.dat -maxdepth 1 -mtime -35 | xargs -P 0 -n 1 grep -i -H "jensen:net group" | wc -l



find: searches for files.
-maxdepth 1: does not search subdirectories.
-mtime -35: selects files modified less than 35×24 hours ago.

xargs: runs grep against the filenames.
-P 0: runs as many processes concurrently as possible.
-n 1: passes one filename to each grep process.

grep -i: performs a case-insensitive search.
-H: prints each matching filename.
wc -l counts the matching lines.
```

Plain-text files and standard tools such as `find` and `grep` are sufficient. This approach is simple and quick to deploy. Because entries are stored in daily files, the file system effectively serves as a date index, eliminating the need for a database or complex indexing. The files are also easy to manage and archive.

You can further develop the reporting mechanism, reduce noise, refine detection indicators, and extend the approach to Linux with assistance from your preferred generative AI tool—for example, when developing filters, parsing logic, or platform-specific configurations. Generative AI remains an optional implementation aid; the underlying detection method itself does not require AI.

## Conclusion

As AI-powered attacks increase the speed and scale of cyber threats, organizations should not rely solely on traditional signature-based detection. A practical alternative is to build behavioural baselines from endpoint telemetry and identify deviations from established routines.

By combining Sysmon, Windows Event Forwarding, syslog, and a simple historical comparison method, organizations can implement effective user behaviour anomaly detection without machine learning or AI. Sometimes, the most powerful detection strategy is simply knowing what “normal” looks like and immediately recognizing when something does not belong.

## Key Benefits

- Detects unknown threats and zero-day attacks.
- Operates independently of malware signatures, threat intelligence feeds, and commercial products.
- Is simple to deploy, operate, and understand.
- Works across users, workstations, and servers.
- Adapts continuously as behaviour evolves.
- Requires no commercial product, database, index, model, or AI—only a lightweight Linux server.
## Appendix

Key Configuration Settings

### Fluent Bit configuration (fluent-bit.conf)

```text
[INPUT]
    Name                 winevtlog
    Channels             Security,Microsoft-Windows-Sysmon/Operational
    Render_Event_As_XML  True
    String_Inserts       True
    Read_Existing_Events True
    DB                   winevtlog.sqlite
    Interval_Sec         1
[OUTPUT]
    Name                tcp
    Match               *
    Host                192.168.1.1
    Port                514
    Format      json_lines
```

### Rsyslog configuration (rsyslog.conf)

```text
module(load="imtcp")
module(load="imudp")
input(type="imtcp" port="514" ruleset="remotelog")
input(type="imudp" port="514" ruleset="remotelog")
$MaxMessageSize 64k
ruleset(name="remotelog") {
  $template CustomTemplate, "/var/log/rsyslog-%$YEAR%%$MONTH%%$DAY%.log"
  *.* ?CustomTemplate;RSYSLOG_TraditionalFileFormat
  $ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
}
```
<br /><br /><br /><br /><br /><br />
#CyberSecurity #InfoSec #AnomalyDetection #ThreatHunting #BlueTeam #UserBehaviorAnalytics #UEBA #CyberSecurity
#Sysmon #WindowsSecurity #Syslog #FluentBit #Bash #Linux #Log #SIEM
#NoAI #ZeroDay #OpenSourceSecurity #DFIR #IncidentResponse #DoItYourself
