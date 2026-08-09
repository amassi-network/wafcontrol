[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# OWASP WAFControl

The **OWASP WAFControl** project provides a web-based dashboard and management interface for ModSecurity and the OWASP Core Rule Set (CRS).  
It simplifies installation, configuration, and operation of CRS and ModSecurity, enabling administrators and security engineers to deploy, monitor, and manage WAF rules more effectively.

WAFControl integrates rule management, attack monitoring, and configuration control into one centralized platform, making it easier to maintain strong web application security with reduced complexity.

![Attack](https://raw.githubusercontent.com/OWASP/www-project-wafcontrol/refs/heads/main/assets/images/crs.png)

## How To Use

The OWASP WAFControl installer automatically sets up **ModSecurity**, the **OWASP CRS**, and all required dependencies.  
It is recommended to install WAFControl on a clean server where these components are not yet installed.  

- If **Nginx** or **Apache** is not installed, the installer can install and configure them as well.  
- WAFControl uses **PostgreSQL** as its database backend, which will also be installed and configured automatically.  
- After installation, the web-based dashboard will be available to manage rules, monitor attacks, and configure CRS/ModSecurity.  

### Quick Installation

Run the following commands on your server:

```bash
curl -fsSL https://wafcontrol.org/download/install.sh -o install.sh
```

```bash
chmod +x install.sh
```

```bash
sudo ./install.sh
```

### Database migrations

Migration source files are versioned in the repository. On a new installation,
apply them with:

```bash
python manage.py migrate
```

Older WAFControl installations created application tables through Django's
`--run-syncdb` fallback and do not have a migration history for `wafinstaller`.
Back up PostgreSQL, then adopt the initial migration and create newer tables
with:

```bash
python manage.py migrate --fake-initial
python manage.py showmigrations wafinstaller
```

Do not use `--fake` for later migrations. Review the migration plan and keep a
database backup before every upgrade.

### Managed exclusions and address lists

The **Managed Policies** page stores exclusions and named address lists in the
database, renders dedicated files before and after CRS, shows a deployment diff,
and requires explicit approval before a rule exclusion becomes active.

The semantics are deliberately distinct:

- **Trusted** remains inspected by the WAF and is reserved for future
  Fail2ban/CrowdSec allow-list export;
- **WAF bypass** disables inspection and produces a prominent warning;
- **Block** returns HTTP 403;
- **Observe** logs the matching source without blocking it.

On an Nginx installation, wire the managed files into ModSecurity once:

~~~bash
sudo WAFCONTROL_SERVICE_USER=wafcontrol ./scripts/install_managed_policy.sh /etc/nginx/modsec/wafcontrol
~~~

The installer places the before-file immediately before the active CRS rules
include and the after-file immediately after it. It runs nginx -t, reloads
Nginx, and restores the previous main.conf if validation or reload fails.

Set the same directory in the application environment:

~~~dotenv
WAFCONTROL_POLICY_DIR=/etc/nginx/modsec/wafcontrol
~~~

The application service account needs write access only to this managed
directory. It does not need write access to OWASP CRS source files.

### Event triage and frozen revisions

The attack view stores a reviewer classification and notes without altering the
original WAF event. Parsed events retain the HTTP method, ModSecurity
transaction ID, matched variable and CRS tags so a draft exclusion can default
to the narrowest known target.

Managed policy deployment follows a freeze, approve, deploy workflow. Frozen
contents and their summary are checksum-verified and immutable. Set
`WAFCONTROL_REQUIRE_SEPARATE_APPROVER=True` to prevent the author from
approving their own exclusion or revision.

Celery checks expiry every hour. When an active object expires, WAFControl
regenerates the policy, validates the live Nginx/ModSecurity configuration and
reloads it. A failed validation restores the database state. The dashboard also
shows objects and owners due to expire within seven days.

### Static asset collection

Dashboard sources live in `frontend/static`; collected files are written to
`staticfiles`. These directories must remain distinct. Nginx should serve
`/static/` from `/opt/WafControl/staticfiles/`. It is safe to run
`python manage.py collectstatic --clear --noinput` only with this layout.




## WAFControl Features

- **Attack Control**:  
  - Real-time logging of attacks with detailed insights. 
  - Dedicated **Critical WAF Attacks** section highlighting threats like SQL Injection (SQLi), Remote Code Execution (RCE), and Local File Inclusion (LFI).  
  - **Top Attacker** dashboard to identify frequent attackers based on attack frequency.

- **Rule Management**:  
  - Upload and edit CRS rules.  
  - Rule viewer categorized by rule IDs.  
  - Custom rule creation and management.  

- **CRS & ModSecurity Control**:  
- 
  - Version switcher to fetch and deploy different CRS versions from GitHub.  
  - GUI-based configuration for key ModSecurity and CRS settings, such as:  

## WAFControl Resources
- [OWASP WAFControl Project Site](https://wafcontrol.org/)
- [OWASP WAFControl Project Page](https://owasp.org/www-project-wafcontrol/)  

## Documentation
- [OWASP WAFControl Docs](https://wafcontrol.org/docs)


## Contributing to WAFControl

We welcome contributions from developers, researchers, and users.  
You can help us by:  
- Reporting bugs, usability issues, or false positives.  
- Suggesting new features and improvements.  
- Contributing code, documentation, or testing.  

👉 [Create an issue on GitHub](https://github.com/wafcontrol/wafcontrol/issues) to report bugs or request features.  
👉 [Join the OWASP Slack](https://owasp.org/slack/invite) and participate in the **#wafcontrol** channel to discuss and collaborate.  


## License

Copyright (c) 2025 OWASP WAFControl Project.  
All rights reserved.  

The OWASP WAFControl project is distributed under the Apache Software License (ASL) version 2.0.  
See the enclosed [LICENSE](./LICENSE) file for full details.
