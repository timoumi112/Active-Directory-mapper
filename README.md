# AD Mapper

A straightforward Python tool that connects to an Active Directory domain and draws you a map — all the OUs, Domain Controllers, computers, and user accounts, neatly laid out in the console and saved as a JSON file.

## What it does

Run the script, answer a few prompts, and you get a tree like this:

```
=================================================================
           ACTIVE DIRECTORY DIRECTORY MAP
=================================================================
└── 🌐 corp.local
    ├── 📁 IT
    │   ├── 📁 Servers
    │   │   └── 🖥️ 👑 DC01 — Windows Server 2022 Standard
    │   └── 📁 Workstations
    │       ├── 💻 LAPTOP-HR01 — Windows 11 Pro
    │       └── 💻 DESKTOP-IT02 — Windows 10 Enterprise
    ├── 📁 HR
    │   ├── 👤 Jane Doe (jdoe)
    │   └── 👤 Mark Green (mgreen)
    └── 📦 Users
        └── 👤 Administrator (Administrator)
=================================================================
```

It also saves a full `ad_network_map.json` you can use for documentation, scripting, or audits.

---

## Requirements

- Python 3.8+
- A domain account with **read access** to the directory (no admin rights needed)
- Network access to your Domain Controller on port 389, or 636 if you're using SSL

---

## Setup

**1. Install the dependencies**

```bash
pip install ldap3 python-dotenv
```

**2. Run the script**

```bash
python ad_mapper.py
```

That's it. On first run, you'll be asked for:

| Prompt | Example |
|--------|---------|
| AD Server address | `dc01.corp.local` or `192.168.1.10` |
| Base DN | `DC=corp,DC=local` |
| Bind username | `reader@corp.local` |
| Password | *(typed securely — nothing echoed to the terminal)* |
| Use SSL? | `y` for LDAPS on port 636, `N` for plain LDAP on 389 |

---

## Skip the prompts with a .env file

If you're running this regularly and don't want to type credentials every time, create a `.env` file in the same directory:

```ini
AD_SERVER=dc01.corp.local
AD_BASE_DN=DC=corp,DC=local
AD_BIND_DN=reader@corp.local
AD_PASSWORD=YourPasswordHere
AD_USE_SSL=False
```

Any values found in `.env` are loaded automatically at startup and the corresponding prompts are skipped.


You can also override the output filename (default is `ad_network_map.json`):

```ini
AD_EXPORT_FILE=my_domain_map.json
```

---

## Output

**Console** — live tree with icons, OS details, and sAMAccountNames inline, printed as the script runs.

**`ad_network_map.json`** — the full hierarchy as structured JSON, ready for scripting, reporting, or feeding into other tools. Each node looks like this:

```json
{
    "name": "IT",
    "dn": "OU=IT,DC=corp,DC=local",
    "type": "ou",
    "rdn_type": "OU",
    "attributes": {},
    "children": [...]
}
```

---

## Icon legend

| Icon | Meaning |
|------|---------|
| 🌐 | Domain root |
| 📁 | Organizational Unit (OU) |
| 📦 | Default container (e.g. CN=Users, CN=Computers) |
| 🖥️ 👑 | Domain Controller |
| 💻 | Computer / workstation |
| 👤 | User account |

---

## Files

| File | Description |
|------|-------------|
| `ad_mapper.py` | The script |
| `.env` | Your local credentials — **not committed to git** |
| `ad_network_map.json` | Generated output, created when you run the script |
