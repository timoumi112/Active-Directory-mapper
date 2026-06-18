#!/usr/bin/env python3

import os
import sys
import json
import logging
import getpass
from typing import Dict, Any, List, Optional

import ldap3
from ldap3.core.exceptions import LDAPException, LDAPBindError

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = lambda: None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("ADMapper")


def find_first_unescaped_comma(dn: str) -> int:
    escaped = False
    for i, char in enumerate(dn):
        if char == "\\":
            escaped = not escaped
        elif char == "," and not escaped:
            return i
        else:
            escaped = False
    return -1


def get_parent_dn(dn: str) -> Optional[str]:
    idx = find_first_unescaped_comma(dn)
    return dn[idx + 1:].strip() if idx != -1 else None


def get_rdn(dn: str) -> str:
    idx = find_first_unescaped_comma(dn)
    return dn[:idx].strip() if idx != -1 else dn


def parse_rdn_details(rdn: str) -> tuple:
    parts = rdn.split("=", 1)
    return (parts[0].strip(), parts[1].strip()) if len(parts) == 2 else ("CN", rdn)


def unescape_value(val: str) -> str:
    result = []
    escaped = False
    for char in val:
        if char == "\\" and not escaped:
            escaped = True
        else:
            result.append(char)
            escaped = False
    return "".join(result)


class ADNode:
    def __init__(
        self,
        dn: str,
        name: str,
        rdn_type: str,
        node_type: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.dn = dn
        self.name = name
        self.rdn_type = rdn_type
        self.node_type = node_type
        self.attributes = attributes or {}
        self.children: Dict[str, "ADNode"] = {}

    def to_dict(self) -> Dict[str, Any]:
        sorted_children = sorted(
            self.children.values(),
            key=lambda x: (x.node_type not in ("domain", "ou", "container"), x.name.lower()),
        )
        return {
            "name": self.name,
            "dn": self.dn,
            "type": self.node_type,
            "rdn_type": self.rdn_type,
            "attributes": self.attributes,
            "children": [child.to_dict() for child in sorted_children],
        }


class ADMapper:
    def __init__(self) -> None:
        self.server_address = os.getenv("AD_SERVER", "")
        self.base_dn = os.getenv("AD_BASE_DN", "")
        self.bind_dn = os.getenv("AD_BIND_DN", "")
        self.password = os.getenv("AD_PASSWORD", "")
        self.use_ssl = os.getenv("AD_USE_SSL", "False").lower() in ("true", "1", "yes")

        port_env = os.getenv("AD_PORT")
        self.port = int(port_env) if port_env and port_env.isdigit() else (636 if self.use_ssl else 389)
        self.export_file = os.getenv("AD_EXPORT_FILE", "ad_network_map.json")
        self.connection: Optional[ldap3.Connection] = None

    def prompt_for_missing_config(self) -> None:
        needs_prompt = not all([self.server_address, self.base_dn, self.bind_dn, self.password])

        if needs_prompt:
            print("\n=== Active Directory Connection Setup ===")
            print("A few details are needed to connect. Fill them in below.")
            print("(You can skip this step next time by adding these to a .env file — see the README.)\n")

        if not self.server_address:
            self.server_address = input("AD Server address  (e.g. dc01.corp.local): ").strip()
        if not self.base_dn:
            self.base_dn = input("Base DN            (e.g. DC=corp,DC=local): ").strip()
        if not self.bind_dn:
            self.bind_dn = input("Bind username      (e.g. reader@corp.local): ").strip()
        if not self.password:
            self.password = getpass.getpass("Password: ")

        if needs_prompt and not os.getenv("AD_USE_SSL"):
            choice = input("\nUse SSL / LDAPS? (y/N): ").strip().lower()
            self.use_ssl = choice in ("y", "yes")
            self.port = 636 if self.use_ssl else 389

        still_missing = [
            name
            for name, val in {
                "AD_SERVER": self.server_address,
                "AD_BASE_DN": self.base_dn,
                "AD_BIND_DN": self.bind_dn,
                "AD_PASSWORD": self.password,
            }.items()
            if not val
        ]

        if still_missing:
            logger.error("The following required fields are still empty: %s", ", ".join(still_missing))
            sys.exit(1)

    def connect(self) -> None:
        logger.info("Connecting to %s:%d (SSL: %s)...", self.server_address, self.port, self.use_ssl)
        try:
            server = ldap3.Server(
                self.server_address,
                port=self.port,
                use_ssl=self.use_ssl,
                get_info=ldap3.ALL,
            )
            self.connection = ldap3.Connection(
                server,
                user=self.bind_dn,
                password=self.password,
                raise_exceptions=True,
                client_strategy=ldap3.SYNC,
            )
            logger.info("Binding to Active Directory...")
            self.connection.bind()
            logger.info("Connected as: %s", self.bind_dn)
        except LDAPBindError as e:
            logger.error("Authentication failed — double-check your username and password. Details: %s", e)
            sys.exit(1)
        except LDAPException as e:
            logger.error("Could not connect to the LDAP server. Details: %s", e)
            sys.exit(1)

    def query_ldap(self, search_filter: str, attributes: List[str]) -> List[Dict[str, Any]]:
        if not self.connection:
            raise RuntimeError("No active LDAP connection.")

        results = []
        cookie = None

        try:
            while True:
                self.connection.search(
                    search_base=self.base_dn,
                    search_filter=search_filter,
                    search_scope=ldap3.SUBTREE,
                    attributes=attributes,
                    paged_size=100,
                    paged_cookie=cookie,
                )

                for entry in self.connection.entries:
                    data = {"dn": entry.entry_dn}
                    for attr in attributes:
                        val = getattr(entry, attr, None)
                        if val is not None:
                            raw = val.value
                            if isinstance(raw, list):
                                data[attr] = raw[0] if len(raw) == 1 else (None if not raw else raw)
                            else:
                                data[attr] = raw
                        else:
                            data[attr] = None
                    results.append(data)

                controls = self.connection.result.get("controls", {})
                paged_ctrl = controls.get("1.2.840.113556.1.4.319", {})
                cookie = paged_ctrl.get("value", {}).get("cookie") if paged_ctrl else None
                if not cookie:
                    break

            return results
        except LDAPException as e:
            logger.error("LDAP query failed (filter: %s): %s", search_filter, e)
            return []

    def build_network_map(self) -> ADNode:
        logger.info("Fetching Organizational Units...")
        ous = self.query_ldap("(objectClass=organizationalUnit)", ["cn", "ou"])

        logger.info("Fetching Domain Controllers...")
        dcs = self.query_ldap(
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            ["cn", "operatingSystem", "sAMAccountName"],
        )

        logger.info("Fetching computers and workstations...")
        computers = self.query_ldap(
            "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
            ["cn", "operatingSystem", "sAMAccountName"],
        )

        logger.info("Fetching user accounts...")
        users = self.query_ldap("(&(objectCategory=person)(objectClass=user))", ["cn", "sAMAccountName"])

        logger.info("Building directory tree...")

        dc_parts = [
            unescape_value(parse_rdn_details(part)[1])
            for part in self.base_dn.split(",")
            if part.strip().lower().startswith("dc=")
        ]
        domain_name = (
            ".".join(dc_parts)
            if dc_parts
            else unescape_value(parse_rdn_details(get_rdn(self.base_dn))[1])
        )

        root_node = ADNode(dn=self.base_dn, name=domain_name, rdn_type="DC", node_type="domain")
        registry: Dict[str, ADNode] = {self.base_dn.lower(): root_node}

        def register_node(
            dn: str,
            name: str,
            rdn_type: str,
            node_type: str,
            attributes: Optional[Dict[str, Any]] = None,
        ) -> ADNode:
            key = dn.lower()
            if key not in registry:
                registry[key] = ADNode(dn, name, rdn_type, node_type, attributes)
            else:
                node = registry[key]
                node.name = name
                node.rdn_type = rdn_type
                node.node_type = node_type
                if attributes:
                    node.attributes.update(attributes)
            return registry[key]

        for ou in ous:
            rdn_type, rdn_val = parse_rdn_details(get_rdn(ou["dn"]))
            register_node(ou["dn"], unescape_value(rdn_val), rdn_type, "ou")

        for dc in dcs:
            rdn_type, rdn_val = parse_rdn_details(get_rdn(dc["dn"]))
            register_node(
                dc["dn"],
                unescape_value(rdn_val),
                rdn_type,
                "dc",
                {"operatingSystem": dc.get("operatingSystem"), "sAMAccountName": dc.get("sAMAccountName")},
            )

        for comp in computers:
            rdn_type, rdn_val = parse_rdn_details(get_rdn(comp["dn"]))
            register_node(
                comp["dn"],
                unescape_value(rdn_val),
                rdn_type,
                "computer",
                {"operatingSystem": comp.get("operatingSystem"), "sAMAccountName": comp.get("sAMAccountName")},
            )

        for user in users:
            rdn_type, rdn_val = parse_rdn_details(get_rdn(user["dn"]))
            register_node(
                user["dn"],
                unescape_value(rdn_val),
                rdn_type,
                "user",
                {"sAMAccountName": user.get("sAMAccountName")},
            )

        for dn_key in list(registry.keys()):
            if dn_key == self.base_dn.lower():
                continue
            parent_dn = get_parent_dn(registry[dn_key].dn)
            while parent_dn and parent_dn.lower() != self.base_dn.lower():
                parent_key = parent_dn.lower()
                if parent_key not in registry:
                    p_rdn_type, p_rdn_val = parse_rdn_details(get_rdn(parent_dn))
                    p_node_type = (
                        "ou"
                        if p_rdn_type.upper() == "OU"
                        else "domain"
                        if p_rdn_type.upper() == "DC"
                        else "container"
                    )
                    register_node(parent_dn, unescape_value(p_rdn_val), p_rdn_type, p_node_type)
                parent_dn = get_parent_dn(parent_dn)

        for dn_key, node in registry.items():
            if dn_key == self.base_dn.lower():
                continue
            parent_dn = get_parent_dn(node.dn)
            if parent_dn:
                registry.get(parent_dn.lower(), root_node).children[dn_key] = node

        return root_node

    def print_tree(self, node: ADNode, prefix: str = "", is_last: bool = True) -> None:
        icons = {
            "domain": "🌐",
            "ou": "📁",
            "container": "📦",
            "dc": "🖥️ 👑",
            "computer": "💻",
            "user": "👤",
        }

        details = ""
        if node.node_type == "user":
            sam = node.attributes.get("sAMAccountName", "")
            details = f" ({sam})" if sam else ""
        elif node.node_type in ("computer", "dc"):
            os_info = node.attributes.get("operatingSystem", "")
            details = f" — {os_info}" if os_info else ""

        connector = "└── " if is_last else "├── "
        print(f"{prefix}{connector}{icons.get(node.node_type, '📄')} {node.name}{details}")

        next_prefix = prefix + ("    " if is_last else "│   ")
        children_list = sorted(
            node.children.values(),
            key=lambda x: (x.node_type not in ("domain", "ou", "container"), x.name.lower()),
        )

        for idx, child in enumerate(children_list):
            self.print_tree(child, next_prefix, is_last=(idx == len(children_list) - 1))

    def export_to_json(self, root_node: ADNode) -> None:
        try:
            logger.info("Exporting directory map to: %s", self.export_file)
            with open(self.export_file, "w", encoding="utf-8") as f:
                json.dump(root_node.to_dict(), f, indent=4)
            logger.info("Export complete.")
        except IOError as e:
            logger.error("Failed to write JSON export: %s", e)

    def disconnect(self) -> None:
        if self.connection:
            logger.info("Closing connection...")
            self.connection.unbind()

    def run(self) -> None:
        self.prompt_for_missing_config()
        self.connect()
        try:
            root_node = self.build_network_map()
            print("\n" + "=" * 65)
            print("           ACTIVE DIRECTORY DIRECTORY MAP")
            print("=" * 65)
            self.print_tree(root_node, is_last=True)
            print("=" * 65 + "\n")
            self.export_to_json(root_node)
        finally:
            self.disconnect()


if __name__ == "__main__":
    load_dotenv()
    ADMapper().run()
