#!/usr/bin/env python3
import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys


NFT_TABLE_FAMILY = "inet"
NFT_TABLE_NAME = "sqm_fw"
NFT_CHAIN_NAME = "sqm_classify"

IPT_TABLE = "mangle"
IPT_CHAIN = "SQM_CLASSIFY"
VALID_BACKENDS = ("nft", "iptables")


def find_command(name):
    candidates = [name, f"/usr/sbin/{name}", f"/usr/bin/{name}", f"/sbin/{name}", f"/bin/{name}"]
    for cand in candidates:
        if "/" in cand:
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
            continue
        found = shutil.which(cand)
        if found:
            return found
    return None


def run_cmd(cmd):
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "cmd": " ".join(shlex.quote(part) for part in cmd),
        "rc": proc.returncode,
        "stdout": (proc.stdout or "").strip(),
        "stderr": (proc.stderr or "").strip(),
    }


def run_checked(cmd, details, ok_rc=(0,)):
    result = run_cmd(cmd)
    details["commands"].append(result)
    return result["rc"] in ok_rc, result


def parse_mark(value):
    if value is None or value == "":
        raise ValueError("mark is required")

    if isinstance(value, int):
        mark_int = value
    elif isinstance(value, str):
        text = value.strip().lower()
        if text.startswith("0x"):
            mark_int = int(text, 16)
        else:
            mark_int = int(text, 10)
    else:
        raise ValueError(f"invalid mark type: {type(value).__name__}")

    if mark_int <= 0 or mark_int > 0xFFFFFFFF:
        raise ValueError("mark must be in range 1..0xffffffff")
    return mark_int


def parse_ports(value):
    if value in (None, "", "*", "any"):
        return []

    if isinstance(value, int):
        tokens = [str(value)]
    elif isinstance(value, str):
        tokens = [item.strip() for item in value.split(",") if item.strip()]
    elif isinstance(value, list):
        tokens = []
        for item in value:
            if isinstance(item, int):
                tokens.append(str(item))
            elif isinstance(item, str) and item.strip():
                tokens.append(item.strip())
            else:
                raise ValueError(f"invalid port item: {item!r}")
    else:
        raise ValueError(f"invalid ports type: {type(value).__name__}")

    parsed = []
    for token in tokens:
        if "-" in token:
            start_s, end_s = token.split("-", 1)
            start = int(start_s.strip(), 10)
            end = int(end_s.strip(), 10)
            if start < 1 or end < 1 or start > 65535 or end > 65535 or start > end:
                raise ValueError(f"invalid port range: {token}")
            parsed.append(f"{start}-{end}")
            continue

        port = int(token, 10)
        if port < 1 or port > 65535:
            raise ValueError(f"invalid port: {token}")
        parsed.append(str(port))
    return parsed


def normalize_rules(raw_rules, category_marks):
    if not isinstance(raw_rules, list):
        raise ValueError("rules must be a JSON array")
    if not isinstance(category_marks, dict):
        raise ValueError("category_marks must be a JSON object")

    normalized = []
    for idx, item in enumerate(raw_rules, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"rule #{idx} must be a JSON object")

        proto = str(item.get("proto", "all")).strip().lower()
        if proto in ("", "*", "any"):
            proto = "all"
        if proto not in ("all", "tcp", "udp"):
            raise ValueError(f"rule #{idx} invalid proto: {proto}")

        ports = parse_ports(item.get("ports"))
        sports = parse_ports(item.get("sport"))
        if (ports or sports) and proto == "all":
            raise ValueError(f"rule #{idx} has ports but proto=all")

        ip_match = str(item.get("ip", "")).strip()
        category = str(item.get("category", "default")).strip() or "default"

        mark_value = item.get("mark")
        if mark_value in (None, "") and category in category_marks:
            mark_value = category_marks.get(category)
        mark_int = parse_mark(mark_value)

        try:
            priority = int(item.get("priority", 0))
        except Exception:
            raise ValueError(f"rule #{idx} invalid priority")

        normalized.append(
            {
                "index": idx,
                "proto": proto,
                "ports": ports,
                "sports": sports,
                "ip": ip_match,
                "priority": priority,
                "category": category,
                "mark_int": mark_int,
                "mark_hex": f"0x{mark_int:x}",
            }
        )

    # Higher number = higher priority
    normalized.sort(key=lambda x: (-x["priority"], x["index"]))
    return normalized


def load_rules_payload(args):
    payload = None
    if args.rules_file:
        with open(args.rules_file, "r", encoding="utf-8") as file_handle:
            payload = file_handle.read()
    elif args.rules_json:
        text = args.rules_json.strip()
        if text.startswith("@"):
            file_path = text[1:]
            with open(file_path, "r", encoding="utf-8") as file_handle:
                payload = file_handle.read()
        else:
            payload = text
    else:
        payload = "[]"

    parsed = json.loads(payload)
    if isinstance(parsed, list):
        return normalize_rules(parsed, {})
    if isinstance(parsed, dict):
        rules = parsed.get("rules", [])
        category_marks = parsed.get("category_marks", {})
        return normalize_rules(rules, category_marks)
    raise ValueError("payload must be rules[] or {rules, category_marks}")


def _collect_backend_paths():
    nft = find_command("nft")
    iptables = find_command("iptables")
    return {"nft": nft or "", "iptables": iptables or ""}


def detect_backend(preferred_backend="", allow_fallback=True):
    details = _collect_backend_paths()
    preferred = str(preferred_backend or "").strip().lower()
    available = {
        "nft": bool(details["nft"]),
        "iptables": bool(details["iptables"]),
    }

    if preferred and preferred not in VALID_BACKENDS:
        return {
            "success": False,
            "backend": "",
            "configured_backend": preferred,
            "error": f"unsupported preferred backend: {preferred}",
            "details": details,
        }

    if preferred:
        if available.get(preferred):
            return {
                "success": True,
                "backend": preferred,
                "configured_backend": preferred,
                "error": "",
                "details": details,
            }
        if not allow_fallback:
            return {
                "success": False,
                "backend": "",
                "configured_backend": preferred,
                "error": f"preferred backend unavailable: {preferred}",
                "details": details,
            }
        for candidate in VALID_BACKENDS:
            if candidate != preferred and available.get(candidate):
                return {
                    "success": True,
                    "backend": candidate,
                    "configured_backend": preferred,
                    "fallback": True,
                    "warning": f"preferred backend unavailable: {preferred}, fallback to {candidate}",
                    "error": "",
                    "details": details,
                }

    for candidate in VALID_BACKENDS:
        if available.get(candidate):
            return {
                "success": True,
                "backend": candidate,
                "configured_backend": preferred,
                "error": "",
                "details": details,
            }

    return {
        "success": False,
        "backend": "",
        "configured_backend": preferred,
        "error": "no supported backend found (nft/iptables)",
        "details": details,
    }


def detect_active_backend():
    details = _collect_backend_paths()
    active = []

    nft_path = details["nft"]
    if nft_path:
        nft_check = run_cmd([nft_path, "list", "table", NFT_TABLE_FAMILY, NFT_TABLE_NAME])
        details["nft_check"] = nft_check
        if nft_check["rc"] == 0:
            active.append("nft")

    iptables_path = details["iptables"]
    if iptables_path:
        chain_check = run_cmd([iptables_path, "-t", IPT_TABLE, "-S", IPT_CHAIN])
        jump_check = run_cmd([iptables_path, "-t", IPT_TABLE, "-C", "PREROUTING", "-j", IPT_CHAIN])
        details["iptables_chain_check"] = chain_check
        details["iptables_jump_check"] = jump_check
        if chain_check["rc"] == 0 or jump_check["rc"] == 0:
            active.append("iptables")

    backend = ""
    if len(active) == 1:
        backend = active[0]
    elif len(active) > 1:
        backend = "mixed"

    return {
        "success": True,
        "backend": backend,
        "active": active,
        "details": details,
    }


def build_nft_match_tokens(rule, dport_token, sport_token):
    tokens = ["meta", "mark", "0x0"]
    if rule["proto"] != "all":
        tokens.extend(["meta", "l4proto", rule["proto"]])
    if rule["ip"]:
        if ":" in rule["ip"]:
            tokens.extend(["ip6", "saddr", rule["ip"]])
        else:
            tokens.extend(["ip", "saddr", rule["ip"]])
    if dport_token:
        tokens.extend(["th", "dport", dport_token])
    if sport_token:
        tokens.extend(["th", "sport", sport_token])
    return tokens


def apply_nft(rules, nft_path):
    details = {"commands": [], "rules_in": len(rules), "rules_applied": 0}

    ok, _ = run_checked([nft_path, "list", "table", NFT_TABLE_FAMILY, NFT_TABLE_NAME], details, ok_rc=(0, 1))
    if not ok:
        return False, "failed to check nft table", details
    if details["commands"][-1]["rc"] == 1:
        ok, _ = run_checked([nft_path, "add", "table", NFT_TABLE_FAMILY, NFT_TABLE_NAME], details)
        if not ok:
            return False, "failed to create nft table", details

    ok, _ = run_checked(
        [nft_path, "list", "chain", NFT_TABLE_FAMILY, NFT_TABLE_NAME, NFT_CHAIN_NAME],
        details,
        ok_rc=(0, 1),
    )
    if not ok:
        return False, "failed to check nft chain", details
    if details["commands"][-1]["rc"] == 1:
        ok, _ = run_checked(
            [
                nft_path,
                "add",
                "chain",
                NFT_TABLE_FAMILY,
                NFT_TABLE_NAME,
                NFT_CHAIN_NAME,
                "{",
                "type",
                "filter",
                "hook",
                "prerouting",
                "priority",
                "-150",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
            details,
        )
        if not ok:
            return False, "failed to create nft chain", details

    ok, _ = run_checked([nft_path, "flush", "chain", NFT_TABLE_FAMILY, NFT_TABLE_NAME, NFT_CHAIN_NAME], details)
    if not ok:
        return False, "failed to flush nft chain", details

    # Restore packet mark from conntrack mark first.
    ok, _ = run_checked(
        [
            nft_path,
            "add",
            "rule",
            NFT_TABLE_FAMILY,
            NFT_TABLE_NAME,
            NFT_CHAIN_NAME,
            "ct",
            "mark",
            "!=",
            "0x0",
            "meta",
            "mark",
            "set",
            "ct",
            "mark",
        ],
        details,
    )
    if not ok:
        return False, "failed to add nft restore-mark rule", details

    for rule in rules:
        dport_tokens = rule["ports"] or [None]
        sport_tokens = rule["sports"] or [None]
        for dport_token in dport_tokens:
            for sport_token in sport_tokens:
                cmd = [nft_path, "add", "rule", NFT_TABLE_FAMILY, NFT_TABLE_NAME, NFT_CHAIN_NAME]
                cmd.extend(build_nft_match_tokens(rule, dport_token, sport_token))
                cmd.extend(["counter", "meta", "mark", "set", rule["mark_hex"], "ct", "mark", "set", "mark"])
                ok, _ = run_checked(cmd, details)
                if not ok:
                    return False, f"failed to add nft rule for category={rule['category']}", details
                details["rules_applied"] += 1

    details["rules"] = rules
    return True, "", details


def apply_iptables(rules, iptables_path):
    details = {"commands": [], "rules_in": len(rules), "rules_applied": 0}

    ok, _ = run_checked([iptables_path, "-t", IPT_TABLE, "-S", IPT_CHAIN], details, ok_rc=(0, 1))
    if not ok:
        return False, "failed to check iptables chain", details
    if details["commands"][-1]["rc"] == 1:
        ok, _ = run_checked([iptables_path, "-t", IPT_TABLE, "-N", IPT_CHAIN], details)
        if not ok:
            return False, "failed to create iptables chain", details

    ok, _ = run_checked([iptables_path, "-t", IPT_TABLE, "-F", IPT_CHAIN], details)
    if not ok:
        return False, "failed to flush iptables chain", details

    ok, _ = run_checked(
        [iptables_path, "-t", IPT_TABLE, "-C", "PREROUTING", "-j", IPT_CHAIN],
        details,
        ok_rc=(0, 1),
    )
    if not ok:
        return False, "failed to check iptables jump", details
    if details["commands"][-1]["rc"] == 1:
        ok, _ = run_checked([iptables_path, "-t", IPT_TABLE, "-I", "PREROUTING", "-j", IPT_CHAIN], details)
        if not ok:
            return False, "failed to add iptables jump", details

    # Restore packet mark from conntrack mark first.
    ok, _ = run_checked(
        [
            iptables_path,
            "-t",
            IPT_TABLE,
            "-A",
            IPT_CHAIN,
            "-m",
            "connmark",
            "!",
            "--mark",
            "0x0/0xffffffff",
            "-j",
            "CONNMARK",
            "--restore-mark",
        ],
        details,
    )
    if not ok:
        return False, "failed to add iptables restore-mark rule", details

    for rule in rules:
        dport_tokens = rule["ports"] or [None]
        sport_tokens = rule["sports"] or [None]
        for dport_token in dport_tokens:
            for sport_token in sport_tokens:
                matches = []
                matches.extend(["-m", "mark", "--mark", "0x0/0xffffffff"])
                if rule["proto"] != "all":
                    matches.extend(["-p", rule["proto"]])
                if rule["ip"]:
                    matches.extend(["-s", rule["ip"]])
                if dport_token:
                    matches.extend(["--dport", dport_token.replace("-", ":")])
                if sport_token:
                    matches.extend(["--sport", sport_token.replace("-", ":")])

                mark_cmd = [
                    iptables_path,
                    "-t",
                    IPT_TABLE,
                    "-A",
                    IPT_CHAIN,
                    *matches,
                    "-j",
                    "MARK",
                    "--set-xmark",
                    f"{rule['mark_hex']}/0xffffffff",
                ]
                ok, _ = run_checked(mark_cmd, details)
                if not ok:
                    return False, f"failed to add iptables MARK rule for category={rule['category']}", details

                save_cmd = [
                    iptables_path,
                    "-t",
                    IPT_TABLE,
                    "-A",
                    IPT_CHAIN,
                    *matches,
                    "-j",
                    "CONNMARK",
                    "--save-mark",
                ]
                ok, _ = run_checked(save_cmd, details)
                if not ok:
                    return False, f"failed to add iptables CONNMARK rule for category={rule['category']}", details

                details["rules_applied"] += 1

    details["rules"] = rules
    return True, "", details


def apply_rules(rules, preferred_backend=""):
    detect = detect_backend(preferred_backend=preferred_backend)
    if not detect.get("success"):
        return detect

    backend = detect.get("backend")
    if backend == "nft":
        nft_path = detect["details"]["nft"]
        success, error, details = apply_nft(rules, nft_path)
    else:
        iptables_path = detect["details"]["iptables"]
        success, error, details = apply_iptables(rules, iptables_path)

    return {
        "success": success,
        "backend": backend,
        "configured_backend": detect.get("configured_backend", ""),
        "fallback": bool(detect.get("fallback")),
        "warning": detect.get("warning", ""),
        "error": error,
        "details": details,
    }


def clear_nft(nft_path):
    details = {"commands": []}
    ok, result = run_checked([nft_path, "delete", "table", NFT_TABLE_FAMILY, NFT_TABLE_NAME], details, ok_rc=(0, 1))
    if not ok:
        return False, "failed to clear nft table", details
    if result["rc"] == 1:
        details["note"] = "table not found"
    return True, "", details


def clear_iptables(iptables_path):
    details = {"commands": []}

    # Remove all PREROUTING jumps to SQM chain.
    for _ in range(32):
        ok, result = run_checked(
            [iptables_path, "-t", IPT_TABLE, "-C", "PREROUTING", "-j", IPT_CHAIN],
            details,
            ok_rc=(0, 1),
        )
        if not ok:
            return False, "failed while checking PREROUTING jump", details
        if result["rc"] == 1:
            break
        ok, _ = run_checked([iptables_path, "-t", IPT_TABLE, "-D", "PREROUTING", "-j", IPT_CHAIN], details)
        if not ok:
            return False, "failed to delete PREROUTING jump", details

    ok, result = run_checked([iptables_path, "-t", IPT_TABLE, "-S", IPT_CHAIN], details, ok_rc=(0, 1))
    if not ok:
        return False, "failed to check iptables chain", details
    if result["rc"] == 1:
        details["note"] = "chain not found"
        return True, "", details

    ok, _ = run_checked([iptables_path, "-t", IPT_TABLE, "-F", IPT_CHAIN], details)
    if not ok:
        return False, "failed to flush iptables chain", details
    ok, _ = run_checked([iptables_path, "-t", IPT_TABLE, "-X", IPT_CHAIN], details)
    if not ok:
        return False, "failed to delete iptables chain", details

    return True, "", details


def clear_rules(preferred_backend=""):
    if str(preferred_backend or "").strip():
        detect = detect_backend(preferred_backend=preferred_backend)
    else:
        active = detect_active_backend()
        active_backend = active.get("backend", "")
        if active_backend == "mixed":
            details = {"nft": {}, "iptables": {}}
            errors = []
            if active["details"].get("nft"):
                success, error, info = clear_nft(active["details"]["nft"])
                details["nft"] = info
                if not success:
                    errors.append(error)
            if active["details"].get("iptables"):
                success, error, info = clear_iptables(active["details"]["iptables"])
                details["iptables"] = info
                if not success:
                    errors.append(error)
            return {
                "success": len(errors) == 0,
                "backend": "mixed",
                "configured_backend": "",
                "fallback": False,
                "warning": "",
                "error": "; ".join(errors),
                "details": details,
            }
        if active_backend and active_backend != "mixed":
            detect = detect_backend(preferred_backend=active_backend, allow_fallback=False)
        else:
            detect = detect_backend()
    if not detect.get("success"):
        return detect

    backend = detect.get("backend")
    if backend == "nft":
        success, error, details = clear_nft(detect["details"]["nft"])
    else:
        success, error, details = clear_iptables(detect["details"]["iptables"])

    return {
        "success": success,
        "backend": backend,
        "configured_backend": detect.get("configured_backend", ""),
        "fallback": bool(detect.get("fallback")),
        "warning": detect.get("warning", ""),
        "error": error,
        "details": details,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", choices=["detect", "apply", "clear"], default="detect")
    parser.add_argument("--rules-json", default="")
    parser.add_argument("--rules-file", default="")
    parser.add_argument("--preferred-backend", default="")
    args = parser.parse_args()

    try:
        if args.action == "detect":
            result = detect_backend(preferred_backend=args.preferred_backend)
        elif args.action == "apply":
            rules = load_rules_payload(args)
            result = apply_rules(rules, preferred_backend=args.preferred_backend)
        else:
            result = clear_rules(preferred_backend=args.preferred_backend)
    except Exception as exc:
        result = {
            "success": False,
            "backend": "",
            "error": str(exc),
            "details": {},
        }

    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if result.get("success") else 1)


if __name__ == "__main__":
    main()
