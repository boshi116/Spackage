#!/usr/bin/env python3
"""
Traffic control manager.
Supports fq_codel and cake.
"""
import logging
import re
import subprocess


def _to_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


class TCManager:
    UPLOAD_CLASS_IDS = ("1:11", "1:12", "1:13")
    DOWNLOAD_CLASS_IDS = ("2:21", "2:22", "2:23")
    ALLOWED_QDISC = ("fq_codel", "cake")

    UPLOAD_FILTER_PREFS = {
        "1:11": {"ip": 311, "ipv6": 321},
        "1:12": {"ip": 312, "ipv6": 322},
        "1:13": {"ip": 313, "ipv6": 323},
    }
    DOWNLOAD_FILTER_PREFS = {
        "2:21": {"ip": 411, "ipv6": 421},
        "2:22": {"ip": 412, "ipv6": 422},
        "2:23": {"ip": 413, "ipv6": 423},
    }

    def __init__(self, config):
        if not isinstance(config, dict):
            raise ValueError("config must be dict")

        self.interface = config.get("interface", "eth0")
        self.upload_kbps = int(config.get("upload_speed", config.get("upload_bandwidth", 0)))
        self.download_kbps = int(config.get("download_speed", config.get("download_bandwidth", 0)))
        self.algorithm = str(config.get("queue_algorithm", "fq_codel")).lower()
        self.ecn = _to_bool(config.get("ecn", True), default=True)
        self.logger = logging.getLogger(__name__)
        self.last_error_details = {}

    def run(self, cmd):
        self.logger.debug(cmd)
        return subprocess.run(cmd, shell=True, capture_output=True, text=True)

    def _set_last_error_details(self, **kwargs):
        self.last_error_details = {key: value for key, value in kwargs.items() if value is not None}

    def clear_tc_rules(self):
        cmds = [
            f"tc qdisc del dev {self.interface} root 2>/dev/null",
            f"tc qdisc del dev {self.interface} handle ffff: ingress 2>/dev/null",
            f"tc filter del dev {self.interface} parent ffff: 2>/dev/null",
            "tc qdisc del dev ifb0 root 2>/dev/null",
        ]
        for cmd in cmds:
            self.run(cmd)

    def setup_ifb(self):
        self.run("modprobe ifb 2>/dev/null || true")
        self.run("ip link add ifb0 type ifb 2>/dev/null || true")
        self.run("ip link set ifb0 up")

    def _capture_output(self, cmd):
        result = self.run(cmd)
        return (result.stdout or "").strip()

    def _qdisc_parent_present(self, text, parent, allowed_qdisc=None):
        qdisc_types = allowed_qdisc or self.ALLOWED_QDISC
        qdisc_pattern = "|".join(re.escape(item) for item in qdisc_types)
        return bool(re.search(rf"\bqdisc (?:{qdisc_pattern}) \S+:\s+parent {re.escape(parent)}\b", text or ""))

    def _apply_ingress_redirect(self):
        proto_list = ("ip", "ipv6")
        matcher_specs = (
            ("matchall", "matchall"),
            ("u32", "u32 match u32 0 0"),
        )
        action_specs = (
            ("connmark", "action connmark pipe action mirred egress redirect dev ifb0"),
            ("ctinfo", "action ctinfo cpmark 0xffffffff pipe action mirred egress redirect dev ifb0"),
            ("mirred", "action mirred egress redirect dev ifb0"),
        )
        last_failure = None

        for action_name, action_clause in action_specs:
            for matcher_name, matcher_clause in matcher_specs:
                self.run(f"tc filter del dev {self.interface} parent ffff: 2>/dev/null")
                all_ok = True

                for proto in proto_list:
                    cmd = (
                        f"tc filter add dev {self.interface} parent ffff: protocol {proto} "
                        f"{matcher_clause} {action_clause}"
                    )
                    result = self.run(cmd)
                    if result.returncode != 0:
                        last_failure = {
                            "stage": "setup-ingress-redirect",
                            "matcher": matcher_name,
                            "mark_restore": action_name,
                            "cmd": cmd,
                            "returncode": result.returncode,
                            "stdout": (result.stdout or "").strip(),
                            "stderr": (result.stderr or "").strip(),
                        }
                        self.logger.warning(
                            "ingress redirect candidate failed matcher=%s mark_restore=%s: %s -> %s",
                            matcher_name,
                            action_name,
                            cmd,
                            (result.stderr or "").strip(),
                        )
                        all_ok = False
                        break

                if all_ok:
                    self.logger.info(
                        "ingress redirect active matcher=%s mark_restore=%s",
                        matcher_name,
                        action_name,
                    )
                    return True

        if last_failure:
            self._set_last_error_details(**last_failure)
        return False

    def setup_htb(self):
        ecn_flag = "ecn" if self.ecn else "noecn"
        self.logger.info(
            "iface=%s up=%s down=%s algo=%s ecn=%s",
            self.interface,
            self.upload_kbps,
            self.download_kbps,
            self.algorithm,
            ecn_flag,
        )

        self.clear_tc_rules()
        cmds = []

        if self.upload_kbps > 0:
            cmds += [
                f"tc qdisc add dev {self.interface} root handle 1: htb default 10",
                f"tc class add dev {self.interface} parent 1: classid 1:1 htb rate {self.upload_kbps}kbit ceil {self.upload_kbps}kbit",
                f"tc class add dev {self.interface} parent 1:1 classid 1:10 htb rate {self.upload_kbps}kbit ceil {self.upload_kbps}kbit",
            ]

            if self.algorithm == "cake":
                cmds.append(
                    f"tc qdisc add dev {self.interface} parent 1:10 handle 10: cake bandwidth {self.upload_kbps}kbit"
                )
            else:
                cmds.append(
                    f"tc qdisc add dev {self.interface} parent 1:10 handle 10: fq_codel {ecn_flag}"
                )

        if self.download_kbps > 0:
            self.setup_ifb()
            cmds += [
                f"tc qdisc add dev {self.interface} handle ffff: ingress",
                f"tc qdisc add dev ifb0 root handle 2: htb default 20",
                f"tc class add dev ifb0 parent 2: classid 2:1 htb rate {self.download_kbps}kbit ceil {self.download_kbps}kbit",
                f"tc class add dev ifb0 parent 2:1 classid 2:20 htb rate {self.download_kbps}kbit ceil {self.download_kbps}kbit",
            ]

            if self.algorithm == "cake":
                cmds.append(
                    f"tc qdisc add dev ifb0 parent 2:20 handle 20: cake bandwidth {self.download_kbps}kbit"
                )
            else:
                cmds.append(
                    f"tc qdisc add dev ifb0 parent 2:20 handle 20: fq_codel {ecn_flag}"
                )

        ok = 0
        for cmd in cmds:
            result = self.run(cmd)
            if result.returncode == 0:
                ok += 1
            else:
                self.logger.error("failed: %s -> %s", cmd, result.stderr.strip())

        if ok == len(cmds) and self.download_kbps > 0:
            if not self._apply_ingress_redirect():
                return False

        return ok == len(cmds)

    def show_status(self):
        status = {}
        cmds = [
            f"tc -s qdisc show dev {self.interface}",
            f"tc -s class show dev {self.interface}",
            "ip link show ifb0 2>/dev/null || echo 'ifb0 missing'",
            "tc -s qdisc show dev ifb0 2>/dev/null || echo 'ifb0 no tc rule'",
        ]
        for cmd in cmds:
            result = self.run(cmd)
            status[cmd] = result.stdout
        return status

    def inspect_runtime_state(self, classification_enabled=True):
        classification_enabled = bool(classification_enabled)
        want_upload = self.upload_kbps > 0
        want_download = self.download_kbps > 0

        upload_qdisc = self._capture_output(f"tc qdisc show dev {self.interface}")
        download_qdisc = self._capture_output("tc qdisc show dev ifb0 2>/dev/null")
        upload_class = self._capture_output(f"tc class show dev {self.interface}")
        download_class = self._capture_output("tc class show dev ifb0 2>/dev/null")
        ingress_filter = self._capture_output(f"tc filter show dev {self.interface} parent ffff: 2>/dev/null")

        upload_root_present = bool(re.search(r"\bqdisc htb 1:\s+root\b", upload_qdisc))
        download_root_present = bool(re.search(r"\bqdisc htb 2:\s+root\b", download_qdisc))
        upload_parent_present = bool(re.search(r"\bclass htb 1:1\b", upload_class))
        download_parent_present = bool(re.search(r"\bclass htb 2:1\b", download_class))
        upload_default_qdisc_present = self._qdisc_parent_present(upload_qdisc, "1:10")
        download_default_qdisc_present = self._qdisc_parent_present(download_qdisc, "2:20")
        ingress_filter_present = any(token in ingress_filter for token in ("mirred", "connmark", "ctinfo"))

        upload_classes_present = {classid: bool(re.search(rf"\bclass htb {re.escape(classid)}\b", upload_class)) for classid in self.UPLOAD_CLASS_IDS}
        download_classes_present = {classid: bool(re.search(rf"\bclass htb {re.escape(classid)}\b", download_class)) for classid in self.DOWNLOAD_CLASS_IDS}
        upload_qdiscs_present = {classid: self._qdisc_parent_present(upload_qdisc, classid) for classid in self.UPLOAD_CLASS_IDS}
        download_qdiscs_present = {classid: self._qdisc_parent_present(download_qdisc, classid) for classid in self.DOWNLOAD_CLASS_IDS}

        upload_class_queues_present = all(upload_classes_present.values()) and all(upload_qdiscs_present.values())
        download_class_queues_present = all(download_classes_present.values()) and all(download_qdiscs_present.values())
        classifier_tc_complete = (
            not classification_enabled or (
                (not want_upload or upload_class_queues_present) and
                (not want_download or download_class_queues_present)
            )
        )

        return {
            "want_upload": want_upload,
            "want_download": want_download,
            "classification_enabled": classification_enabled,
            "upload_root_present": upload_root_present,
            "download_root_present": download_root_present,
            "upload_parent_present": upload_parent_present,
            "download_parent_present": download_parent_present,
            "upload_default_qdisc_present": upload_default_qdisc_present,
            "download_default_qdisc_present": download_default_qdisc_present,
            "ingress_filter_present": ingress_filter_present,
            "upload_classes_present": upload_classes_present,
            "download_classes_present": download_classes_present,
            "upload_qdiscs_present": upload_qdiscs_present,
            "download_qdiscs_present": download_qdiscs_present,
            "upload_class_queues_present": upload_class_queues_present,
            "download_class_queues_present": download_class_queues_present,
            "classifier_tc_complete": classifier_tc_complete,
            "tc_wan_qdisc": upload_qdisc,
            "tc_ifb_qdisc": download_qdisc,
            "tc_wan_class": upload_class,
            "tc_ifb_class": download_class,
            "ingress_filter": ingress_filter,
        }

    def get_current_bandwidth(self):
        bw = {"upload": 0, "download": 0}

        result = self.run(f"tc class show dev {self.interface}")
        for line in result.stdout.splitlines():
            matched = re.search(r"rate (\d+)kbit", line)
            if matched:
                bw["upload"] = int(matched.group(1))

        result = self.run("tc class show dev ifb0 2>/dev/null")
        for line in result.stdout.splitlines():
            matched = re.search(r"rate (\d+)kbit", line)
            if matched:
                bw["download"] = int(matched.group(1))

        return bw

    def _run_checked(self, cmd, stage):
        result = self.run(cmd)
        if result.returncode != 0:
            self._set_last_error_details(
                stage=stage,
                cmd=cmd,
                returncode=result.returncode,
                stdout=(result.stdout or "").strip(),
                stderr=(result.stderr or "").strip(),
            )
            self.logger.error("%s failed: %s -> %s", stage, cmd, result.stderr.strip())
            return False, result
        return True, result

    def _run_delete_optional_detail(self, cmd, stage):
        result = self.run(cmd)
        output = (result.stdout or "").strip()
        error = (result.stderr or "").strip()
        merged = f"{output}\n{error}".strip().lower()
        detail = {
            "stage": stage,
            "cmd": cmd,
            "returncode": result.returncode,
            "stdout": output,
            "stderr": error,
            "absent": False,
            "success": False,
        }

        if result.returncode == 0:
            if merged:
                self.logger.warning("%s unexpected output: %s -> %s", stage, cmd, merged)
            detail["success"] = True
            return detail

        not_found_markers = (
            "no such file or directory",
            "cannot find",
            "not found",
            "no filter",
            "no qdisc",
            "no class",
            "parent qdisc doesn't exists",
            "parent qdisc doesn't exist",
            "failed to find qdisc with specified classid",
            "failed to find qdisc",
        )
        if any(marker in merged for marker in not_found_markers):
            detail["success"] = True
            detail["absent"] = True
            return detail
        if not output and not error:
            self.logger.warning("%s empty non-zero delete treated as optional success: %s", stage, cmd)
            detail["success"] = True
            detail["absent"] = True
            return detail

        self._set_last_error_details(
            stage=stage,
            cmd=cmd,
            returncode=result.returncode,
            stdout=output,
            stderr=error,
        )
        self.logger.error("%s failed: %s -> %s", stage, cmd, error or output)
        return detail

    def _run_delete_optional(self, cmd, stage):
        return bool(self._run_delete_optional_detail(cmd, stage).get("success"))

    def _parse_mark(self, value):
        if isinstance(value, int):
            mark = value
        elif isinstance(value, str):
            text = value.strip().lower()
            if not text:
                raise ValueError("mark is empty")
            mark = int(text, 16) if text.startswith("0x") else int(text, 10)
        else:
            raise ValueError("mark must be int or string")

        if mark <= 0 or mark > 0xFFFFFFFF:
            raise ValueError("mark out of range")
        return mark

    def _parse_positive_int(self, value, field_name):
        parsed = int(value)
        if parsed <= 0:
            raise ValueError(f"{field_name} must be > 0")
        return parsed

    def _normalize_class_plan(self, plan):
        if not isinstance(plan, dict):
            raise ValueError("plan must be dict")
        if "upload_classes" not in plan or "download_classes" not in plan:
            raise ValueError("plan requires upload_classes and download_classes")
        if not isinstance(plan["upload_classes"], list) or not isinstance(plan["download_classes"], list):
            raise ValueError("upload_classes/download_classes must be list")

        normalized = {"upload_classes": [], "download_classes": []}
        upload_seen = set()
        download_seen = set()

        def normalize_item(item, allowed, side):
            if not isinstance(item, dict):
                raise ValueError(f"{side} class item must be dict")

            classid = str(item.get("classid", "")).strip()
            if classid not in allowed:
                raise ValueError(f"{side} classid not allowed: {classid}")

            rate_kbps = self._parse_positive_int(item.get("rate_kbps"), "rate_kbps")
            ceil_raw = int(item.get("ceil_kbps"))
            ceil_kbps = ceil_raw if ceil_raw > 0 else rate_kbps
            prio = int(item.get("prio", 1))

            qdisc = str(item.get("qdisc", self.algorithm)).strip().lower()
            if qdisc not in self.ALLOWED_QDISC:
                raise ValueError(f"{side} qdisc not allowed: {qdisc}")

            return {
                "classid": classid,
                "rate_kbps": rate_kbps,
                "ceil_kbps": ceil_kbps,
                "prio": prio,
                "qdisc": qdisc,
            }

        for raw in plan["upload_classes"]:
            item = normalize_item(raw, self.UPLOAD_CLASS_IDS, "upload")
            if item["classid"] in upload_seen:
                raise ValueError(f"duplicate upload classid: {item['classid']}")
            upload_seen.add(item["classid"])
            normalized["upload_classes"].append(item)

        for raw in plan["download_classes"]:
            item = normalize_item(raw, self.DOWNLOAD_CLASS_IDS, "download")
            if item["classid"] in download_seen:
                raise ValueError(f"duplicate download classid: {item['classid']}")
            download_seen.add(item["classid"])
            normalized["download_classes"].append(item)

        return normalized

    def _normalize_fwmark_map(self, fw_map):
        if not isinstance(fw_map, list):
            raise ValueError("map must be list")

        normalized = []
        for item in fw_map:
            if not isinstance(item, dict):
                raise ValueError("map item must be dict")

            if "mark" not in item or "upload_flowid" not in item or "download_flowid" not in item:
                raise ValueError("map item requires mark/upload_flowid/download_flowid")

            upload_flowid = str(item.get("upload_flowid", "")).strip()
            download_flowid = str(item.get("download_flowid", "")).strip()

            if upload_flowid not in self.UPLOAD_CLASS_IDS:
                raise ValueError(f"upload_flowid not allowed: {upload_flowid}")
            if download_flowid not in self.DOWNLOAD_CLASS_IDS:
                raise ValueError(f"download_flowid not allowed: {download_flowid}")

            mark = self._parse_mark(item.get("mark"))
            normalized.append(
                {
                    "mark_int": mark,
                    "mark_hex": f"0x{mark:x}",
                    "upload_flowid": upload_flowid,
                    "download_flowid": download_flowid,
                }
            )
        return normalized

    def _ensure_base_tree_ready(self):
        checks = [
            (
                f"tc qdisc show dev {self.interface}",
                r"\bqdisc htb 1:\s+root\b",
                "missing upload root htb qdisc (1: root)",
            ),
            (
                "tc qdisc show dev ifb0 2>/dev/null",
                r"\bqdisc htb 2:\s+root\b",
                "missing download root htb qdisc (2: root)",
            ),
            (
                f"tc class show dev {self.interface}",
                r"\bclass htb 1:1\b",
                "missing upload parent class 1:1",
            ),
            (
                "tc class show dev ifb0 2>/dev/null",
                r"\bclass htb 2:1\b",
                "missing download parent class 2:1",
            ),
        ]

        for cmd, pattern, message in checks:
            ok, result = self._run_checked(cmd, "base-tree-check")
            if not ok:
                return False
            if not re.search(pattern, result.stdout or ""):
                self.logger.error("base-tree-check failed: %s", message)
                return False

        return True

    def apply_classes(self, plan):
        self.last_error_details = {}
        try:
            normalized = self._normalize_class_plan(plan)
        except Exception as exc:
            self.logger.error("apply_classes validation failed: %s", exc)
            return False

        if not self._ensure_base_tree_ready():
            self.logger.error("apply_classes requires setup_htb() base tree")
            return False

        ecn_flag = "ecn" if self.ecn else "noecn"

        for item in normalized["upload_classes"]:
            classid = item["classid"]
            handle = classid.split(":", 1)[1] + ":"

            cmd = (
                f"tc class replace dev {self.interface} parent 1:1 classid {classid} "
                f"htb rate {item['rate_kbps']}kbit ceil {item['ceil_kbps']}kbit prio {item['prio']}"
            )
            ok, _ = self._run_checked(cmd, "apply-classes-upload-class")
            if not ok:
                return False

            if item["qdisc"] == "cake":
                qdisc_bw = item["ceil_kbps"] if item["ceil_kbps"] > 0 else item["rate_kbps"]
                cmd = (
                    f"tc qdisc replace dev {self.interface} parent {classid} handle {handle} "
                    f"cake bandwidth {qdisc_bw}kbit"
                )
            else:
                cmd = (
                    f"tc qdisc replace dev {self.interface} parent {classid} handle {handle} "
                    f"fq_codel {ecn_flag}"
                )
            ok, _ = self._run_checked(cmd, "apply-classes-upload-qdisc")
            if not ok:
                return False

        for item in normalized["download_classes"]:
            classid = item["classid"]
            handle = classid.split(":", 1)[1] + ":"

            cmd = (
                f"tc class replace dev ifb0 parent 2:1 classid {classid} "
                f"htb rate {item['rate_kbps']}kbit ceil {item['ceil_kbps']}kbit prio {item['prio']}"
            )
            ok, _ = self._run_checked(cmd, "apply-classes-download-class")
            if not ok:
                return False

            if item["qdisc"] == "cake":
                qdisc_bw = item["ceil_kbps"] if item["ceil_kbps"] > 0 else item["rate_kbps"]
                cmd = (
                    f"tc qdisc replace dev ifb0 parent {classid} handle {handle} "
                    f"cake bandwidth {qdisc_bw}kbit"
                )
            else:
                cmd = (
                    f"tc qdisc replace dev ifb0 parent {classid} handle {handle} "
                    f"fq_codel {ecn_flag}"
                )
            ok, _ = self._run_checked(cmd, "apply-classes-download-qdisc")
            if not ok:
                return False

        return True

    def apply_fwmark_filters(self, fw_map):
        self.last_error_details = {}
        try:
            normalized = self._normalize_fwmark_map(fw_map)
        except Exception as exc:
            self.logger.error("apply_fwmark_filters validation failed: %s", exc)
            return False

        if not self._ensure_base_tree_ready():
            self.logger.error("apply_fwmark_filters requires setup_htb() base tree")
            return False

        proto_list = ("ip", "ipv6")
        expected_down_prefs = set()
        for item in normalized:
            up_pref_map = self.UPLOAD_FILTER_PREFS[item["upload_flowid"]]
            down_pref_map = self.DOWNLOAD_FILTER_PREFS[item["download_flowid"]]

            for proto in proto_list:
                up_pref = up_pref_map[proto]
                down_pref = down_pref_map[proto]
                expected_down_prefs.add(down_pref)

                if not self._run_delete_optional(
                    f"tc filter del dev {self.interface} parent 1: protocol {proto} pref {up_pref}",
                    "apply-fwmark-delete-upload",
                ):
                    return False
                if not self._run_delete_optional(
                    f"tc filter del dev ifb0 parent 2: protocol {proto} pref {down_pref} 2>/dev/null",
                    "apply-fwmark-delete-download",
                ):
                    return False

                cmd = (
                    f"tc filter add dev {self.interface} parent 1: protocol {proto} pref {up_pref} "
                    f"handle {item['mark_hex']} fw flowid {item['upload_flowid']}"
                )
                ok, _ = self._run_checked(cmd, "apply-fwmark-add-upload")
                if not ok:
                    return False

                cmd = (
                    f"tc filter add dev ifb0 parent 2: protocol {proto} pref {down_pref} "
                    f"handle {item['mark_hex']} fw flowid {item['download_flowid']}"
                )
                ok, _ = self._run_checked(cmd, "apply-fwmark-add-download")
                if not ok:
                    return False

        verify_cmd = "tc filter show dev ifb0 parent 2: 2>/dev/null"
        verify_result = self.run(verify_cmd)
        verify_out = (verify_result.stdout or "").strip()
        if verify_result.returncode != 0:
            self._set_last_error_details(
                stage="apply-fwmark-verify",
                verify_cmd=verify_cmd,
                verify_returncode=verify_result.returncode,
                verify_stdout=(verify_result.stdout or "").strip(),
                verify_stderr=(verify_result.stderr or "").strip(),
                expected_down_prefs=sorted(expected_down_prefs),
            )
            self.logger.error("apply-fwmark-verify failed: %s -> %s", verify_cmd, (verify_result.stderr or "").strip())
            return False
        if not verify_out:
            self._set_last_error_details(
                stage="apply-fwmark-verify",
                verify_cmd=verify_cmd,
                verify_returncode=verify_result.returncode,
                verify_stdout=verify_out,
                verify_stderr=(verify_result.stderr or "").strip(),
                expected_down_prefs=sorted(expected_down_prefs),
            )
            self.logger.error("apply-fwmark-verify failed: no filters on ifb0 parent 2:")
            return False

        for pref in sorted(expected_down_prefs):
            if not re.search(rf"\bpref\s+{pref}\b", verify_out):
                self._set_last_error_details(
                    stage="apply-fwmark-verify-missing-pref",
                    missing_pref=pref,
                    verify_cmd=verify_cmd,
                    verify_stdout=verify_out,
                    expected_down_prefs=sorted(expected_down_prefs),
                )
                self.logger.error("apply-fwmark-verify failed: missing ifb0 pref %s", pref)
                return False

        return True

    def clear_classifier_tc(self):
        self.last_error_details = {}
        details = {
            "success": True,
            "removed": [],
            "already_absent": [],
            "failures": [],
        }

        def record(detail):
            item = {
                "stage": detail.get("stage"),
                "cmd": detail.get("cmd"),
                "returncode": detail.get("returncode"),
                "stdout": detail.get("stdout", ""),
                "stderr": detail.get("stderr", ""),
            }
            if detail.get("success"):
                if detail.get("absent"):
                    details["already_absent"].append(item)
                else:
                    details["removed"].append(item)
                return
            details["success"] = False
            details["failures"].append(item)

        for pref_map in self.UPLOAD_FILTER_PREFS.values():
            for proto in ("ip", "ipv6"):
                record(
                    self._run_delete_optional_detail(
                        f"tc filter del dev {self.interface} parent 1: protocol {proto} pref {pref_map[proto]}",
                        "clear-classifier-filter-upload",
                    )
                )

        for pref_map in self.DOWNLOAD_FILTER_PREFS.values():
            for proto in ("ip", "ipv6"):
                record(
                    self._run_delete_optional_detail(
                        f"tc filter del dev ifb0 parent 2: protocol {proto} pref {pref_map[proto]} 2>/dev/null",
                        "clear-classifier-filter-download",
                    )
                )

        for classid in self.UPLOAD_CLASS_IDS:
            handle = classid.split(":", 1)[1] + ":"
            record(
                self._run_delete_optional_detail(
                    f"tc qdisc del dev {self.interface} parent {classid} handle {handle}",
                    "clear-classifier-qdisc-upload",
                )
            )
            record(
                self._run_delete_optional_detail(
                    f"tc class del dev {self.interface} classid {classid}",
                    "clear-classifier-class-upload",
                )
            )

        for classid in self.DOWNLOAD_CLASS_IDS:
            handle = classid.split(":", 1)[1] + ":"
            record(
                self._run_delete_optional_detail(
                    f"tc qdisc del dev ifb0 parent {classid} handle {handle} 2>/dev/null",
                    "clear-classifier-qdisc-download",
                )
            )
            record(
                self._run_delete_optional_detail(
                    f"tc class del dev ifb0 classid {classid} 2>/dev/null",
                    "clear-classifier-class-download",
                )
            )

        for cmd, stage in (
            (f"tc filter del dev {self.interface} parent ffff: 2>/dev/null", "clear-classifier-ingress-filter"),
            (f"tc qdisc del dev {self.interface} handle ffff: ingress 2>/dev/null", "clear-classifier-ingress-qdisc"),
            (f"tc qdisc del dev {self.interface} root 2>/dev/null", "clear-classifier-root-upload"),
            ("tc qdisc del dev ifb0 root 2>/dev/null", "clear-classifier-root-download"),
        ):
            record(self._run_delete_optional_detail(cmd, stage))

        if not details["success"]:
            self.last_error_details = {
                "stage": "clear-classifier-tc",
                "failures": list(details["failures"]),
            }
        return details
