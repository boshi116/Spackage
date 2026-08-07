#!/usr/bin/env python3
"""TC 管理模块。

负责创建和调整 SQM 所需的 qdisc、class 和 filter。
这里不做业务判断，只执行已经确定好的队列结构和速率参数。
"""
import logging
import re
import subprocess
import time

import nss_detect


# tc 命令参数全部走本地白名单校验，避免把异常值直接拼进 shell。
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
_CLASSID_RE = re.compile(r"^[0-9]{1,4}:[0-9]{1,4}$")
_RATE_RE = re.compile(r"^[1-9][0-9]*(kbit|Kbit|mbit|Mbit|gbit|Gbit)$")


def _validate_iface(value, field="interface"):
    v = str(value or "").strip()
    if not v or not _IFACE_RE.match(v):
        raise ValueError(f"{field} '{value}' invalid: [A-Za-z0-9_.:-] max 15 chars")
    return v


def _validate_classid(value, field="classid"):
    v = str(value or "").strip()
    if not _CLASSID_RE.match(v):
        raise ValueError(f"{field} '{value}' invalid: expected 0-9:0-9 like 1:11")
    return v


def _validate_rate(value, field="rate"):
    v = str(value or "").strip()
    if not _RATE_RE.match(v):
        raise ValueError(f"{field} '{value}' invalid: expected Nkbit/NMbit like 1000kbit")
    return v


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
    RATE_UPLOAD_CLASS_IDS = ("1:10", "1:11", "1:12", "1:13")
    RATE_DOWNLOAD_CLASS_IDS = ("2:20", "2:21", "2:22", "2:23")
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

        self.interface = _validate_iface(config.get("interface", "eth0"), "interface")
        self.upload_kbps = int(config.get("upload_speed", config.get("upload_bandwidth", 0)))
        self.download_kbps = int(config.get("download_speed", config.get("download_bandwidth", 0)))
        self.algorithm = str(config.get("queue_algorithm", "fq_codel")).lower()
        self.ecn = _to_bool(config.get("ecn", True), default=True)
        self.queue_backend = str(config.get("queue_backend", "auto")).strip().lower()
        if self.queue_backend not in ("auto", "software", "nss"):
            self.queue_backend = "auto"
        self.nss_info = {}
        self.logger = logging.getLogger(__name__)
        self.last_error_details = {}

    def run(self, cmd):
        self.logger.debug(cmd)
        try:
            return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=124,
                stdout=stdout,
                stderr=stderr + "\ncommand timed out",
            )

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

    def clear_sqm_runtime(self):
        """停掉本插件在 sqm-scripts 中的 section（仅当本插件 section 已启用时执行，不误动用户其他 section）。"""
        # 先检查本插件 section 是否启用；不存在或未启用则无事可做
        enabled_out = (self.run("uci -q get sqm.sqm_controller.enabled 2>/dev/null").stdout or "").strip()
        if enabled_out != "1":
            return True
        result = self.run("uci -q set sqm.sqm_controller.enabled='0' 2>/dev/null")
        if result.returncode != 0:
            self.logger.error("clear_sqm_runtime: disable section failed rc=%s", result.returncode)
            return False
        result = self.run("uci -q commit sqm 2>/dev/null")
        if result.returncode != 0:
            self.logger.error("clear_sqm_runtime: commit failed rc=%s", result.returncode)
            return False
        # restart 让禁用生效（只影响本插件 section 的启用状态）
        result = self.run("/etc/init.d/sqm restart 2>/dev/null")
        if result.returncode != 0:
            # 不执行全局 stop：避免误停用户其他 SQM section，直接向上报失败
            self.logger.error("clear_sqm_runtime: sqm restart failed rc=%s", result.returncode)
            return False
        return True

    def setup_nss(self):
        """NSS 模式：桥接配置到 /etc/config/sqm 并调用 sqm-scripts 启动 nss-zk.qos。"""
        # 先清旧软件后端（HTB/IFB），避免残留队列干扰 NSS
        self.clear_tc_rules()
        if self.upload_kbps <= 0 and self.download_kbps <= 0:
            self._set_last_error_details(stage="setup-nss", error="no bandwidth configured")
            return False

        # 1) 写入 sqm 配置（独立 section，避免与用户 luci-app-sqm 配置互相覆盖）
        uci_cmds = [
            "test -f /etc/config/sqm || touch /etc/config/sqm",
            "uci -q set sqm.sqm_controller=queue",
            f"uci -q set sqm.sqm_controller.interface='{self.interface}'",
            "uci -q set sqm.sqm_controller.enabled='1'",
            f"uci -q set sqm.sqm_controller.download='{max(self.download_kbps, 0)}'",
            f"uci -q set sqm.sqm_controller.upload='{max(self.upload_kbps, 0)}'",
            "uci -q set sqm.sqm_controller.qdisc='fq_codel'",
            "uci -q set sqm.sqm_controller.script='nss-zk.qos'",
            "uci -q set sqm.sqm_controller.algorithm='fq_codel'",
            "uci -q commit sqm",
        ]
        for cmd in uci_cmds:
            result = self.run(cmd)
            if result.returncode != 0:
                self._set_last_error_details(stage="setup-nss-uci", cmd=cmd, returncode=result.returncode, stderr=(result.stderr or "").strip())
                self.logger.error("setup_nss uci failed: %s -> %s", cmd, (result.stderr or "").strip())
                return False

        # 2) 调用 sqm-scripts 启动（内部会调 nss-zk.qos start）
        result = self.run("/etc/init.d/sqm restart 2>&1 || /etc/init.d/sqm start 2>&1")
        if result.returncode != 0:
            self._set_last_error_details(stage="setup-nss-sqm", returncode=result.returncode, stdout=(result.stdout or "").strip(), stderr=(result.stderr or "").strip())
            return False

        # 3) 验证 nsstbl / nssfq_codel 已挂载
        time.sleep(1)
        qdisc_out = self._capture_output(f"tc qdisc show dev {self.interface}") + self._capture_output("tc qdisc show dev ifb0 2>/dev/null")
        if not re.search(r"nsstbl|nssfq_codel", qdisc_out):
            self._set_last_error_details(stage="setup-nss-verify", output=qdisc_out[:2000])
            self.logger.error("setup_nss verify failed: no nsstbl/nssfq_codel qdisc found");
            return False

        return True

    def setup_queues(self):
        """队列总入口：根据 queue_backend 配置 + NSS 检测决定实际后端。"""
        backend, info = nss_detect.resolve_backend(self.queue_backend)
        self.nss_info = info
        self.logger.info("queue backend resolved: %s (%s)", backend, info.get("reason", ""))

        if backend == "nss":
            ok = self.setup_nss()
            if not ok:
                self.logger.error("NSS queue setup failed: %s", self.last_error_details)
            return ok, "nss", info

        # software 模式：先停掉 NSS 可能遗留的 sqm 实例，再清 tc 建 HTB
        if not self.clear_sqm_runtime():
            # 旧 NSS 清理失败：不继续建 HTB，避免新旧队列并存，向上层传播失败
            self.logger.error("software setup aborted: clear_sqm_runtime failed")
            return False, "software", dict(info, error="NSS 旧队列清理失败，未启动软件队列")
        ok = self.setup_htb()
        return ok, "software", info
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

    def _parse_rate_to_kbps(self, value):
        text = str(value or "").strip().lower()
        matched = re.match(r"^([0-9]+(?:\.[0-9]+)?)([a-z/]+)?$", text)
        if not matched:
            return None
        number = float(matched.group(1))
        unit = matched.group(2) or "kbit"
        if unit in ("bit", "bit/s", "bps"):
            return int(round(number / 1000.0))
        if unit in ("kbit", "kbit/s", "kbps"):
            return int(round(number))
        if unit in ("mbit", "mbit/s", "mbps"):
            return int(round(number * 1000.0))
        if unit in ("gbit", "gbit/s", "gbps"):
            return int(round(number * 1000.0 * 1000.0))
        return None

    def _read_class_rates(self, dev):
        ok, result = self._run_checked(f"tc class show dev {dev}", "verify-class-rates-show")
        if not ok:
            return None
        rates = {}
        for line in (result.stdout or "").splitlines():
            class_m = re.search(r"\bclass htb (\S+)\b", line)
            rate_m = re.search(r"\brate (\S+)", line)
            ceil_m = re.search(r"\bceil (\S+)", line)
            prio_m = re.search(r"\bprio (\d+)", line)
            if not class_m or not rate_m or not ceil_m:
                continue
            rates[class_m.group(1)] = {
                "rate_kbps": self._parse_rate_to_kbps(rate_m.group(1)),
                "ceil_kbps": self._parse_rate_to_kbps(ceil_m.group(1)),
                "prio": int(prio_m.group(1)) if prio_m else None,
                "raw": line,
            }
        return rates

    def _verify_class_rates(self, normalized):
        tolerance_kbps = 1
        failures = []
        dev_specs = (
            (self.interface, normalized["upload_classes"]),
            ("ifb0", normalized["download_classes"]),
        )
        for dev, classes in dev_specs:
            observed = self._read_class_rates(dev)
            if observed is None:
                failures.append({"dev": dev, "error": "failed to read class rates"})
                continue
            for item in classes:
                actual = observed.get(item["classid"])
                if not actual:
                    failures.append({"dev": dev, "classid": item["classid"], "error": "class missing after update"})
                    continue
                expected_rate = int(item["rate_kbps"])
                expected_ceil = int(item["ceil_kbps"])
                actual_rate = actual.get("rate_kbps")
                actual_ceil = actual.get("ceil_kbps")
                if actual_rate is None or actual_ceil is None:
                    failures.append({"dev": dev, "classid": item["classid"], "error": "unable to parse rate", "actual": actual})
                    continue
                if abs(actual_rate - expected_rate) > tolerance_kbps or abs(actual_ceil - expected_ceil) > tolerance_kbps:
                    failures.append({
                        "dev": dev,
                        "classid": item["classid"],
                        "expected": {"rate_kbps": expected_rate, "ceil_kbps": expected_ceil},
                        "actual": actual,
                    })
        return {"success": len(failures) == 0, "failures": failures}

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
        if value is None:
            raise ValueError(f"{field_name} is required, got None")
        try:
            parsed = int(value)
        except (ValueError, TypeError):
            raise ValueError(f"{field_name} '{value}' invalid: must be integer kbps")
        if parsed <= 0:
            raise ValueError(f"{field_name} must be > 0, got {parsed}")
        return parsed

    def _normalize_class_plan(self, plan, upload_allowed=None, download_allowed=None):
        if not isinstance(plan, dict):
            raise ValueError("plan must be dict")
        if "upload_classes" not in plan or "download_classes" not in plan:
            raise ValueError("plan requires upload_classes and download_classes")
        if not isinstance(plan["upload_classes"], list) or not isinstance(plan["download_classes"], list):
            raise ValueError("upload_classes/download_classes must be list")

        upload_allowed = tuple(upload_allowed or self.UPLOAD_CLASS_IDS)
        download_allowed = tuple(download_allowed or self.DOWNLOAD_CLASS_IDS)
        normalized = {"upload_classes": [], "download_classes": []}
        upload_seen = set()
        download_seen = set()

        def normalize_item(item, allowed, side):
            if not isinstance(item, dict):
                raise ValueError(f"{side} class item must be dict")

            classid = _validate_classid(str(item.get("classid", "")).strip(), f"{side} classid")
            if classid not in allowed:
                raise ValueError(f"{side} classid not allowed: {classid}")

            rate_kbps = self._parse_positive_int(item.get("rate_kbps"), "rate_kbps")
            ceil_val = item.get("ceil_kbps")
            if ceil_val is None or (isinstance(ceil_val, str) and ceil_val.strip() == ""):
                # None / 空字符串 → 取 rate_kbps
                ceil_kbps = rate_kbps
            else:
                try:
                    ceil_raw = int(ceil_val)
                except (ValueError, TypeError):
                    raise ValueError(
                        f"{side} ceil_kbps '{ceil_val}' invalid: must be integer kbps"
                    )
                if ceil_raw <= 0:
                    raise ValueError(
                        f"{side} ceil_kbps must be > 0, got {ceil_raw}"
                    )
                ceil_kbps = ceil_raw
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
            item = normalize_item(raw, upload_allowed, "upload")
            if item["classid"] in upload_seen:
                raise ValueError(f"duplicate upload classid: {item['classid']}")
            upload_seen.add(item["classid"])
            normalized["upload_classes"].append(item)

        for raw in plan["download_classes"]:
            item = normalize_item(raw, download_allowed, "download")
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

    def update_class_rates(self, plan):
        """仅更新 HTB class 的 rate/ceil，不动 qdisc 和 filter。

        使用 tc class change 增量修改，比 apply_classes() 更轻量。
        plan 格式与 apply_classes() 相同。

        返回：dict {success, applied, failed, not_attempted, commands}
        兼容旧代码：bool(result) → result["success"]
        """
        result = {
            "success": False,
            "applied": [],
            "failed": [],
            "not_attempted": [],
            "commands": [],
        }
        self.last_error_details = {}
        try:
            normalized = self._normalize_class_plan(
                plan,
                upload_allowed=self.RATE_UPLOAD_CLASS_IDS,
                download_allowed=self.RATE_DOWNLOAD_CLASS_IDS,
            )
        except Exception as exc:
            self.logger.error("update_class_rates validation failed: %s", exc)
            result["failed"].append({"classid": "", "error": f"validation: {exc}"})
            return result

        if not self._ensure_base_tree_ready():
            self.logger.error("update_class_rates requires setup_htb() base tree")
            result["failed"].append({"classid": "", "error": "base tree not ready"})
            return result

        all_classids = []

        for item in normalized["upload_classes"]:
            classid = item["classid"]
            cmd = (
                f"tc class change dev {self.interface} parent 1:1 classid {classid} "
                f"htb rate {item['rate_kbps']}kbit ceil {item['ceil_kbps']}kbit prio {item['prio']}"
            )
            ok, details = self._run_checked(cmd, "update-rates-upload")
            cmd_rec = {"classid": classid, "dev": self.interface, "cmd": cmd, "ok": ok}
            result["commands"].append(cmd_rec)
            if ok:
                result["applied"].append(classid)
            else:
                cmd_rec["error"] = str(details) if details else "unknown"
                result["failed"].append({"classid": classid, "error": str(details) if details else "unknown"})
                # 同方向剩余 class 标记 not_attempted
                remaining = [i["classid"] for i in normalized["upload_classes"] if i["classid"] not in result["applied"] and i["classid"] != classid]
                result["not_attempted"].extend(remaining)
                # 全部 download class 也标记 not_attempted
                result["not_attempted"].extend(i["classid"] for i in normalized["download_classes"])
                result["success"] = False
                return result

        for item in normalized["download_classes"]:
            classid = item["classid"]
            cmd = (
                f"tc class change dev ifb0 parent 2:1 classid {classid} "
                f"htb rate {item['rate_kbps']}kbit ceil {item['ceil_kbps']}kbit prio {item['prio']}"
            )
            ok, details = self._run_checked(cmd, "update-rates-download")
            cmd_rec = {"classid": classid, "dev": "ifb0", "cmd": cmd, "ok": ok}
            result["commands"].append(cmd_rec)
            if ok:
                result["applied"].append(classid)
            else:
                cmd_rec["error"] = str(details) if details else "unknown"
                result["failed"].append({"classid": classid, "error": str(details) if details else "unknown"})
                remaining = [i["classid"] for i in normalized["download_classes"] if i["classid"] not in result["applied"] and i["classid"] != classid]
                result["not_attempted"].extend(remaining)
                result["success"] = False
                return result

        verify = self._verify_class_rates(normalized)
        result["post_check"] = verify
        if not verify.get("success"):
            result["success"] = False
            result["failed"].extend(verify.get("failures", []))
            self._set_last_error_details(stage="update-rates-post-check", failures=verify.get("failures", []))
            return result

        result["success"] = True
        return result

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
