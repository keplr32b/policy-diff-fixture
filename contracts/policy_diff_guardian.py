# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""
PolicyDiff Guardian

A GenLayer Intelligent Contract for consensus-backed monitoring of material
changes to registered public HTTPS policy pages.

It seals one baseline snapshot for each registered policy and later compares
the same URL against plain-English guardrails. The result is an append-only,
consensus-backed check record.

This development-network contract is not legal advice, does not autonomously
poll the web, and does not transfer funds.
"""

from genlayer import *
import json
import time
from dataclasses import dataclass


try:
    _UserError = gl.vm.UserError
except Exception:
    _UserError = Exception


MAX_POLICY_ID_LEN = 64
MAX_LABEL_LEN = 120
MAX_GUARDRAILS_LEN = 2400
MAX_SNAPSHOT_LEN = 6000
MAX_NOTE_LEN = 240

STATUS_NO_CHANGE = "NO_MATERIAL_CHANGE"
STATUS_MATERIAL = "MATERIAL_CHANGE"
STATUS_INCONCLUSIVE = "INCONCLUSIVE"

CLASS_NONE = "NONE"
CLASS_DATA_USE = "DATA_USE"
CLASS_USER_RIGHTS = "USER_RIGHTS"
CLASS_FEES = "FEES"
CLASS_ARBITRATION = "ARBITRATION"
CLASS_ELIGIBILITY = "ELIGIBILITY"
CLASS_SECURITY = "SECURITY"
CLASS_GOVERNANCE = "GOVERNANCE"
CLASS_OTHER = "OTHER"

BAND_NONE = "NONE"
BAND_LOW = "LOW"
BAND_MEDIUM = "MEDIUM"
BAND_HIGH = "HIGH"
BAND_UNKNOWN = "UNKNOWN"


def require(cond: bool, msg: str) -> None:
    if not cond:
        raise _UserError(msg)


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def parse_json_response(text: str) -> dict:
    t = (text or "").strip()

    if t.startswith("```"):
        t = t.strip("`")
        if t[:4].lower() == "json":
            t = t[4:]
        t = t.strip()

    start = t.find("{")
    end = t.rfind("}")

    if start != -1 and end != -1:
        t = t[start : end + 1]

    return json.loads(t)


def now_u256() -> u256:
    return u256(int(time.time()))


def normalize_text(text: str) -> str:
    raw = text if isinstance(text, str) else ""
    compact = " ".join(raw.split())
    require(len(compact) > 0, "empty rendered policy page")
    return compact[:MAX_SNAPSHOT_LEN]


def snapshot_identity(text: str) -> str:
    return canonical(
        {
            "length": len(text),
            "prefix": text[:160],
            "suffix": text[-160:] if len(text) > 160 else text,
        }
    )


def host_of(url: str) -> str:
    u = (url or "").strip().lower()

    require(u.startswith("https://"), "only https urls allowed")

    rest = u[8:]
    host = rest.split("/")[0].split("?")[0].split("#")[0]

    require(len(host) > 0, "empty host")
    require("@" not in host, "userinfo not allowed")
    require(not host.replace(".", "").isdigit(), "ip literal hosts rejected")
    require("localhost" not in host, "localhost rejected")
    require(not host.endswith(".local"), "local tld rejected")

    return host


def normalize_rule_csv(raw: str) -> str:
    text = (raw or "").strip()

    if len(text) == 0:
        return ""

    seen = {}
    values = []

    for item in text.split(","):
        token = item.strip()

        require(token in ("1", "2", "3", "4", "5"), "invalid triggered rule id")

        if token not in seen:
            seen[token] = True
            values.append(int(token))

    values.sort()

    return ",".join([str(v) for v in values])


@allow_storage
        self.baseline_captured_at_of[pid] = u256(0)

        self.acknowledged_of[pid] = False
        self.check_count_of[pid] = u256(0)
        self.latest_check_plus_one[pid] = u256(0)

    @gl.public.write
    def capture_baseline(self, policy_id: str) -> str:
        pid = self._require_registered(policy_id)

        require(
            self.baseline_captured_of.get(pid, False) is not True,
            "baseline already sealed",
        )

        host = self.policy_host_of.get(pid, "")
        url = self.policy_url_of.get(pid, "")

        require(self.allowed_hosts.get(host, False) is True, "host not allowed")

        try:
            content = gl.nondet.web.render(url, mode="text")
            baseline = normalize_text(content)
        except Exception as e:
            raise _UserError(("baseline fetch failed: " + str(e))[:240])

        identity = snapshot_identity(baseline)

        self.baseline_text_of[pid] = baseline
        self.baseline_identity_of[pid] = identity
        self.baseline_captured_of[pid] = True
        self.baseline_captured_at_of[pid] = now_u256()

        return identity

    @gl.public.write
    def check_policy(self, policy_id: str) -> str:
        pid = self._require_registered(policy_id)

        require(
            self.baseline_captured_of.get(pid, False) is True,
            "capture baseline first",
        )

        host = self.policy_host_of.get(pid, "")
        url = self.policy_url_of.get(pid, "")
        baseline = self.baseline_text_of.get(pid, "")
        baseline_identity_value = self.baseline_identity_of.get(pid, "")
        guardrails = self.guardrails_of.get(pid, "")

        require(self.allowed_hosts.get(host, False) is True, "host not allowed")

        try:
            content = gl.nondet.web.render(url, mode="text")
            current = normalize_text(content)
        except Exception as e:
            self._append_check(
                pid,
                STATUS_INCONCLUSIVE,
                CLASS_NONE,
                BAND_UNKNOWN,
                "",
                ("current policy fetch failed: " + str(e))[:MAX_NOTE_LEN],
                baseline_identity_value,
                "",
            )
            return STATUS_INCONCLUSIVE

        current_identity_value = snapshot_identity(current)

        result = self._run_judgment(
            baseline,
            current,
            guardrails,
            baseline_identity_value,
            current_identity_value,
        )

        self._append_check(
            pid,
            result["status"],
            result["change_class"],
            result["materiality_band"],
            result["triggered_rules_csv"],
            result["note"],
            baseline_identity_value,
            current_identity_value,
        )

        return result["status"]

    @gl.public.write
    def acknowledge_change(self, policy_id: str) -> None:
        pid = self._require_registered(policy_id)

        require(
            gl.message.sender_address == self.policy_owner_of.get(pid, self.owner),
            "only policy owner",
        )

        require(
            self.latest_check_plus_one.get(pid, u256(0)) > u256(0),
            "no checks yet",
        )

        index = int(self.latest_check_plus_one[pid]) - 1
        latest = self.checks[index]

        require(
            latest.status == STATUS_MATERIAL,
            "latest result is not a material change",
        )

        self.acknowledged_of[pid] = True

    @gl.public.view
    def check_count(self) -> u256:
        return u256(len(self.checks))

    @gl.public.view
    def read_policy(self, policy_id: str) -> str:
        pid = self._require_registered(policy_id)

        return canonical(
            {
                "policy_id": pid,
                "owner": str(self.policy_owner_of.get(pid, self.owner)),
                "label": self.policy_label_of.get(pid, ""),
                "url": self.policy_url_of.get(pid, ""),
                "host": self.policy_host_of.get(pid, ""),
                "guardrails": self.guardrails_of.get(pid, ""),
                "baseline_captured": bool(self.baseline_captured_of.get(pid, False)),
                "baseline_identity": self.baseline_identity_of.get(pid, ""),
                "created_at": int(self.created_at_of.get(pid, u256(0))),
                "baseline_captured_at": int(self.baseline_captured_at_of.get(pid, u256(0))),
                "acknowledged": bool(self.acknowledged_of.get(pid, False)),
                "checks_for_policy": int(self.check_count_of.get(pid, u256(0))),
            }
        )

    @gl.public.view
    def read_check(self, check_id: int) -> str:
        require(0 <= check_id < len(self.checks), "no such check")

        record = self.checks[check_id]

        return canonical(
            {
                "policy_id": record.policy_id,
                "status": record.status,
                "change_class": record.change_class,
                "materiality_band": record.materiality_band,
                "triggered_rules_csv": record.triggered_rules_csv,
                "note": record.note,
                "baseline_identity": record.baseline_identity,
                "current_identity": record.current_identity,
                "checked_at": int(record.checked_at),
            }
        )

    @gl.public.view
    def read_latest_check(self, policy_id: str) -> str:
        pid = self._require_registered(policy_id)

        require(
            self.latest_check_plus_one.get(pid, u256(0)) > u256(0),
            "no checks for policy",
        )

        index = int(self.latest_check_plus_one[pid]) - 1

        return self.read_check(index)

    @gl.public.view
    def is_host_allowed(self, host: str) -> bool:
        h = (host or "").strip().lower()
        return self.allowed_hosts.get(h, False) is True

    @gl.public.view
    def get_owner(self) -> Address:
        return self.owner