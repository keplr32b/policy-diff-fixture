# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""
PolicyDiff Guardian

Consensus-backed monitoring for material changes to public HTTPS policy pages.
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
        t = t[start:end + 1]

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
    host = rest.split("/").split("?").split("#")[0]

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

        require(
            token in ("1", "2", "3", "4", "5"),
            "invalid triggered rule id",
        )

        if token not in seen:
            seen[token] = True
            values.append(int(token))

    values.sort()

    return ",".join([str(v) for v in values])


@allow_storage
@dataclass
class PolicyCheck:
    policy_id: str
    status: str
    change_class: str
    materiality_band: str
    triggered_rules_csv: str
    note: str
    baseline_identity: str
    current_identity: str
    checked_at: u256


class PolicyDiffGuardian(gl.Contract):
    owner: Address

    allowed_hosts: TreeMap[str, bool]

    registered_of: TreeMap[str, bool]
    policy_owner_of: TreeMap[str, Address]
    policy_label_of: TreeMap[str, str]
    policy_url_of: TreeMap[str, str]
    policy_host_of: TreeMap[str, str]
    guardrails_of: TreeMap[str, str]

    baseline_captured_of: TreeMap[str, bool]
    baseline_text_of: TreeMap[str, str]
    baseline_identity_of: TreeMap[str, str]
    created_at_of: TreeMap[str, u256]
    baseline_captured_at_of: TreeMap[str, u256]

    acknowledged_of: TreeMap[str, bool]
    check_count_of: TreeMap[str, u256]
    latest_check_plus_one: TreeMap[str, u256]

    checks: DynArray[PolicyCheck]

    def __init__(self):
        self.owner = gl.message.sender_address

    @gl.public.write
    def allow_host(self, host: str) -> None:
        require(gl.message.sender_address == self.owner, "only owner")

        h = (host or "").strip().lower()

        require(len(h) > 0, "empty host")
        require("://" not in h, "pass host only, not url")
        require("@" not in h, "userinfo not allowed")
        require(not h.replace(".", "").isdigit(), "ip literal rejected")
        require("localhost" not in h, "localhost rejected")
        require(not h.endswith(".local"), "local tld rejected")

        self.allowed_hosts[h] = True

    @gl.public.write
    def disallow_host(self, host: str) -> None:
        require(gl.message.sender_address == self.owner, "only owner")

        h = (host or "").strip().lower()

        if h in self.allowed_hosts:
            self.allowed_hosts[h] = False

    def _require_registered(self, policy_id: str) -> str:
        pid = (policy_id or "").strip()

        require(1 <= len(pid) <= MAX_POLICY_ID_LEN, "invalid policy id")
        require(
            self.registered_of.get(pid, False) is True,
            "unknown policy",
        )

        return pid

    def _validate_result(
        self,
        status: str,
        change_class: str,
        materiality_band: str,
        triggered_rules_csv: str,
        note: str,
    ) -> dict:
        allowed_statuses = (
            STATUS_NO_CHANGE,
            STATUS_MATERIAL,
            STATUS_INCONCLUSIVE,
        )

        allowed_classes = (
            CLASS_NONE,
            CLASS_DATA_USE,
            CLASS_USER_RIGHTS,
            CLASS_FEES,
            CLASS_ARBITRATION,
            CLASS_ELIGIBILITY,
            CLASS_SECURITY,
            CLASS_GOVERNANCE,
            CLASS_OTHER,
        )

        allowed_bands = (
            BAND_NONE,
            BAND_LOW,
            BAND_MEDIUM,
            BAND_HIGH,
            BAND_UNKNOWN,
        )

        s = (status or "").strip().upper()
        c = (change_class or "").strip().upper()
        b = (materiality_band or "").strip().upper()
        rules = normalize_rule_csv(triggered_rules_csv)
        n = (note or "").strip()[:MAX_NOTE_LEN]

        require(s in allowed_statuses, "invalid status")
        require(c in allowed_classes, "invalid change class")
        require(b in allowed_bands, "invalid materiality band")

        if s == STATUS_NO_CHANGE:
            require(c == CLASS_NONE, "no-change class must be NONE")
            require(b == BAND_NONE, "no-change band must be NONE")
            require(rules == "", "no-change cannot trigger rules")

        elif s == STATUS_MATERIAL:
            require(c != CLASS_NONE, "material change needs a class")
            require(
                b in (BAND_LOW, BAND_MEDIUM, BAND_HIGH),
                "material change needs LOW MEDIUM or HIGH",
            )
            require(rules != "", "material change needs triggered rules")

        else:
            require(c == CLASS_NONE, "inconclusive class must be NONE")
            require(b == BAND_UNKNOWN, "inconclusive band must be UNKNOWN")
            require(rules == "", "inconclusive cannot trigger rules")

        return {
            "status": s,
            "change_class": c,
            "materiality_band": b,
            "triggered_rules_csv": rules,
            "note": n,
        }

    def _append_check(
        self,
        policy_id: str,
        status: str,
        change_class: str,
        materiality_band: str,
        triggered_rules_csv: str,
        note: str,
        baseline_identity_value: str,
        current_identity_value: str,
    ) -> None:
        record = PolicyCheck(
            policy_id=policy_id,
            status=status,
            change_class=change_class,
            materiality_band=materiality_band,
            triggered_rules_csv=triggered_rules_csv,
            note=note[:MAX_NOTE_LEN],
            baseline_identity=baseline_identity_value,
            current_identity=current_identity_value,
            checked_at=now_u256(),
        )

        self.checks.append(record)

        index = len(self.checks) - 1

        self.latest_check_plus_one[policy_id] = u256(index + 1)
        self.check_count_of[policy_id] = (
            self.check_count_of.get(policy_id, u256(0)) + u256(1)
        )

    def _run_judgment(
        self,
        baseline_text: str,
        current_text: str,
        guardrails: str,
        baseline_identity_value: str,
        current_identity_value: str,
    ) -> dict:
        def judge() -> str:
            prompt = (
                "You are evaluating whether a public policy page has changed in a "
                "MATERIALLY RELEVANT way against sealed monitoring guardrails.

"
                "IMPORTANT LIMITATIONS:
"
                "- This is a document-change assessment, not legal advice.
"
                "- Judge only the supplied baseline and current rendered text.
"
                "- Do not invent text, facts, obligations, or implications.
"
                "- Treat only a meaningful change affecting a listed guardrail as material.
"
                "- Formatting, headings, spelling, and non-substantive wording changes are not material.
"
                "- If either document is unusable or comparison is genuinely ambiguous, return INCONCLUSIVE.

"
                "SEALED BASELINE POLICY:
---
"
                + baseline_text
                + "
---

"
                + "CURRENT POLICY:
---
"
                + current_text
                + "
---

"
                + "MONITORING GUARDRAILS:
"
                + guardrails
                + "

"
                + "CLASSIFICATION RULES:
"
                + "1 = DATA_USE: new/broader collection, sale, disclosure, sharing, profiling, "
                + "or retention of personal or usage data.
"
                + "2 = USER_RIGHTS: reduced ability to access, delete, correct, export, or control data.
"
                + "3 = FEES: new/increased fees, subscription charges, cancellation/refund restrictions, "
                + "withdrawal restrictions, or payment obligations.
"
                + "4 = ARBITRATION: new mandatory arbitration, class-action waiver, venue restriction, "
                + "or reduced dispute-resolution rights.
"
                + "5 = SECURITY: material weakening of security, incident-notification, governance, "
                + "eligibility, or service-access commitments.

"
                + "Return ONLY strict JSON with exactly these fields:
"
                + '{ "status": "NO_MATERIAL_CHANGE" or "MATERIAL_CHANGE" or "INCONCLUSIVE", '
                + '"change_class": "NONE" or "DATA_USE" or "USER_RIGHTS" or "FEES" or '
                + '"ARBITRATION" or "ELIGIBILITY" or "SECURITY" or "GOVERNANCE" or "OTHER", '
                + '"materiality_band": "NONE" or "LOW" or "MEDIUM" or "HIGH" or "UNKNOWN", '
                + '"triggered_rules_csv": "comma-separated IDs from 1,2,3,4,5 or empty", '
                + '"note": "brief evidence-grounded explanation" }

'
                + "OUTPUT CONSTRAINTS:
"
                + "- NO_MATERIAL_CHANGE requires change_class NONE, materiality_band NONE, and empty triggered_rules_csv.
"
                + "- MATERIAL_CHANGE requires a non-NONE change_class, LOW/MEDIUM/HIGH band, and one or more triggered rule IDs.
"
                + "- INCONCLUSIVE requires change_class NONE, materiality_band UNKNOWN, and empty triggered_rules_csv.
"
                + "- Choose one primary change_class even if multiple rules trigger.
"
            )

            raw = gl.nondet.exec_prompt(prompt)
            data = parse_json_response(raw)

            validated = self._validate_result(
                str(data.get("status", "")),
                str(data.get("change_class", "")),
                str(data.get("materiality_band", "")),
                str(data.get("triggered_rules_csv", "")),
                str(data.get("note", "")),
            )

            return canonical(
                {
                    "status": validated["status"],
                    "change_class": validated["change_class"],
                    "materiality_band": validated["materiality_band"],
                    "triggered_rules_csv": validated["triggered_rules_csv"],
                    "note": validated["note"],
                    "baseline_identity": baseline_identity_value,
                    "current_identity": current_identity_value,
                }
            )

        principle = (
            "Two policy-change assessments are EQUIVALENT if and only if all "
            "state-changing fields are identical: (1) status, (2) change_class, "
            "(3) materiality_band, (4) triggered_rules_csv after treating it as "
            "an unordered set of rule IDs, (5) baseline_identity, and "
            "(6) current_identity. The note may differ in wording, detail, or style. "
            "If any state-changing field differs, the assessments are NOT equivalent."
        )

        agreed = gl.eq_principle.prompt_comparative(judge, principle)
        parsed = json.loads(agreed)

        require(
            str(parsed.get("baseline_identity", "")) == baseline_identity_value,
            "baseline identity mismatch",
        )

        require(
            str(parsed.get("current_identity", "")) == current_identity_value,
            "current identity mismatch",
        )

        return self._validate_result(
            str(parsed.get("status", "")),
            str(parsed.get("change_class", "")),
            str(parsed.get("materiality_band", "")),
            str(parsed.get("triggered_rules_csv", "")),
            str(parsed.get("note", "")),
        )

    @gl.public.write
    def register_policy(
        self,
        policy_id: str,
        policy_url: str,
        policy_label: str,
        guardrails: str,
    ) -> None:
        require(gl.message.sender_address == self.owner, "only owner")

        pid = (policy_id or "").strip()
        url = (policy_url or "").strip()
        label = (policy_label or "").strip()
        rules = (guardrails or "").strip()

        require(1 <= len(pid) <= MAX_POLICY_ID_LEN, "invalid policy id")
        require(1 <= len(label) <= MAX_LABEL_LEN, "invalid policy label")
        require(
            80 <= len(rules) <= MAX_GUARDRAILS_LEN,
            "guardrails must be 80 to 2400 chars",
        )
        require(
            self.registered_of.get(pid, False) is not True,
            "policy id already exists",
        )

        host = host_of(url)

        require(
            self.allowed_hosts.get(host, False) is True,
            "host not allowed: " + host,
        )

        self.registered_of[pid] = True
        self.policy_owner_of[pid] = gl.message.sender_address
        self.policy_label_of[pid] = label
        self.policy_url_of[pid] = url
        self.policy_host_of[pid] = host
        self.guardrails_of[pid] = rules

        self.baseline_captured_of[pid] = False
        self.baseline_text_of[pid] = ""
        self.baseline_identity_of[pid] = ""
        self.created_at_of[pid] = now_u256()
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
                "baseline_captured_at": int(
                    self.baseline_captured_at_of.get(pid, u256(0))
                ),
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