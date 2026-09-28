# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""
PolicyDiff Guardian
===================

Consensus-backed material policy-change monitoring for public HTTPS pages.

A policy owner:
  1. allowlists a public HTTPS host;
  2. registers one policy URL and plain-English guardrails;
  3. seals a bounded baseline snapshot from that exact URL;
  4. later re-checks the same URL.

GenLayer validators fetch the current page, compare it to the sealed baseline,
and agree on one bounded outcome:

  NO_MATERIAL_CHANGE
  MATERIAL_CHANGE
  INCONCLUSIVE

This contract is a development-network monitoring primitive. It does not
provide legal advice, does not autonomously poll, and does not move funds.
A check must be triggered through a transaction.
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


def normalize_text(text: str, max_len: int = MAX_SNAPSHOT_LEN) -> str:
    raw = text if isinstance(text, str) else ""
    compact = " ".join(raw.split())
    require(len(compact) > 0, "empty rendered policy page")
    return compact[:max_len]


def snapshot_hash(text: str) -> str:
    """
    Deterministic snapshot identity for this development-network prototype.

    This is an auditable canonical metadata representation, not a cryptographic
    hash. A future production version can replace this with a confirmed stable
    hash primitive or content-addressed snapshot storage.
    """
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
    """
    Accept only registered rule IDs 1..5. Normalize output to ascending,
    comma-separated order: '1,3,5'. Empty string is valid.
    """
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
@dataclass
class Policy:
    policy_id: str
    label: str
    url: str
    host: str
    guardrails: str
    baseline_text: str
    baseline_hash: str
    baseline_captured: bool
    created_at: u256
    baseline_captured_at: u256
    acknowledged: bool


@allow_storage
@dataclass
class PolicyCheck:
    policy_id: str
    status: str
    change_class: str
    materiality_band: str
    triggered_rules_csv: str
    note: str
    baseline_hash: str
    current_hash: str
    checked_at: u256


class PolicyDiffGuardian(gl.Contract):
    """
    Public HTTPS policy-page monitor with an owner-managed host allowlist.

    Policy IDs are unique. The first successfully captured baseline is sealed:
    it cannot be replaced by another method in this contract.
    """

    owner: Address

    allowed_hosts: TreeMap[str, bool]

    policies: DynArray[Policy]
    policy_index_plus_one: TreeMap[str, u256]

    checks: DynArray[PolicyCheck]
    latest_check_plus_one: TreeMap[str, u256]
    check_count_of: TreeMap[str, u256]

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

    def _policy_index(self, policy_id: str) -> int:
        pid = (policy_id or "").strip()

        require(self.policy_index_plus_one.get(pid, u256(0)) > u256(0), "unknown policy")

        return int(self.policy_index_plus_one[pid]) - 1

    def _read_policy(self, policy_id: str) -> Policy:
        return self.policies[self._policy_index(policy_id)]

    def _write_policy(self, policy_id: str, policy: Policy) -> None:
        self.policies[self._policy_index(policy_id)] = policy

    def _append_check(
        self,
        policy_id: str,
        status: str,
        change_class: str,
        materiality_band: str,
        triggered_rules_csv: str,
        note: str,
        baseline_hash_value: str,
        current_hash_value: str,
    ) -> None:
        record = PolicyCheck(
            policy_id=policy_id,
            status=status,
            change_class=change_class,
            materiality_band=materiality_band,
            triggered_rules_csv=triggered_rules_csv,
            note=note[:MAX_NOTE_LEN],
            baseline_hash=baseline_hash_value,
            current_hash=current_hash_value,
            checked_at=now_u256(),
        )

        self.checks.append(record)

        check_index = len(self.checks) - 1

        self.latest_check_plus_one[policy_id] = u256(check_index + 1)
        self.check_count_of[policy_id] = self.check_count_of.get(policy_id, u256(0)) + u256(1)

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
            require(b in (BAND_LOW, BAND_MEDIUM, BAND_HIGH), "material change needs LOW MEDIUM or HIGH")
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

    def _judge_policy_change(self, policy: Policy, current_text: str) -> dict:
        baseline = policy.baseline_text
        baseline_hash_value = policy.baseline_hash
        current_hash_value = snapshot_hash(current_text)
        guardrails = policy.guardrails

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
                + baseline
                + "
---

"

                "CURRENT POLICY:
---
"
                + current_text
                + "
---

"

                "MONITORING GUARDRAILS:
"
                + guardrails
                + "

"

                "CLASSIFICATION RULES:
"
                "1 = DATA_USE: new/broader collection, sale, disclosure, sharing, profiling, "
                "or retention of personal or usage data.
"
                "2 = USER_RIGHTS: reduced ability to access, delete, correct, export, or control data.
"
                "3 = FEES: new/increased fees, subscription charges, cancellation/refund restrictions, "
                "withdrawal restrictions, or payment obligations.
"
                "4 = ARBITRATION: new mandatory arbitration, class-action waiver, venue restriction, "
                "or reduced dispute-resolution rights.
"
                "5 = SECURITY: material weakening of security, incident-notification, governance, "
                "eligibility, or service-access commitments.

"

                "Return ONLY strict JSON with exactly these fields:
"
                '{ "status": "NO_MATERIAL_CHANGE" or "MATERIAL_CHANGE" or "INCONCLUSIVE", '
                '"change_class": "NONE" or "DATA_USE" or "USER_RIGHTS" or "FEES" or '
                '"ARBITRATION" or "ELIGIBILITY" or "SECURITY" or "GOVERNANCE" or "OTHER", '
                '"materiality_band": "NONE" or "LOW" or "MEDIUM" or "HIGH" or "UNKNOWN", '
                '"triggered_rules_csv": "comma-separated IDs from 1,2,3,4,5 or empty", '
                '"note": "brief evidence-grounded explanation" }

'

                "OUTPUT CONSTRAINTS:
"
                "- NO_MATERIAL_CHANGE requires change_class NONE, materiality_band NONE, and empty triggered_rules_csv.
"
                "- MATERIAL_CHANGE requires a non-NONE change_class, LOW/MEDIUM/HIGH band, and one or more triggered rule IDs.
"
                "- INCONCLUSIVE requires change_class NONE, materiality_band UNKNOWN, and empty triggered_rules_csv.
"
                "- Choose one primary change_class even if multiple rules trigger.
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
                    "baseline_hash": baseline_hash_value,
                    "current_hash": current_hash_value,
                }
            )

        principle = (
            "Two policy-change assessments are EQUIVALENT if and only if all "
            "state-changing fields are identical: (1) status, (2) change_class, "
            "(3) materiality_band, (4) triggered_rules_csv after treating it as "
            "an unordered set of rule IDs, (5) baseline_hash, and (6) current_hash. "
            "The note may differ in wording, detail, or style. If any state-changing "
            "field differs, the assessments are NOT equivalent."
        )

        agreed = gl.eq_principle.prompt_comparative(judge, principle)
        parsed = json.loads(agreed)

        require(
            str(parsed.get("baseline_hash", "")) == baseline_hash_value,
            "baseline identity mismatch",
        )

        require(
            str(parsed.get("current_hash", "")) == current_hash_value,
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
        require(80 <= len(rules) <= MAX_GUARDRAILS_LEN, "guardrails must be 80 to 2400 chars")
        require(self.policy_index_plus_one.get(pid, u256(0)) == u256(0), "policy id already exists")

        host = host_of(url)

        require(self.allowed_hosts.get(host, False) is True, "host not allowed: " + host)

        policy = Policy(
            policy_id=pid,
            label=label,
            url=url,
            host=host,
            guardrails=rules,
            baseline_text="",
            baseline_hash="",
            baseline_captured=False,
            created_at=now_u256(),
            baseline_captured_at=u256(0),
            acknowledged=False,
        )

        self.policies.append(policy)
        self.policy_index_plus_one[pid] = u256(len(self.policies))

    @gl.public.write
    def capture_baseline(self, policy_id: str) -> str:
        pid = (policy_id or "").strip()
        policy = self._read_policy(pid)

        require(policy.baseline_captured is not True, "baseline already sealed")
        require(self.allowed_hosts.get(policy.host, False) is True, "host not allowed")

        try:
            content = gl.nondet.web.render(policy.url, mode="text")
            baseline = normalize_text(content)
        except Exception as e:
            raise _UserError(("baseline fetch failed: " + str(e))[:240])

        policy.baseline_text = baseline
        policy.baseline_hash = snapshot_hash(baseline)
        policy.baseline_captured = True
        policy.baseline_captured_at = now_u256()

        self._write_policy(pid, policy)

        return policy.baseline_hash

    @gl.public.write
    def check_policy(self, policy_id: str) -> str:
        pid = (policy_id or "").strip()
        policy = self._read_policy(pid)

        require(policy.baseline_captured is True, "capture baseline first")
        require(self.allowed_hosts.get(policy.host, False) is True, "host not allowed")

        current_text = ""
        fetch_failed = False
        failure_note = ""

        try:
            content = gl.nondet.web.render(policy.url, mode="text")
            current_text = normalize_text(content)
        except Exception as e:
            fetch_failed = True
            failure_note = ("current policy fetch failed: " + str(e))[:MAX_NOTE_LEN]

        if fetch_failed:
            self._append_check(
                pid,
                STATUS_INCONCLUSIVE,
                CLASS_NONE,
                BAND_UNKNOWN,
                "",
                failure_note,
                policy.baseline_hash,
                "",
            )

            return STATUS_INCONCLUSIVE

        result = self._judge_policy_change(policy, current_text)

        self._append_check(
            pid,
            result["status"],
            result["change_class"],
            result["materiality_band"],
            result["triggered_rules_csv"],
            result["note"],
            policy.baseline_hash,
            snapshot_hash(current_text),
        )

        return result["status"]

    @gl.public.write
    def acknowledge_change(self, policy_id: str) -> None:
        require(gl.message.sender_address == self.owner, "only owner")

        pid = (policy_id or "").strip()
        policy = self._read_policy(pid)

        require(self.latest_check_plus_one.get(pid, u256(0)) > u256(0), "no checks yet")

        check_index = int(self.latest_check_plus_one[pid]) - 1
        latest = self.checks[check_index]

        require(latest.status == STATUS_MATERIAL, "latest result is not a material change")

        policy.acknowledged = True

        self._write_policy(pid, policy)

    @gl.public.view
    def policy_count(self) -> u256:
        return u256(len(self.policies))

    @gl.public.view
    def check_count(self) -> u256:
        return u256(len(self.checks))

    @gl.public.view
    def read_policy(self, policy_id: str) -> str:
        pid = (policy_id or "").strip()
        policy = self._read_policy(pid)

        return canonical(
            {
                "policy_id": policy.policy_id,
                "label": policy.label,
                "url": policy.url,
                "host": policy.host,
                "guardrails": policy.guardrails,
                "baseline_captured": bool(policy.baseline_captured),
                "baseline_hash": policy.baseline_hash,
                "created_at": int(policy.created_at),
                "baseline_captured_at": int(policy.baseline_captured_at),
                "acknowledged": bool(policy.acknowledged),
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
                "baseline_hash": record.baseline_hash,
                "current_hash": record.current_hash,
                "checked_at": int(record.checked_at),
            }
        )

    @gl.public.view
    def read_latest_check(self, policy_id: str) -> str:
        pid = (policy_id or "").strip()

        require(self.latest_check_plus_one.get(pid, u256(0)) > u256(0), "no checks for policy")

        check_index = int(self.latest_check_plus_one[pid]) - 1

        return self.read_check(check_index)

    @gl.public.view
    def is_host_allowed(self, host: str) -> bool:
        h = (host or "").strip().lower()
        return self.allowed_hosts.get(h, False) is True

    @gl.public.view
    def get_owner(self) -> Address:
        return self.owner