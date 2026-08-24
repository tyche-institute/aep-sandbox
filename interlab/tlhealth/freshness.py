#!/usr/bin/env python3
"""Trusted-List Freshness — the second dimension: is the list current, and does it say so?

Reachability tells you the artefact can be fetched. It says nothing about whether the
artefact is still meant to be believed. ETSI TS 119 612 gives a list two ways to speak
about its own currency: ListIssueDateTime, and NextUpdate — where an EMPTY NextUpdate
element is the standard's way of saying "this list will not be updated again".

NOTE (2026-08-25): the first version of this probe matched unprefixed element names only,
and so misread every list that uses a namespace prefix such as tsl:TrustServiceStatusList -
Hungary's, for one. Recorded rather than quietly corrected: a detector that assumes one
serialisation of the same standard produces confident, wrong counts.

This probe reads both, for every XML pointer in the EU List of Trusted Lists, and reports:
  * how old each list is,
  * whether it has passed its own declared NextUpdate,
  * and whether it is terminal (empty NextUpdate).

It makes no judgement about whether a stale list is wrong. A list can be legitimately old,
and a terminal list is correctly terminal - the United Kingdom's entry, frozen one second
before the end of the Brexit transition, is marked terminal exactly as the standard intends.
What is unmeasured, and what this exists to expose, is whether anything downstream honours
those signals.
"""
from __future__ import annotations
import datetime, json, pathlib, re, subprocess, sys, time
import concurrent.futures as cf

LOTL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
WORKERS, TIMEOUT = 3, 30
NOW = datetime.datetime.now(datetime.timezone.utc)


def fetch(url: str) -> tuple[str, str]:
    for attempt in (1, 2):
        r = subprocess.run(["curl", "-sSL", "-m", str(TIMEOUT), url],
                           capture_output=True, timeout=TIMEOUT + 20)
        if r.returncode == 0 and r.stdout:
            return r.stdout.decode("utf-8", "ignore"), ""
        if attempt == 1:
            time.sleep(2)
    return "", (r.stderr or b"").decode("utf-8", "ignore").strip().splitlines()[-1][:120] if r.stderr else "fetch failed"


def parse(url: str) -> dict:
    raw, err = fetch(url)
    out = {"url": url, "fetch_error": err}
    if not raw:
        out["state"] = "unfetchable"
        return out
    if not re.search(r"<(?:\w+:)?TrustServiceStatusList", raw) and "TSLTag" not in raw:
        out["state"] = "not_a_tsl"          # PDF or other human-readable artefact
        return out

    issued = re.search(r"<(?:\w+:)?ListIssueDateTime>([^<]+)</", raw)
    terminal = bool(re.search(r"<(?:\w+:)?NextUpdate\s*/>", raw))
    nxt = re.search(r"<(?:\w+:)?NextUpdate[^>]*>\s*<(?:\w+:)?dateTime[^>]*>([^<]+)</", raw)
    territory = re.search(r"<(?:\w+:)?SchemeTerritory>([^<]+)</", raw)
    seq = re.search(r"<(?:\w+:)?TSLSequenceNumber>([^<]+)</", raw)

    out["territory"] = territory.group(1) if territory else None
    out["sequence"] = seq.group(1) if seq else None
    out["providers"] = len(re.findall(r"<(?:\w+:)?TSPName>", raw))
    out["services"] = len(re.findall(r"<(?:\w+:)?ServiceTypeIdentifier>", raw))
    out["terminal_next_update"] = terminal

    if issued:
        t = datetime.datetime.fromisoformat(issued.group(1).replace("Z", "+00:00"))
        out["issued"] = issued.group(1)
        out["age_days"] = (NOW - t).days
    if nxt:
        n = datetime.datetime.fromisoformat(nxt.group(1).replace("Z", "+00:00"))
        out["next_update"] = nxt.group(1)
        out["overdue_days"] = max(0, (NOW - n).days)

    if terminal:
        out["state"] = "terminal_declared"
    elif "overdue_days" in out and out["overdue_days"] > 0:
        out["state"] = "past_declared_next_update"
    elif "next_update" in out:
        out["state"] = "current"
    else:
        out["state"] = "no_next_update_declared"
    return out


def main() -> int:
    r = subprocess.run(["curl", "-sS", "-m", "40", LOTL], capture_output=True, timeout=70)
    raw = r.stdout.decode("utf-8", "ignore")
    xml_pointers = sorted({u for u in re.findall(r"<TSLLocation>(https?://[^<]+)</TSLLocation>", raw)
                           if u.lower().split("?")[0].endswith(".xml")})

    rows = []
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for row in ex.map(parse, xml_pointers):
            rows.append(row)
    rows.sort(key=lambda x: (x.get("territory") or "zz", x["url"]))

    states: dict[str, int] = {}
    for row in rows:
        states[row["state"]] = states.get(row["state"], 0) + 1

    run = {
        "instrument": "tlfreshness", "schema": 1,
        "observed_utc": NOW.isoformat(),
        "source": LOTL,
        "caveat": ("Declared currency only. A stale list is not necessarily a wrong list, and a "
                   "terminal list is correctly terminal. This measures what the artefacts say "
                   "about themselves, not whether anyone downstream honours it."),
        "summary": {"xml_pointers": len(rows), "by_state": states},
        "rows": rows,
    }
    out = pathlib.Path(__file__).resolve().parent / "runs-freshness"
    out.mkdir(exist_ok=True)
    stamp = NOW.strftime("%Y-%m-%dT%H-%M-%SZ")
    payload = json.dumps(run, indent=1, sort_keys=True) + "\n"
    (out / f"{stamp}.json").write_text(payload, encoding="utf-8")
    (out / "latest.json").write_text(payload, encoding="utf-8")

    print(f"freshness {stamp}: {len(rows)} XML pointers")
    for k, v in sorted(states.items()):
        print(f"   {k:28s} {v}")
    oldest = sorted((r for r in rows if "age_days" in r), key=lambda r: -r["age_days"])[:6]
    print("   oldest:")
    for r in oldest:
        print(f"      {str(r.get('territory')):4s} {r['age_days']:5d}d  {r['state']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
