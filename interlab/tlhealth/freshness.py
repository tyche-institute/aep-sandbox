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
            # surrogateescape, not ignore: a zip-wrapped list must survive the round trip to
            # bytes, and "ignore" drops the bytes it cannot decode without saying so.
            return r.stdout.decode("utf-8", "surrogateescape"), ""
        if attempt == 1:
            time.sleep(2)
    return "", (r.stderr or b"").decode("utf-8", "ignore").strip().splitlines()[-1][:120] if r.stderr else "fetch failed"


def unwrap_zip(raw: str) -> str:
    """Some publishers ship the list inside a zip. Unwrap so the same fields are read.

    The Alianza del Pacifico bloc publishes its four national lists as zip attachments on a
    ministry page rather than at a followable TSLLocation, which is why a pointer crawl cannot
    reach them at all - the fact that they need unwrapping is itself part of the finding.
    """
    if not raw.startswith("PK\x03\x04"):
        return raw
    import io, zipfile
    try:
        z = zipfile.ZipFile(io.BytesIO(raw.encode("utf-8", "surrogateescape")))
        for n in z.namelist():
            inner = z.read(n).decode("utf-8", "ignore")
            if "TrustServiceStatusList" in inner:
                return inner
    except Exception:
        pass
    return raw


def parse(url: str) -> dict:
    raw, err = fetch(url)
    out = {"url": url, "fetch_error": err}
    if not raw:
        out["state"] = "unfetchable"
        return out
    raw = unwrap_zip(raw)
    out["zip_wrapped"] = url.lower().endswith(".zip")
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
    # "Names no providers" and "carries no provider section at all" are different statements
    # about a list, and only the second is true of Moldova's. Recorded separately so the
    # published wording can be the accurate one.
    out["provider_section"] = bool(re.search(r"<(?:\w+:)?TrustServiceProviderList", raw))
    out["tsl_type"] = (m.group(1) if (m := re.search(r"<(?:\w+:)?TSLType>([^<]+)</", raw)) else None)
    out["pointers_out"] = len(re.findall(r"<(?:\w+:)?TSLLocation>", raw))
    # Recorded so an edge can be drawn from what the document declares rather than from
    # anybody's memory of it. The Pacific Alliance lists reach the graph only this way: they
    # are zip attachments on a web page, so no pointer crawl can arrive at them.
    out["declares_pointers"] = [
        {"location": loc, "territory": (ter[0].strip() if ter else None)}
        for loc, ter in (
            (re.search(r"<(?:\w+:)?TSLLocation>([^<]+)</", b).group(1).strip(),
             re.findall(r"SchemeTerritory\"[^>]*>\s*<(?:\w+:)?String[^>]*>([^<]+)</", b)
             or re.findall(r"<(?:\w+:)?SchemeTerritory>([^<]+)</", b))
            for b in re.findall(r"<(?:\w+:)?OtherTSLPointer>(.*?)</(?:\w+:)?OtherTSLPointer>", raw, re.S)
            if re.search(r"<(?:\w+:)?TSLLocation>([^<]+)</", b)
        )
    ]

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

    # The four published copies of the MERCOSUR regional list. Read here because the question
    # they raise is one of declared currency, not reachability: all four answer, and on
    # 25.08.2026 three of them were a sequence that had lapsed 110 days earlier. A signature
    # does not carry freshness, so nothing but this field distinguishes them.
    extra = [
        "https://validar.iti.gov.br/trustlist/trust-list-MB.xml",
        "https://pki.jgm.gov.ar/TSL/TSL-MB.xml",
        "https://pki.jgm.gov.ar/TSL/tsl-MB.xml",
        "http://www.gub.uy/unidad-certificacion-electronica/sites/unidad-certificacion-electronica/files/tsl/tsl_mb.xml",
    ]
    # Lists no hub points at. They are read for the same fields as everything else, because
    # "nobody points at it" is a statement about the graph and says nothing about whether the
    # artefact is current — and the difference between those two is the whole point.
    islands = [
        "https://czo.gov.ua/download/tl/TL-UA.xml",
        "https://tl.ico.org.uk/uktrustedlist/UKTL.xml",
        "https://trustedlist.tsl-switzerland.ch/tsl-ch.xml",
        "https://www.mit.gov.rs/TrustedList/TSL-RS.xml",
        "https://tl.gov.me/ME_TL.xml",
        "https://sis.md/sites/default/files/MD-TL/MD-TL.xml",
        "https://pki.jgm.gov.ar/TSL/tsl-CL.xml",
    ]
    extra += islands

    # The Pacific Alliance bloc: zip-wrapped, no followable hub, and every list years overdue.
    pacific = [
        "https://cdn.www.gob.pe/uploads/document/file/541707/TSL-PERU.xml.zip",
        "https://cdn.www.gob.pe/uploads/document/file/541708/TSL-COLOMBIA.xml.zip",
        "https://cdn.www.gob.pe/uploads/document/file/541709/TSL-CHILE.xml.zip",
        "https://cdn.www.gob.pe/uploads/document/file/541710/TSL-MEXICO.xml.zip",
    ]
    extra += pacific

    rows = []
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for row in ex.map(parse, xml_pointers + extra):
            rows.append(row)
    for row in rows:
        row["group"] = ("pacific_alliance" if row["url"] in pacific
                        else "islands" if row["url"] in islands
                        else "mercosur_copies" if row["url"] in extra
                        else "eu_lotl_pointers")
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
