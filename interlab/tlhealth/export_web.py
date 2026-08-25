#!/usr/bin/env python3
"""Assemble the web instrument's data file from recorded runs.

The published page must not carry numbers that exist only in the page. Everything here is
read back out of the append-only run directories — the transport probe, the freshness reader,
and the pointer crawl — so any figure on the page can be traced to a run file, and a later
run refreshes the page without anyone editing it by hand.

Three rules this file exists to enforce:

  * A node's state comes from the probe run, not from a one-off check somebody ran once.
  * A node's territory comes from a list's own declaration — its SchemeTerritory, or the
    pointer that names it — never from a filename. The Irish list has not answered once in
    this series; it is labelled IE because the LOTL says so.
  * Populations stay separate. The European list and the MERCOSUR list are measured against
    their own denominators, because a merged percentage hides which one a reading came from.

Usage:  python3 export_web.py [--out ../../../tyche-institute-site/public/lab/trust-list-graph/data.json]
"""
from __future__ import annotations
import argparse, collections, glob, json, os, pathlib, sys

HERE = pathlib.Path(__file__).resolve().parent
HUB_EU = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
HUB_MB = "https://validar.iti.gov.br/trustlist/trust-list-MB.xml"
# The EU's second list of lists, for mutual-recognition agreements. Named separately because
# the main LOTL does not mention it, so it is a hub that no crawl arrives at.
HUB_MRA = "https://ec.europa.eu/tools/lotl/mra/ades-lotl.xml"
HUBS = (HUB_EU, HUB_MB, HUB_MRA)

# Class from the probe -> state shown on the page. The page never invents a state.
STATE = {
    "ok": "ok",
    "tls_validation_failed": "tls_validation_failed",
    "transport_failed": "fail",
    "unreachable_timeout": "fail",
    "http_error": "http_error",
    "access_refused": "blocked",
    "other": "fail",
}


def newest(dirname: str) -> dict:
    files = sorted(f for f in glob.glob(str(HERE / dirname / "*.json")) if "latest" not in f)
    if not files:
        sys.exit(f"no runs in {dirname}/ — run the instrument first")
    return json.load(open(files[-1], encoding="utf-8"))


def run_count(dirname: str) -> int:
    return len([f for f in glob.glob(str(HERE / dirname / "*.json")) if "latest" not in f])


def series_window(dirname: str = "runs") -> dict:
    """How long the series actually spans. A run count is not a duration.

    Twenty-seven observations sound like weeks and are, at the time of writing, one night. A
    reader not told the window will assume the flattering reading, so the page states it.
    """
    import datetime
    files = sorted(f for f in glob.glob(str(HERE / dirname / "*.json")) if "latest" not in f)
    if not files:
        return {}
    a = json.load(open(files[0], encoding="utf-8")).get("started_utc")
    b = json.load(open(files[-1], encoding="utf-8")).get("started_utc")
    try:
        ta = datetime.datetime.fromisoformat(a.replace("Z", "+00:00"))
        tb = datetime.datetime.fromisoformat(b.replace("Z", "+00:00"))
        hours = round((tb - ta).total_seconds() / 3600, 1)
    except Exception:
        hours = None
    return {"first": a, "last": b, "hours": hours, "runs": len(files)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(HERE / "graph-data.json"))
    args = ap.parse_args()

    probe = newest("runs")
    fresh = newest("runs-freshness")
    graph = newest("runs-graph")

    # --- what the crawl saw: identity, attribution, structure ----------------
    crawled = {n["url"]: n for n in graph["nodes"]}
    edges = [{"s": e["from"], "d": e["to"]} for e in graph["edges"] if e["from"] != e["to"]]
    outdeg = collections.Counter(e["s"] for e in edges)
    indeg = collections.Counter(e["d"] for e in edges)

    # --- what the probe measured: state --------------------------------------
    measured = {}
    for r in probe["results"]:
        if r["url"].startswith("http"):
            measured[r["url"]] = r

    # --- what a second vantage saw, where this one failed ---------------------
    vantage = {v["url"]: v for v in probe.get("vantage_checks", [])}

    # --- what each list says about its own currency ---------------------------
    freshness = {r["url"]: r for r in fresh["rows"]}

    ids = set(crawled) | set(measured) | set(freshness)
    # Root-programme inventories are not trust lists and are measured for contrast only.
    ids = {u for u in ids if not any(k in u for k in (
        "salesforce-sites", "learn.microsoft.com", "support.apple.com", "gstatic.com/ct",
        "icao.int", "aamva.org", "idmanagement.gov"))}

    nodes = []
    for u in sorted(ids):
        c = crawled.get(u, {})
        m = measured.get(u, {})
        f = freshness.get(u, {})
        terr = c.get("territory") or f.get("territory") or "??"
        state = STATE.get(m.get("class", ""), None)
        if state is None:
            state = "ok" if c.get("fetched") else "fail"
        if u in HUBS:
            state = "hub"
        elif f.get("terminal_next_update"):
            # An empty NextUpdate is the standard's way of saying "never again". The UK entry
            # is frozen one second before the end of the Brexit transition and is correctly
            # terminal; drawing it as a failure would be the instrument misreading compliance.
            state = "terminal"
        elif f.get("state") == "expired" or (f.get("overdue_days") or 0) > 0:
            state = "stale"
        elif state == "ok" and f.get("providers") == 0 and f.get("state") == "current":
            state = "empty"

        mime = c.get("mime")
        nodes.append({
            "id": u,
            "t": terr,
            "label": terr,
            "kind": "pdf" if (mime or "").endswith("pdf") else "xml",
            "mime": mime,
            "state": state,
            "territory_source": c.get("territory_source"),
            "scheme": u.split(":", 1)[0],
            "providers": f.get("providers"),
            "services": f.get("services"),
            "age": f.get("age_days"),
            "next": f.get("next_update"),
            "terminal": f.get("terminal_next_update"),
            "overdue": f.get("overdue_days"),
            "provider_section": f.get("provider_section"),
            "tsl_type": f.get("tsl_type"),
            "http": m.get("http_code"),
            "vantage": ({"there": vantage[u]["there"], "colo": vantage[u].get("there_colo"),
                         "agrees": vantage[u]["agrees"]} if u in vantage else None),
            "in": indeg.get(u, 0),
            "out": outdeg.get(u, 0),
            "bloc": ("pacific_alliance" if f.get("group") == "pacific_alliance" else None),
            "hub_role": ("eu_lotl" if u == HUB_EU else "eu_mra" if u == HUB_MRA
                         else "mercosur" if u == HUB_MB else None),
            "zip_wrapped": f.get("zip_wrapped"),
        })

    keep = {n["id"] for n in nodes}
    edges = [e for e in edges if e["s"] in keep and e["d"] in keep]

    # Edges a list declares but no crawl can find. The Pacific Alliance publishes its four
    # national lists as zip attachments on a ministry page, so nothing can be followed TO
    # them; each of them, though, declares a pointer OUT - naming an ec.europa.eu address as
    # the list of lists for territory "AP". The redirect target is the EU LOTL. Drawn because
    # it was read out of the retrieved documents, and because an unreciprocated pointer into
    # another bloc's hub is exactly the kind of thing a picture should not hide.
    LOTL_ALIASES = {HUB_EU,
                    "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml"}
    have = {(e["s"], e["d"]) for e in edges}
    for u, f in freshness.items():
        if u not in keep:
            continue
        for d in (f.get("declares_pointers") or []):
            tgt = HUB_EU if d.get("location") in LOTL_ALIASES else d.get("location")
            if tgt in keep and (u, tgt) not in have and u != tgt:
                edges.append({"s": u, "d": tgt, "declared_only": True})
                have.add((u, tgt))

    # --- the counts the page quotes, computed here and only here --------------
    eu_kids = [e["d"] for e in edges if e["s"] == HUB_EU]
    by_id = {n["id"]: n for n in nodes}
    eu_xml = [k for k in eu_kids if by_id[k]["kind"] == "xml" and k != HUB_EU]
    eu_pdf = [k for k in eu_kids if by_id[k]["kind"] == "pdf"]
    # "Answers" is a transport question. A list that is stale, terminal, or names nobody has
    # still answered; folding those into the same number would let a freshness problem be read
    # as an unreachable server, which is the confusion this instrument exists to separate.
    NOT_ANSWERING = {"fail", "tls_validation_failed", "http_error", "blocked"}
    eu_xml_ok = [k for k in eu_xml if by_id[k]["state"] not in NOT_ANSWERING]
    mb_kids = [e["d"] for e in edges if e["s"] == HUB_MB]
    mb_ok = [k for k in mb_kids if by_id[k]["state"] not in NOT_ANSWERING]
    plain_http = [n["id"] for n in nodes if n["scheme"] == "http" and n["kind"] == "xml"]

    facts = {
        "eu_pointers_total": len([e for e in edges if e["s"] == HUB_EU]) + 1,  # + the self-pointer
        "eu_machine_lists": len(eu_xml),
        "eu_machine_lists_answering": len(eu_xml_ok),
        "eu_pdf_copies": len(eu_pdf),
        "mb_national_pointers": len(mb_kids),
        "mb_national_answering": len(mb_ok),
        "hub_to_hub_edges": len([e for e in edges
                                 if {e["s"], e["d"]} == {HUB_EU, HUB_MB}]),
        "pointers_declared_over_plain_http": plain_http,
        "islands": [n["t"] for n in nodes if n["in"] == 0 and n["state"] != "hub"],
        "eu_has_two_hubs": {
            "main_lotl_pointers": len([e for e in edges if e["s"] == HUB_EU]),
            "mra_lotl_pointers": len([e for e in edges if e["s"] == HUB_MRA]),
            "mra_targets": [by_id[e["d"]]["t"] for e in edges if e["s"] == HUB_MRA],
            "main_mentions_mra": any(e["s"] == HUB_EU and e["d"] == HUB_MRA for e in edges),
        },
        "runs_in_series": run_count("runs"),
        "series_window": series_window(),
        "pacific_alliance": [{"t": n["t"], "overdue": n["overdue"], "state": n["state"]}
                             for n in nodes if n.get("bloc") == "pacific_alliance"],
        "vantage_disagreements": [{"t": by_id[u]["t"], "here": v["here"], "there": v["there"]}
                                  for u, v in vantage.items()
                                  if u in by_id and not v["agrees"]],
        "vantage_agreements": [{"t": by_id[u]["t"], "code": v["there"]}
                               for u, v in vantage.items()
                               if u in by_id and v["agrees"]],
    }

    out = {
        "instrument": "tlhealth/export_web.py",
        "observed": probe.get("finished_utc") or probe.get("started_utc"),
        "graph_observed": graph.get("observed_utc"),
        "freshness_observed": fresh.get("observed_utc"),
        "runs": run_count("runs"),
        "caveat": ("One vantage point, one moment. A pointer recorded as not answering could "
                   "not be retrieved from here; an endpoint recorded as refusing declined this "
                   "client specifically, which a single vantage cannot distinguish from "
                   "declining everyone."),
        "facts": facts,
        "nodes": nodes,
        "edges": edges,
    }
    pathlib.Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(args.out).write_text(json.dumps(out, indent=1, sort_keys=True), encoding="utf-8")
    print(f"wrote {args.out}: nodes={len(nodes)} edges={len(edges)} runs={out['runs']}")
    for k, v in facts.items():
        print(f"   {k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
