#!/usr/bin/env python3
"""Trust-list graph — who points at whom, followed transitively.

The EU List of Trusted Lists is usually read as a star: one hub, many national lists. It is
not. National lists carry PointersToOtherTSL of their own, and some of those edges leave the
EU entirely. Serbia points at Montenegro; Montenegro points only back at Serbia and never at
the EU hub at all, so Montenegro's trust graph reaches Brussels solely through Belgrade.

Nobody publishes this graph. This walks it: start at the EU list of lists, follow every
TSLLocation, and follow the pointers those lists carry, to a bounded depth. It records the
edges, not a judgement about them.
"""
from __future__ import annotations
import datetime, json, pathlib, re, subprocess, sys, time

MAX_DEPTH = 3
TIMEOUT = 30
SEEDS = {
    "https://ec.europa.eu/tools/lotl/eu-lotl.xml": "EU list of lists",
    # The EU publishes a SECOND list of lists, for mutual-recognition agreements, and the
    # first one does not mention it. Seeded because a crawl that starts at the famous hub
    # never arrives here, which is exactly why we recorded Moldova and Ukraine as lists
    # nobody points at. They are pointed at - from a hub almost nobody knows exists.
    "https://ec.europa.eu/tools/lotl/mra/ades-lotl.xml": "EU MRA list of lists",
}
# Non-EU lists discovered by census; included as seeds so the walk can find edges the EU
# hub does not reach. Each is a published national artefact, fetched as any client would.
SEEDS.update({
    "https://czo.gov.ua/download/tl/TL-UA.xml": "Ukraine",
    "https://tl.ico.org.uk/uktrustedlist/UKTL.xml": "United Kingdom",
    "https://trustedlist.tsl-switzerland.ch/tsl-ch.xml": "Switzerland",
    "https://www.mit.gov.rs/TrustedList/TSL-RS.xml": "Serbia",
    "https://tl.gov.me/ME_TL.xml": "Montenegro",
    "https://sis.md/sites/default/files/MD-TL/MD-TL.xml": "Moldova",
    # A second regional list of lists, in the same ETSI format, that no European document
    # mentions. Seeded so the walk can find a hub the EU hub cannot reach.
    "https://validar.iti.gov.br/trustlist/trust-list-MB.xml": "MERCOSUR (Brazilian copy)",
    "https://pki.jgm.gov.ar/TSL/TSL-MB.xml": "MERCOSUR (Argentine copy)",
    "https://e-trust.gosuslugi.ru/CA/DownloadTSL?schemaVersion=0": "Russia",
    "https://czo.gov.ua/download/tl/TL-UA-EC.xml": "Ukraine (EU-facing list)",
    "https://trusteid.mdt.gov.mk/tl/TL_MK.xml": "North Macedonia",
    # Added 25.08.2026 from the worldwide survey, each confirmed by an independent verifier as
    # a machine-readable national list. Seeded so the walk reaches trust infrastructure that no
    # European or MERCOSUR hub declares - the Americas beyond the two blocs already mapped.
    "https://onac.org.co/certificados/tsl/tsl-co.xml": "Colombia (national accreditation body)",
    "https://applin.indotel.gob.do/tsl/tsl.xml": "Dominican Republic",
    "http://acraiz.icpbrasil.gov.br/tsl/LPSC.xml": "Brazil (ICP-Brasil root authority)",
})

# Where a list cannot be fetched and nothing points at it, the territory cannot be taken from
# a declaration. These are stated as ours, and marked as such in the export, so that a label
# we asserted is never mistaken for one a publisher declared.
SEED_TERRITORY = {
    "https://czo.gov.ua/download/tl/TL-UA.xml": "UA",
    "https://tl.ico.org.uk/uktrustedlist/UKTL.xml": "UK",
    "https://trustedlist.tsl-switzerland.ch/tsl-ch.xml": "CH",
    "https://www.mit.gov.rs/TrustedList/TSL-RS.xml": "RS",
    "https://tl.gov.me/ME_TL.xml": "ME",
    "https://sis.md/sites/default/files/MD-TL/MD-TL.xml": "MD",
    "https://validar.iti.gov.br/trustlist/trust-list-MB.xml": "MB",
    "https://pki.jgm.gov.ar/TSL/TSL-MB.xml": "MB",
    "https://e-trust.gosuslugi.ru/CA/DownloadTSL?schemaVersion=0": "RU",
    "https://trusteid.mdt.gov.mk/tl/TL_MK.xml": "MK",
    "https://onac.org.co/certificados/tsl/tsl-co.xml": "CO",
    "https://applin.indotel.gob.do/tsl/tsl.xml": "DO",
    "http://acraiz.icpbrasil.gov.br/tsl/LPSC.xml": "BR",
}


def fetch(url: str) -> str:
    for attempt in (1, 2):
        r = subprocess.run(["curl", "-sSL", "-m", str(TIMEOUT), url],
                           capture_output=True, timeout=TIMEOUT + 20)
        if r.returncode == 0 and r.stdout:
            return r.stdout.decode("utf-8", "ignore")
        if attempt == 1:
            time.sleep(2)
    return ""


def territory(raw: str) -> str | None:
    m = re.search(r"<(?:\w+:)?SchemeTerritory>([^<]+)</", raw)
    return m.group(1) if m else None


def pointers(raw: str) -> list[str]:
    return sorted(set(re.findall(r"<(?:\w+:)?TSLLocation>(https?://[^<]+)</", raw)))


def declarations(raw: str) -> dict[str, dict]:
    """What a list says about each pointer it publishes.

    Every OtherTSLPointer carries the territory and the media type of the artefact it points
    at. Reading them here means a pointer we cannot fetch is still attributed correctly: the
    Irish list has not answered once in this series, and the only reason we can label it IE
    is that the LOTL says so. Guessing the territory from the filename would be our inference
    presented as the publisher's statement.
    """
    out: dict[str, dict] = {}
    for b in re.findall(r"<(?:\w+:)?OtherTSLPointer>(.*?)</(?:\w+:)?OtherTSLPointer>", raw, re.S):
        loc = re.search(r"<(?:\w+:)?TSLLocation>(https?://[^<]+)</", b)
        if not loc:
            continue
        ter = (re.findall(r"SchemeTerritory\"[^>]*>\s*<(?:\w+:)?String[^>]*>([^<]+)</", b)
               or re.findall(r"<(?:\w+:)?SchemeTerritory>([^<]+)</", b))
        mime = re.findall(r"MimeType[^>]*>([^<]+)<", b)
        out[loc.group(1)] = {"territory": ter[0].strip() if ter else None,
                             "mime": mime[0].strip() if mime else None}
    return out


def main() -> int:
    seen: dict[str, dict] = {}
    edges: list[dict] = []
    frontier = [(u, 0) for u in SEEDS]

    declared: dict[str, dict] = {}   # what some list said about a pointer, by URL

    while frontier:
        url, depth = frontier.pop(0)
        if url in seen or depth > MAX_DEPTH:
            continue
        raw = fetch(url)
        said = declared.get(url, {})
        node = {"url": url, "depth": depth, "fetched": bool(raw),
                "territory": ((territory(raw) if raw else None) or said.get("territory")
                              or SEED_TERRITORY.get(url)),
                "territory_source": ("self" if (raw and territory(raw))
                                     else "declared_by_pointer" if said.get("territory")
                                     else "asserted_by_us" if SEED_TERRITORY.get(url) else None),
                "mime": said.get("mime"),
                "is_tsl": bool(re.search(r"<(?:\w+:)?TrustServiceStatusList", raw)) if raw else False,
                "seed_label": SEEDS.get(url)}
        seen[url] = node
        if not raw:
            continue
        for loc, said_about in declarations(raw).items():
            declared.setdefault(loc, said_about)
            if loc in seen and seen[loc]["territory"] is None:
                seen[loc].update(territory=said_about.get("territory"),
                                 territory_source="declared_by_pointer",
                                 mime=said_about.get("mime"))
            elif loc in seen and seen[loc].get("mime") is None:
                seen[loc]["mime"] = said_about.get("mime")
        for target in pointers(url and raw):
            edges.append({"from": url, "from_territory": node["territory"], "to": target})
            if target not in seen:
                frontier.append((target, depth + 1))

    # a node is "known to the EU hub" if the hub or one of its direct children points at it
    hub = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
    hub_targets = {e["to"] for e in edges if e["from"] == hub}
    non_hub_edges = [e for e in edges if e["from"] != hub and e["to"] not in hub_targets
                     and e["to"] != hub]

    out = {
        "instrument": "tlgraph", "schema": 1,
        "observed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "max_depth": MAX_DEPTH,
        "caveat": ("Edges as published, followed as a client would. Presence of an edge is not "
                   "a claim about legal recognition between the parties."),
        "summary": {
            "nodes": len(seen),
            "fetched": sum(1 for n in seen.values() if n["fetched"]),
            "edges": len(edges),
            "edges_not_from_the_eu_hub": len(non_hub_edges),
            "territories": sorted({n["territory"] for n in seen.values() if n["territory"]}),
        },
        "nodes": sorted(seen.values(), key=lambda n: (n["territory"] or "zz", n["url"])),
        "edges": edges,
    }
    d = pathlib.Path(__file__).resolve().parent / "runs-graph"
    d.mkdir(exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    payload = json.dumps(out, indent=1, sort_keys=True) + "\n"
    (d / f"{stamp}.json").write_text(payload, encoding="utf-8")
    (d / "latest.json").write_text(payload, encoding="utf-8")

    s = out["summary"]
    print(f"nodes={s['nodes']} fetched={s['fetched']} edges={s['edges']}")
    print(f"territories seen: {' '.join(s['territories'])}")
    print(f"edges NOT originating at the EU hub: {s['edges_not_from_the_eu_hub']}")
    for e in non_hub_edges:
        print(f"   {str(e['from_territory']):4s} → {e['to'][:76]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
