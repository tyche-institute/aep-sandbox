#!/usr/bin/env python3
"""Trusted-List Health — transport-layer probe over published trust-list pointers.

Measures what nobody is assigned to check: whether the endpoints that trust
infrastructure points at can actually be reached by a strict TLS client.

Design rules (Tyche Labs):
  * classifier first — what counts as "should resolve" is declared here, in code,
    before any percentage is published;
  * every run is dated, hashed and append-only; no run is ever rewritten;
  * failures are recorded with the observed error, never interpreted as vulnerabilities;
  * the EU List of Trusted Lists is the seed; other jurisdictions are added as
    separate, clearly-labelled populations, never silently merged into an EU number.

Usage:  python3 probe.py [--out DIR]
"""
from __future__ import annotations
import argparse, datetime, hashlib, json, pathlib, re, subprocess, sys
import concurrent.futures as cf
import time

LOTL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
TIMEOUT = 25
RETRIES = 1        # one retry before a transport failure is recorded as such
WORKERS = 3        # deliberately gentle: a probe must not manufacture its own failures

# --- population definitions -------------------------------------------------
# Each population is measured and reported separately. Merging them would make
# the headline number depend on an unstated choice.
POPULATIONS = {
    "eu_lotl_pointers": "TSLLocation pointers inside the live EU List of Trusted Lists",
    "global_root_programmes": "Publicly published root-programme inventories",
    "other_jurisdictions": "National trust artefacts outside the EU/EEA (curated)",
    "mercosur_pointers": "National pointers declared by the MERCOSUR regional list of lists",
    "mercosur_copies": "Copies of the MERCOSUR regional list of lists, published across three states",
}

# The Americas publish a regional list of lists in the same ETSI format. It is measured as its
# own population and never merged with the European one: the two differ in scale by an order of
# magnitude, and a combined percentage would hide which of them a reading came from.
# The national pointers are exactly the four the regional list declares, transcribed from it
# rather than reconstructed. An earlier version of this file carried a Uruguayan URL we had
# guessed; it returned 404, and that 404 was ours, not Uruguay's. The declared Uruguayan
# pointer answers — over plain HTTP, which is a separate and real observation.
MERCOSUR = {
    "mb_ar": "https://pki.jgm.gov.ar/TSL/tsl-AR.xml",
    "mb_br": "https://validar.iti.gov.br/trustlist/trust-list-BR.xml",
    "mb_py": "https://www.acraiz.gov.py/tsl/tsl_Py.xml",
    "mb_uy": "http://www.gub.uy/unidad-certificacion-electronica/sites/unidad-certificacion-electronica/files/tsl/tsl_uy.xml",
}

# Four copies of the regional list of lists are published across three states. They are
# measured as their own population because the question they answer is not "does it answer"
# but "do the copies agree" — on 25.08.2026 three of them were byte-identical at a sequence
# that lapsed 110 days earlier, and one was current.
MERCOSUR_COPIES = {
    "mb_copy_br": "https://validar.iti.gov.br/trustlist/trust-list-MB.xml",
    "mb_copy_ar_upper": "https://pki.jgm.gov.ar/TSL/TSL-MB.xml",
    "mb_copy_ar_lower": "https://pki.jgm.gov.ar/TSL/tsl-MB.xml",
    "mb_copy_uy": "http://www.gub.uy/unidad-certificacion-electronica/sites/unidad-certificacion-electronica/files/tsl/tsl_mb.xml",
}

GLOBAL_ROOTS = {
    "mozilla_included_ca_csv": "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV",
    "microsoft_participants": "https://learn.microsoft.com/en-us/security/trusted-root/participants-list",
    "apple_root_programme": "https://support.apple.com/en-us/103272",
    "ct_log_list_google": "https://www.gstatic.com/ct/log_list/v3/log_list.json",
}

OTHER_JURISDICTIONS = {
    "us_fpki_documented": "https://fpki.idmanagement.gov/",
    "us_fpki_working": "https://www.idmanagement.gov/fpki/",
    "icao_pkd": "https://www.icao.int/Security/FAL/PKD/Pages/default.aspx",
    "aamva_dts": "https://www.aamva.org/technology/systems/identity-management-systems/digital-trust-service",
    # Added 25.08.2026, so the denominator of this population changes at that date. Recorded
    # rather than backfilled: the run files before it measured four endpoints, not five.
    "ru_gosuslugi_tsl": "https://e-trust.gosuslugi.ru/CA/DownloadTSL?schemaVersion=0",
}


def curl_once(url: str) -> dict:
    """One strict-client observation. Never follows into a different scheme."""
    fmt = "%{http_code} %{ssl_verify_result} %{size_download} %{num_redirects} %{url_effective}"
    try:
        r = subprocess.run(
            ["curl", "-sSL", "-o", "/dev/null", "-m", str(TIMEOUT), "-w", fmt, url],
            capture_output=True, text=True, timeout=TIMEOUT + 15)
        parts = (r.stdout or "").split(" ", 4)
        while len(parts) < 5:
            parts.append("")
        err = (r.stderr or "").strip().splitlines()
        return {
            "http_code": parts[0], "ssl_verify_result": parts[1],
            "bytes": parts[2], "redirects": parts[3], "final_url": parts[4],
            "curl_error": err[-1][:160] if r.returncode else "",
            "curl_exit": r.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"http_code": "TIMEOUT", "ssl_verify_result": "", "bytes": "",
                "redirects": "", "final_url": "", "curl_error": "timeout", "curl_exit": -1}


def curl(url: str) -> dict:
    """Observe, and retry a transport failure once before believing it.

    Rationale (recorded 2026-08-25): the first run of this instrument reported two
    Hungarian endpoints as timing out. They were not down - eight parallel workers
    were. An instrument that manufactures its own failures is worse than no
    instrument, so transport failures are retried once and the attempt count is
    published rather than hidden.
    """
    obs = curl_once(url)
    attempts = 1
    while attempts <= RETRIES and obs["curl_exit"] != 0 and obs["ssl_verify_result"] in ("0", ""):
        time.sleep(2)
        obs = curl_once(url)
        attempts += 1
    obs["attempts"] = attempts
    return obs


def classify(obs: dict) -> str:
    """The published classifier. Declared before any percentage is computed."""
    if obs["http_code"] == "TIMEOUT":
        return "unreachable_timeout"
    if obs["curl_exit"] != 0 and obs["ssl_verify_result"] not in ("0", ""):
        return "tls_validation_failed"
    if obs["curl_exit"] != 0:
        return "transport_failed"
    if obs["http_code"].startswith("2"):
        return "ok"
    # Added 25.08.2026. A server that answers 401/403/451 has understood the request and
    # declined it; one that answers 404 or 500 is failing to serve what it published. Both
    # were "http_error" until this date, and calling a refusal a breakage overstates what a
    # single vantage point can support: we cannot tell "refused everyone" from "refused us".
    if obs["http_code"] in ("401", "403", "451"):
        return "access_refused"
    if obs["http_code"].startswith(("4", "5")):
        return "http_error"
    return "other"


def fetch_lotl_pointers() -> tuple[list[str], str]:
    r = subprocess.run(["curl", "-sS", "-m", "40", LOTL], capture_output=True, timeout=70)
    raw = r.stdout.decode("utf-8", "ignore")
    pointers = sorted(set(re.findall(r"<TSLLocation>(https?://[^<]+)</TSLLocation>", raw)))
    return pointers, hashlib.sha256(r.stdout).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(pathlib.Path(__file__).resolve().parent / "runs"))
    args = ap.parse_args()
    out = pathlib.Path(args.out); out.mkdir(parents=True, exist_ok=True)

    started = datetime.datetime.now(datetime.timezone.utc)
    pointers, lotl_hash = fetch_lotl_pointers()

    targets = [("eu_lotl_pointers", u, u) for u in pointers]
    targets += [("global_root_programmes", k, v) for k, v in GLOBAL_ROOTS.items()]
    targets += [("other_jurisdictions", k, v) for k, v in OTHER_JURISDICTIONS.items()]
    targets += [("mercosur_pointers", k, v) for k, v in MERCOSUR.items()]
    targets += [("mercosur_copies", k, v) for k, v in MERCOSUR_COPIES.items()]

    results = []
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(curl, url): (pop, name, url) for pop, name, url in targets}
        for f in cf.as_completed(futs):
            pop, name, url = futs[f]
            obs = f.result()
            results.append({"population": pop, "name": name, "url": url,
                            "class": classify(obs), **obs})
    results.sort(key=lambda r: (r["population"], r["name"]))

    summary = {}
    for pop in POPULATIONS:
        rows = [r for r in results if r["population"] == pop]
        counts: dict[str, int] = {}
        for r in rows:
            counts[r["class"]] = counts.get(r["class"], 0) + 1
        summary[pop] = {"total": len(rows), "by_class": counts}

    run = {
        "instrument": "tlhealth",
        "schema": 1,
        "started_utc": started.isoformat(),
        "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "lotl_url": LOTL,
        "lotl_sha256": lotl_hash,
        "populations": POPULATIONS,
        "classifier": "see classify() in probe.py; published before any percentage",
        "retry_policy": f"transport failures retried {RETRIES}x at {WORKERS} workers; attempts recorded per row",
        "caveat": ("Transport-layer reachability under a strict TLS client only. "
                   "Not signature validation, not supervision, not a conformity assessment, "
                   "and not a vulnerability assessment."),
        "summary": summary,
        "results": results,
    }
    stamp = started.strftime("%Y-%m-%dT%H-%M-%SZ")
    path = out / f"{stamp}.json"
    payload = json.dumps(run, indent=1, sort_keys=True) + "\n"
    path.write_text(payload, encoding="utf-8")
    (out / "latest.json").write_text(payload, encoding="utf-8")

    print(f"run {stamp}  sha256={hashlib.sha256(payload.encode()).hexdigest()[:16]}")
    for pop, s in summary.items():
        print(f"  {pop:26s} n={s['total']:3d}  {s['by_class']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
