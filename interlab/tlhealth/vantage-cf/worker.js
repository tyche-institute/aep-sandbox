/**
 * A second, declared vantage point for the trusted-list observatory.
 *
 * The instrument measures from one host in Estonia. Some endpoints answer that host and some
 * refuse it, and from a single place those are indistinguishable from "answers everyone" and
 * "refuses everyone". This worker exists to tell them apart by asking from somewhere else and
 * publishing both answers.
 *
 * It is deliberately NOT a proxy:
 *   * it will only fetch URLs on a fixed allowlist — the artefacts the observatory already
 *     measures, and nothing else, so it cannot be used to reach anything on our behalf;
 *   * it identifies itself and links to the page explaining what it is, so an operator who
 *     sees the request can find out who we are and tell us to stop;
 *   * it returns the observation, never the fetched document, so it cannot be used to pull
 *     content that an operator has decided not to serve to someone.
 *
 * Routing around an access decision would destroy the measurement anyway: a result obtained by
 * evading a block is not a description of what a client sees.
 */
const UA = "TycheLabs-TrustedListObservatory/1.0 (+https://tyche.institute/lab/trust-list-graph/)";

const ALLOW = new Set([
  "https://e-trust.gosuslugi.ru/CA/DownloadTSL?schemaVersion=0",
  "https://eidas.gov.ie/Irelandtslsignedv6.xml",
  "https://www.acraiz.gov.py/tsl/tsl_Py.xml",
  "https://fpki.idmanagement.gov/",
  "http://tl.nbu.gov.sk/kca/tsl/tsl.xml",
  "https://ec.europa.eu/tools/lotl/eu-lotl.xml",
  "https://validar.iti.gov.br/trustlist/trust-list-MB.xml",
]);

export default {
  async fetch(request) {
    const u = new URL(request.url);
    if (u.pathname === "/allow")
      return json({ allow: [...ALLOW], ua: UA });
    if (u.pathname !== "/probe")
      return json({ what: "A declared second vantage point for the Tyche Labs trusted-list "
        + "observatory. It fetches only a fixed allowlist of published trust artefacts and "
        + "returns the observation, not the document. https://tyche.institute/lab/trust-list-graph/" });

    const target = u.searchParams.get("url");
    if (!target) return json({ error: "no url" }, 400);
    if (!ALLOW.has(target)) return json({ error: "not on the allowlist", target }, 403);

    const started = Date.now();
    try {
      const r = await fetch(target, {
        method: "GET",
        headers: { "User-Agent": UA, "Accept": "*/*" },
        redirect: "follow",
        cf: { cacheTtl: 0, cacheEverything: false },
      });
      // Read and discard, so the size is measured but the document is never returned.
      const body = await r.arrayBuffer();
      return json({
        url: target, http_code: String(r.status), bytes: body.byteLength,
        final_url: r.url, ms: Date.now() - started,
        colo: request.cf ? request.cf.colo : null,
        country: request.cf ? request.cf.country : null,
        vantage: "cloudflare-edge", ua: UA,
      });
    } catch (e) {
      return json({
        url: target, http_code: "000", error: String(e && e.message || e),
        ms: Date.now() - started,
        colo: request.cf ? request.cf.colo : null,
        vantage: "cloudflare-edge", ua: UA,
      });
    }
  },
};

function json(o, status = 200) {
  return new Response(JSON.stringify(o, null, 1) + "\n",
    { status, headers: { "content-type": "application/json; charset=utf-8" } });
}
