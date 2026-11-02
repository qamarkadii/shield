// Cloudflare Worker: serves Shield (running on Hugging Face Spaces) at aidashield.tech.
//
// Setup (Cloudflare dashboard, free plan):
//   Workers & Pages -> Create -> Worker -> paste this file -> Deploy
//   Settings -> Variables -> add SPACE_URL = https://YOUR-HF-USERNAME-shield.hf.space
//   Settings -> Domains & Routes -> Add -> Custom domain -> aidashield.tech (and www.aidashield.tech)

export default {
  async fetch(request, env) {
    const space = (env.SPACE_URL || "").replace(/\/$/, "");
    if (!space) return new Response("SPACE_URL is not set on this Worker.", { status: 500 });

    const incoming = new URL(request.url);
    const target = space + incoming.pathname + incoming.search;

    const forwarded = new Request(target, request);           // same method, headers and body
    forwarded.headers.set("X-Forwarded-For", request.headers.get("CF-Connecting-IP") || "");
    forwarded.headers.set("X-Forwarded-Proto", "https");

    const response = await fetch(forwarded, { redirect: "manual" });

    // keep visitors on aidashield.tech if Shield answers with a redirect to the Space address
    const out = new Response(response.body, response);
    const location = response.headers.get("Location");
    if (location && location.startsWith(space)) {
      out.headers.set("Location", incoming.origin + location.slice(space.length));
    }
    return out;
  },
};
