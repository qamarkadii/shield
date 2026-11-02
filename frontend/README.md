# Frontend: AIDA showcase website

React + Vite + TypeScript, Three.js (React Three Fiber), GSAP, Tailwind.
3D threat-map hero, live threat feed, how-it-works pipeline, domain demo, model performance, dataset.

## Where it runs

Shield's public app serves the built site (`frontend/dist`) at **/site/**:

- `python run_shield.py` → http://127.0.0.1:8001/site/
- Hugging Face / `space_app.py` → https://<your-space>/site/

The demo calls Shield's public `POST /api/check` on the same site, so results come from the real model
(same rate limit as the public page: 20 checks a minute per visitor).

`dist/` is already built and included, so nothing needs Node to run Shield.

## Change the site

Requires Node.js 20+.

    cd frontend
    npm install
    npm run dev            # live preview at http://127.0.0.1:5173 (simulation mode, no backend)
    npm run build:shield   # rebuild dist/ for Shield (served at /site/, uses /api/check)

Then restart Shield. Model numbers shown on the site are in `src/lib/model.ts` and `public/model-report.json`.
