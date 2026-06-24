# Echo CRM

> Customer-relationship-management API for ECHO Prime (v2.0.0). Contacts,
> companies, deals, pipelines, activities, lead scoring, analytics, and
> Stripe-backed billing — a Hono app on Cloudflare Workers.

Private to Echo Prime Technologies.

## Auth

All mutating routes require auth (`X-Echo-API-Key`). `GET`/`OPTIONS`/`HEAD`,
`/health`, `/status`, and `/webhooks/stripe` are exempt.

## API by resource

**Contacts** — `GET /contacts`, `POST /contacts`, `GET|PUT|DELETE /contacts/:id`,
`GET /export/contacts`, `POST /import/contacts`
**Companies** — `GET /companies`, `POST /companies`, `GET|DELETE /companies/:id`
**Deals** — `GET /deals`, `GET /deals/board`, `POST /deals`, `GET|DELETE /deals/:id`,
`POST /deals/:id/move`
**Pipelines & stages** — `GET|POST /pipelines`, `GET|DELETE /pipelines/:id`,
`GET|POST /pipelines/:id/stages`, `PUT|DELETE /stages/:id`
**Activities & notes** — `GET|POST /activities`, `DELETE /activities/:id`,
`GET /activity-log`, `GET|POST /notes`, `DELETE /notes/:id`
**Tags** — `GET|POST /tags`, `DELETE /tags/:id`
**Lead scoring** — `GET|POST /lead-scoring/rules`, `DELETE /lead-scoring/rules/:id`,
`POST /lead-scoring/score`
**Analytics** — `GET /analytics/{contacts,pipeline,revenue,activity}`
**Email events** — `GET|POST /email-events`
**Billing (Stripe)** — `GET /plans`, `POST /plans/upgrade`, `POST /webhooks/stripe`,
`POST /admin/migrate-stripe`
**Meta** — `GET /`, `GET /health`, `GET /status`

## Develop

```bash
npm install
npx wrangler dev       # local Worker
npx wrangler deploy    # deploy
```

Stripe keys + the D1 binding are configured in `wrangler.toml` / the Cloudflare
dashboard — never commit secrets. The `/webhooks/stripe` route verifies the Stripe
signature, so the webhook signing secret must be set.

## License

Proprietary — © Echo Prime Technologies. (The npm `package.json` license field is a
scaffold default; this repo is proprietary.)
