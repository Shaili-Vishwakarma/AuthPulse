# AuthPulse

HMAC-SHA256 message authentication, tamper detection, and replay prevention —
a self-contained Flask + SQLite backend with a plain HTML/CSS/JS frontend.

## What it demonstrates

AuthPulse implements a 3-check verification pipeline for signed messages:

1. **HMAC integrity** — the receiver recomputes the HMAC-SHA256 tag from the
   payload, timestamp, and nonce, then compares it with the received tag using
   `hmac.compare_digest`. A mismatch means the payload was tampered with.

2. **Timestamp window** — the message timestamp must be within ±60 seconds of
   the server's clock. This rejects stale messages.

3. **Nonce uniqueness** — each nonce is stored in a SQLite table with a
   `UNIQUE` constraint. A duplicate nonce means a replay attack.

The checks run in order: HMAC first (tamper), then timestamp (expired), then
nonce (replay). Only if all three pass is the message accepted.

## Project layout

```
authpulse/
├── app.py                 # Flask backend (API + static serving)
├── .env                   # AUTHPULSE_SECRET (never reaches frontend)
├── requirements.txt
├── tests/
│   ├── conftest.py
│   └── test_verify.py      # pytest: valid, tampered, replay, expired, concurrent
├── static/
│   ├── index.html
│   ├── css/style.css
│   └── js/app.js
└── README.md
```

## Setup

```bash
cd authpulse
python -m venv .venv
# Windows:  .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## Run tests

```bash
pytest -v
```

## Demo script

Here is a quick end-to-end demo you can run from a second terminal while the
server is running:

```bash
# 1. Sign a payload (demo client)
curl -s http://127.0.0.1:5000/api/sign \
  -H "Content-Type: application/json" \
  -d '{"payload": {"amount": 100, "recipient": "alice"}}' | python -m json.tool

# 2. Verify a valid message — copy timestamp, nonce, tag from step 1
curl -s http://127.0.0.1:5000/api/verify \
  -H "Content-Type: application/json" \
  -d '{
    "payload": {"amount": 100, "recipient": "alice"},
    "timestamp": <TIMESTAMP>,
    "nonce": "<NONCE>",
    "tag": "<TAG>"
  }' | python -m json.tool

# 3. Simulate a tamper attack
curl -s -X POST http://127.0.0.1:5000/api/simulate/tamper \
  -H "Content-Type: application/json" \
  -d '{"payload": {"amount": 100}}' | python -m json.tool

# 4. Simulate a replay attack
curl -s -X POST http://127.0.0.1:5000/api/simulate/replay \
  -H "Content-Type: application/json" \
  -d '{"payload": {"action": "transfer"}}' | python -m json.tool

# 5. Simulate an expired message
curl -s -X POST http://127.0.0.1:5000/api/simulate/expired \
  -H "Content-Type: application/json" \
  -d '{"payload": {"action": "ping"}}' | python -m json.tool

# 6. View stats and recent events
curl -s http://127.0.0.1:5000/api/stats | python -m json.tool
curl -s "http://127.0.0.1:5000/api/events?page=1&page_size=5" | python -m json.tool
```

## API reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/sign` | Sign a payload server-side; returns tag, timestamp, nonce |
| POST | `/api/verify` | Run the full 3-check verification pipeline |
| POST | `/api/simulate/tamper` | Sign then tamper payload before verifying |
| POST | `/api/simulate/replay` | Verify same message twice (accept then reject) |
| POST | `/api/simulate/expired` | Sign with a 120s-old timestamp |
| GET | `/api/events` | Paginated, searchable, filterable, sortable event log |
| GET | `/api/stats` | Aggregate metrics for dashboard |
| GET | `/api/health` | Health check |

## Frontend pages

All pages are interactive — no passive display-only screens.

- **Overview** — 4 metric cards (click to jump to filtered logs), auto-refresh
  toggle (5s live polling with animated indicator), activity chart, outcome
  donut, and a Quick Test widget: type a payload, click Sign & Verify, and see
  the full check trace right on the dashboard.
- **Message Lab** — Sign a payload, then use quick-action buttons to
  auto-modify fields:
  - **Tamper Payload** — flips the first value in the JSON
  - **Age Timestamp** — subtracts 120s to simulate expiry
  - **Corrupt Tag** — flips the first hex character of the HMAC tag
  - **Reuse Nonce** — resets nonce to the original (verify twice for replay)
  - **Reset All** — restore all fields
  A live diff indicator below the fields tells you which check will fail before
  you verify. Copy buttons on every signed value. Signing string preview.
- **Attack Simulator** — A visual pipeline that shows the message flowing from
  sender to receiver in real time. Configure parameters, click "Run Attack
  Simulation", and watch each step animate: signing, transmission, tampering,
  and each verification check lighting up pass/fail as it happens.
  - **Tamper**: choose which field to tamper (first, last, or all) and set the
    replacement value. Watch the message get signed, travel the wire, get
    tampered in transit, then fail the HMAC check.
  - **Replay**: set replay count (1-5) and delay between sends. Watch each
    attempt animate through the pipeline — the first passes all checks,
    subsequent attempts fail at the nonce uniqueness check.
  - **Expired**: slider for timestamp age (10-600s). Watch the message pass
    the HMAC check but fail the timestamp window check.
  Each step shows a visual sender/wire/receiver diagram, animated pipeline
  nodes that activate and resolve one by one, and real check traces.
- **Verification Logs** — searchable, filterable, sortable, paginated table with:
  - **Live polling toggle** (5s auto-refresh)
  - **Inline row expansion** (click a row to expand the full trace inline)
  - **Export to JSON** (downloads current filtered results)
- **API Playground** — a real API explorer that actually works:
  - **Preset templates** per endpoint (click to pre-fill body/params)
  - **Query parameter builder** for GET endpoints (add/remove key-value rows)
  - **Response panel** showing status code, request URL, response time, and
    properly formatted JSON (no more empty response box)
  - **Request history** (last 10 requests with method badges and timestamps)
- **How It Works** — the 9-step protocol with limitations noted

## Security notes

- The HMAC secret lives in `.env` and never reaches the frontend, logs, or database.
- HMAC does not encrypt the payload — use TLS for confidentiality.
- HMAC alone does not stop replays — that is why we combine it with nonce
  uniqueness and a timestamp window.
