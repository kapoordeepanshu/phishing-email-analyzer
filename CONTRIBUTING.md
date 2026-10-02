# Contributing

Thanks for helping make phishing easier to spot!

## Development

```bash
python -m unittest discover -s tests -v     # tests (stdlib only, no installs needed)
python -m phishanalyzer samples --summary   # run on the sample emails
python samples/generate_samples.py          # regenerate samples after editing them
```

Web app locally (serve the repo root so `web/` can load the Python package):

```bash
python -m http.server 8000
# open http://localhost:8000/web/
```

## Guidelines

- **No runtime dependencies.** The core must stay stdlib-only so it runs in the browser via Pyodide.
- **Never execute or render attachment content**: read bytes only.
- **Treat email content as hostile** in the web UI: render with `textContent`, never `innerHTML`; no clickable links.
- Every new check needs a test, including one proving it doesn't fire on a legitimate email.
- Keep severities honest. Something common in legitimate newsletters should be `LOW`/`INFO`.
- Don't commit real emails. Build synthetic ones in `samples/generate_samples.py` or in the tests.

## Where checks live

| Module | Checks |
|---|---|
| `headers.py` | SPF/DKIM/DMARC, From/Reply-To/Return-Path, relay path |
| `links.py` | URL heuristics, unwrapping, deceptive link text |
| `attachments.py` | file type, macros, PDF/HTML/archive internals |
| `content.py` | social-engineering language, HTML forms |
| `domains.py` | brand list, lookalike/homograph detection |
