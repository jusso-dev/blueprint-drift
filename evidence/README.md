# Evidence Pack Templates and Renderers (`evidence/`)

Generates IRAP-ready evidence packs from drift runs in four formats (#11):

- Markdown (`.md`)
- HTML (`.html`)
- CSV (`.csv`)
- JSON (`.json`)

Each pack records the UTC timestamp, tenant placeholder or target tenant ID, exact read-only Graph query used, reproducible SHA-256 hash of the raw response payload, ISM control mapping, Essential Eight mapping, and a manual assessor checklist.
