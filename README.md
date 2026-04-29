# Stage309 REMEDA Verification History DB

Stage309 transforms verification into an accumulated trust system.

## Core Concept

Stage308 proved:

same evidence + different policy = different decision

Stage309 adds:

verification + policy version + DB history = accumulated trust

## What This Stage Achieves

- Verification results are stored as history
- Policy differences are recorded with SHA-256
- Manifest integrity is preserved with SHA-256
- Decisions are reproducible
- Trust evolves over time

## Key Insight

This stage proves:

"Trust is not a single result, but a history of verifiable decisions."

## Example Evolution

Initial state:
v1 → accept  
v2 → accept  
v3 → reject  

After Sigstore:
v1 → accept  
v2 → accept  
v3 → accept  

## Architecture

Frontend (Flask UI)
/verify
/history
/result/{id}

↓

Verification Engine (Policy)

↓

SQLite (Trust History DB)

## Run

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py

Open:
http://127.0.0.1:3090

## License

MIT License

Copyright (c) 2025 Motohiro Suzuki
