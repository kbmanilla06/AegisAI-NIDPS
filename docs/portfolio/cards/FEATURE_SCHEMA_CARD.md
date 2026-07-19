# Feature Schema Card

- **Input:** canonical flow v1 only
- **Schema:** `flow_features/1.0.0`
- **Model columns:** 39, fixed order
- **Reserved provenance:** 7 columns, excluded from model input
- **Windows:** deterministic event-time 60/300-second windows
- **Controls:** train-only fitting, missing/unseen/range handling, leakage
  denylist, deterministic ordering, artifact SHA-256
- **Raw endpoint values:** never exposed as model values or portfolio output

The feature contract is an engineering interface, not evidence of real-world
generalization. Any incompatible schema or hash fails closed.
