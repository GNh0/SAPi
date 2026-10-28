-- Additive upgrade from the earlier state-d1.sql schema. Apply only after review.
-- Does not delete or modify existing replay claims or rate buckets.
CREATE TABLE sapi_replay_policy (service TEXT PRIMARY KEY NOT NULL, version TEXT NOT NULL, config TEXT NOT NULL);
