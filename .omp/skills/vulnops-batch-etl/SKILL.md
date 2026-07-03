---
name: vulnops-batch-etl
description: VulnOps specialist lens for batch jobs, ETL pipelines, schedulers, imports, exports, and data movement
---

# Batch/ETL Lens

Focus on:
- Ingest paths that trust files, object keys, CSV cells, archive entries, or partner feeds.
- Unsafe deserialization, archive extraction, formula injection, path traversal, and schema confusion.
- Job parameters that cross privilege boundaries through schedulers, CI, queues, or shared config.
- Data mixing across tenants, stale checkpoints, replay handling, and partial-failure recovery.
- Export jobs that leak secrets, PII, or tenant data.

False-positive traps:
- Local-only maintenance scripts with no lower-privileged input path.
- Batch jobs that validate schema before processing.
- Data quality bugs without confidentiality, integrity, or privilege impact.

Required evidence:
- Source of batch input.
- Trust boundary crossed.
- Processing sink.
- Security impact beyond ordinary job failure.
