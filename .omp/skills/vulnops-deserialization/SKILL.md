---
name: vulnops-deserialization
description: VulnOps specialist lens for unsafe deserialization, object injection, parser abuse, and gadget-backed loading
---

# Deserialization Lens

Focus on:
- Unsafe object loaders: pickle, marshal, shelve, dill, joblib, YAML unsafe loaders, Java ObjectInputStream, XMLDecoder, XStream, PHP unserialize, jsonpickle, Hessian, Kryo, .NET BinaryFormatter.
- Polymorphic type handling where input controls class/type names.
- Archive extraction and parser paths that materialize attacker-controlled names or objects.
- Message queues, sessions, cookies, imports, caches, and migration jobs that deserialize untrusted data.

False-positive traps:
- JSON parsing into plain data structures without dynamic type resolution.
- Deserialization of files only root/operator can write.
- Safe loader APIs with explicit allow-lists.

Required evidence:
- Untrusted serialized source.
- Unsafe loader or dynamic type resolution.
- Reachable effect: code execution, file write, auth bypass, data corruption, or sensitive read.
