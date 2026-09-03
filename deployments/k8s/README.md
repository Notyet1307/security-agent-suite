# Kubernetes scaffold

These manifests are a conservative starting point for Mock mode. They deliberately keep one replica and deny general egress because the current store is file-based and the real agent-compose endpoint is environment-specific.

Before production:

1. replace the image tag with a signed digest;
2. create the Secret through the cluster secret manager, not from `secret.example.yaml`;
3. migrate to PostgreSQL and object storage;
4. add identity-based ingress and explicit agent-compose egress;
5. add PodDisruptionBudget, topology, backup and OTEL configuration;
6. validate NetworkPolicy behavior in the target CNI.
