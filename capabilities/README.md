# Capability contracts

`catalog.yaml` is the intended OctoBus-facing surface. It is deliberately a design contract rather than an executable service package, because downstream products and APIs are not yet known.

Implementation rules:

1. one method, one bounded business action;
2. no generic shell, SQL or unrestricted HTTP method;
3. tenant, run and actor context are mandatory;
4. high-risk methods validate authorization independently from the Agent;
5. raw output is persisted as an Artifact and summarized in the response;
6. request and response schemas are versioned;
7. timeouts, rate limits, response size and audit fields are explicit;
8. secrets are resolved inside the service, never passed in Agent text.

The first executable service should be `security-evidence`; it gives every later Agent a common evidence protocol.
