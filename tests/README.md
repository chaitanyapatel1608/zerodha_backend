# Backend test safety

`npm test` and `npm run test:unit` run database-free tests. HTTP route tests bind a temporary loopback server and stub persistence/email; they do not load `.env`, connect to MongoDB or send real mail.

`npm run test:integration` is explicitly opt-in and **writes/deletes test data**. Each integration file loads the target guard before application modules, including when invoked directly with `node --test`.

Use a disposable, locally hosted MongoDB replica set for transaction testing. Set `TEST_MONGO_URL` to a loopback URI whose database name starts with `zerodha_test_`, for example:

```powershell
$env:TEST_MONGO_URL = 'mongodb://127.0.0.1:27017/zerodha_test_local?replicaSet=rs0'
npm run test:integration
```

Do not use a port-forward or proxy to a shared database. A URI guard can validate a local address and database name, but cannot prove the server behind that address is disposable. Provision and identify the test instance before running the suite.

The guard rejects absent configuration, ordinary database names, remote/SRV/authenticated targets and external `TEST_API_BASE`. It replaces `MONGO_URL` and signing/encryption test keys, and removes email credentials from the test process. Test mode does not load the backend `.env`. Only replicaSet, directConnection and serverSelectionTimeoutMS URI options are accepted.

For automated provisioning, run `npm run test:integration` from the repository root. Its runner downloads a pinned MongoDB binary and creates/stops a disposable replica set without Docker or a preinstalled MongoDB. Each test file receives its own database. Results and limitations are recorded in the root enhancement progress document.

Tests await database/catalog readiness. Background timers are not started by `startServer` in test mode. Do not point direct integration invocations at development accounts you want to retain. The full transaction/worker failure matrix remains Gate B work; passing legacy integration assertions does not resolve the audit's untested domain findings.
