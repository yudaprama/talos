import http from "k6/http";
import { check, group, fail } from "k6";
import { Counter } from "k6/metrics";

// Custom metrics
const keyCreations = new Counter("key_creations");
const keyRotations = new Counter("key_rotations");
const keyRevocations = new Counter("key_revocations");
const keyImports = new Counter("key_imports");
const keySelfRevocations = new Counter("key_self_revocations");
const keyUpdates = new Counter("key_updates");
const verifications = new Counter("verifications");
const tokenDerivations = new Counter("token_derivations");

// Run-unique ID for idempotent key names across re-runs
const RUN_ID = Date.now().toString(36);

// Configuration from environment
const BASE_URL = __ENV.BASE_URL || "http://localhost:4420";

// Profile-based scaling
//
// smoke/load use constant-vus (flat concurrency).
// stress uses ramping-vus to gradually increase load and find the breaking point:
//   Warm-up:   0 → 25 VUs over 30s
//   Ramp 1:   25 → 75 VUs over 60s
//   Ramp 2:   75 → 150 VUs over 60s
//   Hold:    150 VUs for 120s
//   Ramp down: 150 → 0 VUs over 30s
// Read scenarios get ~70% of VUs, write scenarios get ~30%.
const PROFILE = __ENV.TEST_PROFILE || "smoke";
const profiles = {
  smoke: { type: "constant", readVUs: 1, writeVUs: 1, duration: "15s" },
  load: { type: "constant", readVUs: 15, writeVUs: 5, duration: "120s" },
  stress: {
    type: "ramping",
    readStages: [
      { duration: "30s", target: 18 },
      { duration: "60s", target: 53 },
      { duration: "60s", target: 105 },
      { duration: "120s", target: 105 },
      { duration: "30s", target: 0 },
    ],
    writeStages: [
      { duration: "30s", target: 7 },
      { duration: "60s", target: 22 },
      { duration: "60s", target: 45 },
      { duration: "120s", target: 45 },
      { duration: "30s", target: 0 },
    ],
    functionalStages: [
      { duration: "30s", target: 1 },
      { duration: "240s", target: 1 },
      { duration: "30s", target: 0 },
    ],
  },
};
const profile = profiles[PROFILE] || profiles.smoke;

function buildScenarios(p) {
  if (p.type === "ramping") {
    return {
      read_operations: {
        executor: "ramping-vus",
        stages: p.readStages,
        exec: "readOperations",
        tags: { scenario: "read" },
      },
      key_lifecycle: {
        executor: "ramping-vus",
        stages: p.writeStages,
        exec: "keyLifecycle",
        tags: { scenario: "lifecycle" },
      },
      import_lifecycle: {
        executor: "ramping-vus",
        stages: p.writeStages,
        exec: "importLifecycle",
        tags: { scenario: "import" },
      },
      self_revoke_lifecycle: {
        executor: "ramping-vus",
        stages: p.writeStages,
        exec: "selfRevokeLifecycle",
        tags: { scenario: "self-revoke" },
      },
      batch_import_lifecycle: {
        executor: "ramping-vus",
        stages: p.writeStages,
        exec: "batchImportLifecycle",
        tags: { scenario: "batch-import" },
      },
      nid_isolation: {
        executor: "ramping-vus",
        stages: p.writeStages,
        exec: "nidIsolation",
        tags: { scenario: "nid-isolation" },
      },
      macaroon_derivation: {
        executor: "ramping-vus",
        stages: p.readStages,
        exec: "macaroonDerivation",
        tags: { scenario: "macaroon" },
      },
      pagination_cursor: {
        executor: "ramping-vus",
        stages: p.functionalStages,
        exec: "paginationCursor",
        tags: { scenario: "pagination" },
      },
      batch_boundary: {
        executor: "ramping-vus",
        stages: p.functionalStages,
        exec: "batchBoundaryTest",
        tags: { scenario: "batch-boundary" },
      },
    };
  }
  return {
    read_operations: {
      executor: "constant-vus",
      vus: p.readVUs,
      duration: p.duration,
      exec: "readOperations",
      tags: { scenario: "read" },
    },
    key_lifecycle: {
      executor: "constant-vus",
      vus: p.writeVUs,
      duration: p.duration,
      exec: "keyLifecycle",
      tags: { scenario: "lifecycle" },
    },
    import_lifecycle: {
      executor: "constant-vus",
      vus: p.writeVUs,
      duration: p.duration,
      exec: "importLifecycle",
      tags: { scenario: "import" },
    },
    self_revoke_lifecycle: {
      executor: "constant-vus",
      vus: p.writeVUs,
      duration: p.duration,
      exec: "selfRevokeLifecycle",
      tags: { scenario: "self-revoke" },
    },
    batch_import_lifecycle: {
      executor: "constant-vus",
      vus: p.writeVUs,
      duration: p.duration,
      exec: "batchImportLifecycle",
      tags: { scenario: "batch-import" },
    },
    nid_isolation: {
      executor: "constant-vus",
      vus: p.writeVUs,
      duration: p.duration,
      exec: "nidIsolation",
      tags: { scenario: "nid-isolation" },
    },
    macaroon_derivation: {
      executor: "constant-vus",
      vus: p.readVUs,
      duration: p.duration,
      exec: "macaroonDerivation",
      tags: { scenario: "macaroon" },
    },
    pagination_cursor: {
      executor: "constant-vus",
      vus: 1,
      duration: p.duration,
      exec: "paginationCursor",
      tags: { scenario: "pagination" },
    },
    batch_boundary: {
      executor: "constant-vus",
      vus: 1,
      duration: p.duration,
      exec: "batchBoundaryTest",
      tags: { scenario: "batch-boundary" },
    },
  };
}

function buildThresholds(p) {
  if (p.type === "ramping") {
    // Stress tests intentionally push past comfortable limits
    return {
      checks: ["rate==1.0"],
      http_req_failed: ["rate<0.01"], // stress may push limits
      http_req_duration: ["p(99)<400"], // measured p99=123ms → 3.2x headroom
      "http_req_duration{name:verify}": [
        "p(95)<100", // measured p95=48ms → 2.1x headroom
        "p(99)<200", // measured p99=95ms → 2.1x headroom
      ],
    };
  }
  return {
    checks: ["rate==1.0"],
    http_req_failed: ["rate==0.0"], // zero tolerance for smoke/load
    http_req_duration: ["p(99)<500"], // measured p99~6ms → ~80x headroom
    "http_req_duration{name:verify}": [
      "p(95)<50", // measured p95~25ms in CI (postgres) → 2x headroom
      "p(99)<100", // measured p99~42ms in CI (postgres) → 2.4x headroom
    ],
  };
}

export const options = {
  scenarios: buildScenarios(profile),
  thresholds: buildThresholds(profile),
};

// ============================================================================
// HEADERS
// ============================================================================

function authHeaders(extra) {
  return Object.assign(
    {
      "Content-Type": "application/json",
      Authorization: `Bearer ${__ENV.AUTH_TOKEN || "test-token"}`,
    },
    extra || {},
  );
}

function publicHeaders() {
  return { "Content-Type": "application/json" };
}

function authHeadersForTenant(hostname) {
  return authHeaders({ Host: hostname });
}

function publicHeadersForTenant(hostname) {
  return Object.assign(publicHeaders(), { Host: hostname });
}

// ============================================================================
// SETUP: Create IMMUTABLE test data (never rotated or revoked during scenarios)
// ============================================================================
export function setup() {
  console.log(`Setup starting - Base URL: ${BASE_URL}, Profile: ${PROFILE}, Run ID: ${RUN_ID}`);

  const data = {
    readKeys: [],
    importedReadKeys: [],
    revokedKeys: [],
    macaroonKey: null,
    batchBoundaryKeys: [],
  };

  // Create 10 keys for read-only operations
  console.log("Creating read-only keys...");
  for (let i = 0; i < 10; i++) {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/issuedApiKeys`,
      JSON.stringify({
        name: `Read Key ${RUN_ID}_${i}`,
        actor_id: `read-service-${RUN_ID}-${i}`,
        scopes: ["read", "write"],
        metadata: { pool: "read", index: i, run_id: RUN_ID },
      }),
      { headers: authHeaders() },
    );

    if (!check(res, { "setup: create read key": (r) => r.status === 201 })) {
      fail(`Failed to create read key ${i}: ${res.status} ${res.body}`);
    }

    const body = JSON.parse(res.body);
    data.readKeys.push({
      keyId: body.issued_api_key.key_id,
      secret: body.secret,
      actorId: body.issued_api_key.actor_id,
    });
  }
  console.log(`Created ${data.readKeys.length} read keys`);

  // Import 5 keys for read-only operations
  console.log("Importing read-only keys...");
  for (let i = 0; i < 5; i++) {
    const rawKey = `sk_import_read_${RUN_ID}_${i}_${"x".repeat(20)}`;
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/importedApiKeys`,
      JSON.stringify({
        raw_key: rawKey,
        name: `Imported Read Key ${RUN_ID}_${i}`,
        actor_id: `import-read-${RUN_ID}-${i}`,
        scopes: ["read"],
      }),
      { headers: authHeaders() },
    );

    if (!check(res, { "setup: import read key": (r) => r.status === 201 })) {
      fail(`Failed to import read key ${i}: ${res.status} ${res.body}`);
    }

    const body = JSON.parse(res.body);
    data.importedReadKeys.push({
      keyId: body.imported_api_key.key_id,
      rawKey: rawKey,
    });
  }
  console.log(`Imported ${data.importedReadKeys.length} read keys`);

  // Create and revoke 3 keys for negative testing
  console.log("Creating pre-revoked keys...");
  for (let i = 0; i < 3; i++) {
    const createRes = http.post(
      `${BASE_URL}/v2alpha1/admin/issuedApiKeys`,
      JSON.stringify({
        name: `Revoked Key ${RUN_ID}_${i}`,
        actor_id: `revoked-service-${RUN_ID}-${i}`,
        scopes: ["read"],
      }),
      { headers: authHeaders() },
    );

    if (!check(createRes, { "setup: create key for revocation": (r) => r.status === 201 })) {
      fail(`Failed to create key for revocation ${i}: ${createRes.status}`);
    }

    const createBody = JSON.parse(createRes.body);
    const keyId = createBody.issued_api_key.key_id;
    const secret = createBody.secret;

    const revokeRes = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys/${keyId}:revoke`,
      JSON.stringify({ reason: "REVOCATION_REASON_KEY_COMPROMISE" }),
      { headers: authHeaders() },
    );

    if (!check(revokeRes, { "setup: revoke key": (r) => r.status === 204 })) {
      fail(`Failed to revoke key ${i}: ${revokeRes.status}`);
    }

    data.revokedKeys.push({ keyId, secret });
  }
  console.log(`Created ${data.revokedKeys.length} pre-revoked keys`);

  // Create 1 key dedicated to macaroon derivation testing
  console.log("Creating macaroon test key...");
  {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/issuedApiKeys`,
      JSON.stringify({
        name: `Macaroon Key ${RUN_ID}`,
        actor_id: `macaroon-${RUN_ID}`,
        scopes: ["read", "write"],
        metadata: { pool: "macaroon", run_id: RUN_ID },
      }),
      { headers: authHeaders() },
    );

    if (!check(res, { "setup: create macaroon key": (r) => r.status === 201 })) {
      fail(`Failed to create macaroon key: ${res.status} ${res.body}`);
    }

    const body = JSON.parse(res.body);
    data.macaroonKey = {
      keyId: body.issued_api_key.key_id,
      secret: body.secret,
    };
  }
  console.log("Created macaroon test key");

  // Create 100 keys for batch boundary testing
  console.log("Creating batch boundary keys...");
  for (let i = 0; i < 100; i++) {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/issuedApiKeys`,
      JSON.stringify({
        name: `Batch Boundary ${RUN_ID}_${i}`,
        actor_id: `batch-boundary-${RUN_ID}`,
        scopes: ["read"],
        metadata: { pool: "batch-boundary", run_id: RUN_ID },
      }),
      { headers: authHeaders() },
    );

    if (!check(res, { "setup: create batch boundary key": (r) => r.status === 201 })) {
      fail(`Failed to create batch boundary key ${i}: ${res.status} ${res.body}`);
    }

    const body = JSON.parse(res.body);
    data.batchBoundaryKeys.push({
      keyId: body.issued_api_key.key_id,
      secret: body.secret,
    });
  }
  console.log(`Created ${data.batchBoundaryKeys.length} batch boundary keys`);

  console.log("Setup complete");
  return data;
}

// ============================================================================
// READ OPERATIONS: Uses immutable keys from setup
// ============================================================================
export function readOperations(data) {
  const keyIndex = __ITER % data.readKeys.length;
  const key = data.readKeys[keyIndex];

  group("Health Check", () => {
    const res = http.get(`${BASE_URL}/health`);
    check(res, {
      "health: status 200": (r) => r.status === 200,
    });
  });

  group("Verify Credential", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:verify`,
      JSON.stringify({ credential: key.secret }),
      {
        headers: publicHeaders(),
        tags: { name: "verify" },
      },
    );

    const success = check(res, {
      "verify: status 200": (r) => r.status === 200,
      "verify: active true": (r) => JSON.parse(r.body).is_active === true,
      "verify: has key_id": (r) => JSON.parse(r.body).key_id === key.keyId,
      "verify: has actor_id": (r) => JSON.parse(r.body).actor_id === key.actorId,
      "verify: has scopes": (r) => Array.isArray(JSON.parse(r.body).scopes),
    });

    if (success) verifications.add(1);
  });

  group("Batch Verify", () => {
    const keys = [
      data.readKeys[keyIndex],
      data.readKeys[(keyIndex + 1) % data.readKeys.length],
      data.readKeys[(keyIndex + 2) % data.readKeys.length],
    ];

    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:batchVerify`,
      JSON.stringify({
        requests: keys.map((k) => ({ credential: k.secret })),
      }),
      { headers: publicHeaders() },
    );

    check(res, {
      "batch: status 200": (r) => r.status === 200,
      "batch: has 3 responses": (r) => JSON.parse(r.body).results.length === 3,
      "batch: all active": (r) =>
        JSON.parse(r.body).results.every((resp) => resp.is_active === true),
    });
  });

  group("Get API Key", () => {
    const res = http.get(`${BASE_URL}/v2alpha1/admin/issuedApiKeys/${key.keyId}`, {
      headers: authHeaders(),
    });

    check(res, {
      "get: status 200": (r) => r.status === 200,
      "get: correct key_id": (r) => JSON.parse(r.body).key_id === key.keyId,
      "get: has name": (r) => JSON.parse(r.body).name.length > 0,
      "get: has actor_id": (r) => JSON.parse(r.body).actor_id === key.actorId,
    });
  });

  group("List API Keys", () => {
    const res = http.get(`${BASE_URL}/v2alpha1/admin/issuedApiKeys?page_size=50`, {
      headers: authHeaders(),
    });

    check(res, {
      "list: status 200": (r) => r.status === 200,
      "list: has issued_api_keys array": (r) => Array.isArray(JSON.parse(r.body).issued_api_keys),
      "list: has keys": (r) => JSON.parse(r.body).issued_api_keys.length > 0,
    });
  });

  group("Derive Token", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:derive`,
      JSON.stringify({
        credential: key.secret,
        algorithm: "TOKEN_ALGORITHM_JWT",
        ttl: "3600s",
        scopes: ["read"],
      }),
      { headers: authHeaders() },
    );

    const success = check(res, {
      "derive: status 200": (r) => r.status === 200,
      "derive: has token": (r) => JSON.parse(r.body).token.token.length > 0,
      "derive: has expire_time": (r) => JSON.parse(r.body).token.expire_time !== undefined,
      "derive: has scopes": (r) => Array.isArray(JSON.parse(r.body).token.scopes),
    });

    if (success) tokenDerivations.add(1);
  });

  group("Get JWKS", () => {
    const res = http.get(`${BASE_URL}/v2alpha1/derivedKeys/jwks.json`, {
      headers: publicHeaders(),
    });

    check(res, {
      "jwks: status 200": (r) => r.status === 200,
      "jwks: has keys": (r) => {
        const body = JSON.parse(r.body);
        return (body.jwks && body.jwks.keys) || body.keys;
      },
    });
  });

  group("Verify Imported Key", () => {
    const importedIndex = __ITER % data.importedReadKeys.length;
    const importedKey = data.importedReadKeys[importedIndex];

    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:verify`,
      JSON.stringify({ credential: importedKey.rawKey }),
      { headers: publicHeaders(), tags: { name: "verify" } },
    );

    check(res, {
      "verify-import: status 200": (r) => r.status === 200,
      "verify-import: active true": (r) => JSON.parse(r.body).is_active === true,
      "verify-import: has key_id": (r) => JSON.parse(r.body).key_id === importedKey.keyId,
    });
  });

  group("Verify Revoked Key (Negative Test)", () => {
    const revokedIndex = __ITER % data.revokedKeys.length;
    const revokedKey = data.revokedKeys[revokedIndex];

    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:verify`,
      JSON.stringify({ credential: revokedKey.secret }),
      {
        headers: Object.assign(publicHeaders(), { "Cache-Control": "no-cache" }),
        tags: { name: "verify" },
      },
    );

    check(res, {
      "verify-revoked: status 200": (r) => r.status === 200,
      "verify-revoked: active false": (r) => JSON.parse(r.body).is_active === false,
      "verify-revoked: has error_code": (r) => {
        const body = JSON.parse(r.body);
        return body.error_code === "VERIFICATION_ERROR_REVOKED" || body.error_code === 3;
      },
    });
  });

  group("Verify Invalid Credential (Negative Test)", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:verify`,
      JSON.stringify({ credential: `invalid_${RUN_ID}_vu${__VU}_iter${__ITER}` }),
      { headers: publicHeaders(), tags: { name: "verify" } },
    );

    check(res, {
      "verify-invalid: status 200": (r) => r.status === 200,
      "verify-invalid: active false": (r) => JSON.parse(r.body).is_active === false,
    });
  });
}

// ============================================================================
// KEY LIFECYCLE: Create -> Use -> Rotate -> Verify Old Fails -> Revoke -> Verify Fails
// ============================================================================
export function keyLifecycle() {
  const uniqueId = `${RUN_ID}_vu${__VU}_iter${__ITER}`;
  let createdKey = null;
  let rotatedKey = null;

  group("1. Create API Key", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/issuedApiKeys`,
      JSON.stringify({
        name: `Lifecycle Key ${uniqueId}`,
        actor_id: `lifecycle-${uniqueId}`,
        scopes: ["read", "write"],
        metadata: { test: "lifecycle", vu: __VU, iter: __ITER },
      }),
      { headers: authHeaders() },
    );

    if (res.status !== 201) {
      console.error(`Create failed: ${res.status} - ${res.body}`);
    }

    const success = check(res, {
      "create: status 201": (r) => r.status === 201,
      "create: has secret": (r) => {
        if (r.status !== 201) return false;
        try {
          return JSON.parse(r.body).secret.length > 0;
        } catch {
          return false;
        }
      },
      "create: has key_id": (r) => {
        if (r.status !== 201) return false;
        try {
          return JSON.parse(r.body).issued_api_key.key_id.length > 0;
        } catch {
          return false;
        }
      },
      "create: status active": (r) => {
        if (r.status !== 201) return false;
        try {
          const status = JSON.parse(r.body).issued_api_key.status;
          return status === "KEY_STATUS_ACTIVE" || status === 1;
        } catch {
          return false;
        }
      },
    });

    if (success && res.status === 201) {
      const body = JSON.parse(res.body);
      createdKey = { keyId: body.issued_api_key.key_id, secret: body.secret };
      keyCreations.add(1);
    }
  });

  if (!createdKey) {
    fail("Cannot continue lifecycle: key creation failed");
  }

  group("2. Verify Created Key Works", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:verify`,
      JSON.stringify({ credential: createdKey.secret }),
      { headers: publicHeaders(), tags: { name: "verify" } },
    );

    check(res, {
      "verify-created: status 200": (r) => r.status === 200,
      "verify-created: active true": (r) => JSON.parse(r.body).is_active === true,
      "verify-created: correct key_id": (r) => JSON.parse(r.body).key_id === createdKey.keyId,
    });
  });

  group("2.5. Update API Key Metadata", () => {
    const res = http.patch(
      `${BASE_URL}/v2alpha1/admin/issuedApiKeys/${createdKey.keyId}`,
      JSON.stringify({
        name: `Updated Lifecycle Key ${uniqueId}`,
        scopes: ["read", "write"],
        metadata: { test: "lifecycle", updated: true, vu: __VU, iter: __ITER },
      }),
      { headers: authHeaders() },
    );

    if (res.status !== 200) {
      console.error(`Update failed: ${res.status} - ${res.body}`);
    }

    const success = check(res, {
      "update: status 200": (r) => r.status === 200,
      "update: correct key_id": (r) => {
        if (r.status !== 200) return false;
        try {
          return JSON.parse(r.body).key_id === createdKey.keyId;
        } catch {
          return false;
        }
      },
      "update: name updated": (r) => {
        if (r.status !== 200) return false;
        try {
          return JSON.parse(r.body).name === `Updated Lifecycle Key ${uniqueId}`;
        } catch {
          return false;
        }
      },
    });

    if (success) keyUpdates.add(1);
  });

  group("3. Rotate API Key", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/issuedApiKeys/${createdKey.keyId}:rotate`,
      JSON.stringify({
        scopes: ["read"],
        metadata: { rotated: true, vu: __VU, iter: __ITER },
      }),
      { headers: authHeaders() },
    );

    if (res.status !== 201) {
      console.error(`Rotate failed: ${res.status} - ${res.body}`);
    }

    const success = check(res, {
      "rotate: status 201": (r) => r.status === 201,
      "rotate: has new secret": (r) => {
        if (r.status !== 201) return false;
        try {
          return JSON.parse(r.body).secret.length > 0;
        } catch {
          return false;
        }
      },
      "rotate: has new key": (r) => {
        if (r.status !== 201) return false;
        try {
          return JSON.parse(r.body).issued_api_key.key_id.length > 0;
        } catch {
          return false;
        }
      },
      "rotate: new key active": (r) => {
        if (r.status !== 201) return false;
        try {
          const status = JSON.parse(r.body).issued_api_key.status;
          return status === "KEY_STATUS_ACTIVE" || status === 1;
        } catch {
          return false;
        }
      },
      "rotate: old key revoked": (r) => {
        if (r.status !== 201) return false;
        try {
          const status = JSON.parse(r.body).old_issued_api_key.status;
          return status === "KEY_STATUS_REVOKED" || status === 2;
        } catch {
          return false;
        }
      },
    });

    if (success && res.status === 201) {
      const body = JSON.parse(res.body);
      rotatedKey = { keyId: body.issued_api_key.key_id, secret: body.secret };
      keyRotations.add(1);
    }
  });

  if (!rotatedKey) {
    fail("Cannot continue lifecycle: rotation failed");
  }

  group("4. Verify Rotated Key Works", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:verify`,
      JSON.stringify({ credential: rotatedKey.secret }),
      { headers: publicHeaders(), tags: { name: "verify" } },
    );

    check(res, {
      "verify-rotated: status 200": (r) => r.status === 200,
      "verify-rotated: active true": (r) => JSON.parse(r.body).is_active === true,
      "verify-rotated: correct key_id": (r) => JSON.parse(r.body).key_id === rotatedKey.keyId,
    });
  });

  group("5. Verify OLD Key Fails (Revoked by Rotation)", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:verify`,
      JSON.stringify({ credential: createdKey.secret }),
      {
        headers: Object.assign(publicHeaders(), { "Cache-Control": "no-cache" }),
        tags: { name: "verify" },
      },
    );

    check(res, {
      "verify-old: status 200": (r) => r.status === 200,
      "verify-old: active false": (r) => JSON.parse(r.body).is_active === false,
      "verify-old: error is revoked": (r) => {
        const code = JSON.parse(r.body).error_code;
        return code === "VERIFICATION_ERROR_REVOKED" || code === 3;
      },
    });
  });

  group("6. Revoke Rotated Key", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys/${rotatedKey.keyId}:revoke`,
      JSON.stringify({ reason: "REVOCATION_REASON_KEY_COMPROMISE" }),
      { headers: authHeaders() },
    );

    if (res.status !== 204) {
      console.error(`Revoke failed: ${res.status} - ${res.body}`);
    }

    const success = check(res, {
      "revoke: status 204": (r) => r.status === 204,
    });

    if (success) keyRevocations.add(1);
  });

  group("7. Verify Revoked Key Fails", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:verify`,
      JSON.stringify({ credential: rotatedKey.secret }),
      {
        headers: Object.assign(publicHeaders(), { "Cache-Control": "no-cache" }),
        tags: { name: "verify" },
      },
    );

    check(res, {
      "verify-final: status 200": (r) => r.status === 200,
      "verify-final: active false": (r) => JSON.parse(r.body).is_active === false,
      "verify-final: error is revoked": (r) => {
        const code = JSON.parse(r.body).error_code;
        return code === "VERIFICATION_ERROR_REVOKED" || code === 3;
      },
    });
  });
}

// ============================================================================
// IMPORT LIFECYCLE: Import -> Verify -> Get -> List -> Delete -> Verify Fails
// ============================================================================
export function importLifecycle() {
  const uniqueId = `${RUN_ID}_vu${__VU}_iter${__ITER}`;
  const rawKey = `sk_lifecycle_${uniqueId}_${"x".repeat(20)}`;
  let importedKey = null;

  group("1. Import API Key", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/importedApiKeys`,
      JSON.stringify({
        raw_key: rawKey,
        name: `Import Lifecycle ${uniqueId}`,
        actor_id: `import-lifecycle-${uniqueId}`,
        scopes: ["read"],
        metadata: { test: "import-lifecycle", vu: __VU, iter: __ITER },
      }),
      { headers: authHeaders() },
    );

    if (res.status !== 201) {
      console.error(`Import failed: ${res.status} - ${res.body}`);
    }

    const success = check(res, {
      "import: status 201": (r) => r.status === 201,
      "import: has key_id": (r) => {
        if (r.status !== 201) return false;
        try {
          return JSON.parse(r.body).imported_api_key.key_id.length > 0;
        } catch {
          return false;
        }
      },
      "import: status active": (r) => {
        if (r.status !== 201) return false;
        try {
          const status = JSON.parse(r.body).imported_api_key.status;
          return status === "KEY_STATUS_ACTIVE" || status === 1;
        } catch {
          return false;
        }
      },
    });

    if (success && res.status === 201) {
      const body = JSON.parse(res.body);
      importedKey = { keyId: body.imported_api_key.key_id, rawKey: rawKey };
      keyImports.add(1);
    }
  });

  if (!importedKey) {
    fail("Cannot continue import lifecycle: import failed");
  }

  group("2. Verify Imported Key Works", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:verify`,
      JSON.stringify({ credential: importedKey.rawKey }),
      { headers: publicHeaders(), tags: { name: "verify" } },
    );

    check(res, {
      "verify-imported: status 200": (r) => r.status === 200,
      "verify-imported: active true": (r) => JSON.parse(r.body).is_active === true,
      "verify-imported: correct key_id": (r) => JSON.parse(r.body).key_id === importedKey.keyId,
    });
  });

  group("3. Get Imported Key", () => {
    const res = http.get(`${BASE_URL}/v2alpha1/admin/importedApiKeys/${importedKey.keyId}`, {
      headers: authHeaders(),
    });

    check(res, {
      "get-imported: status 200": (r) => r.status === 200,
      "get-imported: correct key_id": (r) => JSON.parse(r.body).key_id === importedKey.keyId,
    });
  });

  group("4. List Imported Keys", () => {
    const res = http.get(`${BASE_URL}/v2alpha1/admin/importedApiKeys?page_size=50`, {
      headers: authHeaders(),
    });

    check(res, {
      "list-imported: status 200": (r) => r.status === 200,
      "list-imported: has imported_api_keys array": (r) =>
        Array.isArray(JSON.parse(r.body).imported_api_keys),
    });
  });

  group("5. Delete Imported Key", () => {
    const res = http.del(`${BASE_URL}/v2alpha1/admin/importedApiKeys/${importedKey.keyId}`, null, {
      headers: authHeaders(),
    });

    if (res.status !== 204) {
      console.error(`Delete imported failed: ${res.status} - ${res.body}`);
    }

    const success = check(res, {
      "delete-imported: status 204": (r) => r.status === 204,
    });

    if (success) keyRevocations.add(1);
  });

  group("6. Verify Deleted Import Fails", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:verify`,
      JSON.stringify({ credential: importedKey.rawKey }),
      {
        headers: Object.assign(publicHeaders(), { "Cache-Control": "no-cache" }),
        tags: { name: "verify" },
      },
    );

    check(res, {
      "verify-deleted-import: status 200": (r) => r.status === 200,
      "verify-deleted-import: active false": (r) => JSON.parse(r.body).is_active === false,
    });
  });
}

// ============================================================================
// SELF-REVOKE LIFECYCLE: Import -> Verify -> Self-Revoke -> Verify Fails
// ============================================================================
export function selfRevokeLifecycle() {
  const uniqueId = `${RUN_ID}_vu${__VU}_iter${__ITER}`;
  const rawKey = `sk_selfrevoke_${uniqueId}_${"x".repeat(20)}`;
  let importedKey = null;

  group("1. Import Key for Self-Revoke", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/importedApiKeys`,
      JSON.stringify({
        raw_key: rawKey,
        name: `Self-Revoke Key ${uniqueId}`,
        actor_id: `self-revoke-${uniqueId}`,
        scopes: ["read"],
      }),
      { headers: authHeaders() },
    );

    if (res.status !== 201) {
      console.error(`Import for self-revoke failed: ${res.status} - ${res.body}`);
    }

    const success = check(res, {
      "self-revoke-import: status 201": (r) => r.status === 201,
      "self-revoke-import: has key_id": (r) => {
        if (r.status !== 201) return false;
        try {
          return JSON.parse(r.body).imported_api_key.key_id.length > 0;
        } catch {
          return false;
        }
      },
    });

    if (success && res.status === 201) {
      const body = JSON.parse(res.body);
      importedKey = { keyId: body.imported_api_key.key_id, rawKey: rawKey };
      keyImports.add(1);
    }
  });

  if (!importedKey) {
    fail("Cannot continue self-revoke lifecycle: import failed");
  }

  group("2. Verify Key Works Before Self-Revoke", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:verify`,
      JSON.stringify({ credential: importedKey.rawKey }),
      { headers: publicHeaders(), tags: { name: "verify" } },
    );

    check(res, {
      "self-revoke-verify-before: status 200": (r) => r.status === 200,
      "self-revoke-verify-before: active true": (r) => JSON.parse(r.body).is_active === true,
      "self-revoke-verify-before: correct key_id": (r) =>
        JSON.parse(r.body).key_id === importedKey.keyId,
    });
  });

  group("3. Self-Revoke Key (credential proof-of-possession)", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/apiKeys:selfRevoke`,
      JSON.stringify({
        credential: importedKey.rawKey,
        reason: "REVOCATION_REASON_KEY_COMPROMISE",
      }),
      { headers: publicHeaders() },
    );

    if (res.status !== 200) {
      console.error(`Self-revoke failed: ${res.status} - ${res.body}`);
    }

    const success = check(res, {
      "self-revoke: status 200": (r) => r.status === 200,
    });

    if (success) keySelfRevocations.add(1);
  });

  group("4. Verify Self-Revoked Key Fails", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:verify`,
      JSON.stringify({ credential: importedKey.rawKey }),
      {
        headers: Object.assign(publicHeaders(), { "Cache-Control": "no-cache" }),
        tags: { name: "verify" },
      },
    );

    check(res, {
      "self-revoke-verify-after: status 200": (r) => r.status === 200,
      "self-revoke-verify-after: active false": (r) => JSON.parse(r.body).is_active === false,
      "self-revoke-verify-after: has error_code": (r) => {
        const body = JSON.parse(r.body);
        return body.error_code === "VERIFICATION_ERROR_REVOKED" || body.error_code === 3;
      },
    });
  });
}

// ============================================================================
// BATCH IMPORT LIFECYCLE: Batch-import 3 keys -> verify -> clean up
// ============================================================================
export function batchImportLifecycle() {
  const uniqueId = `${RUN_ID}_vu${__VU}_iter${__ITER}`;
  const rawKeys = [
    `sk_batch_a_${uniqueId}_${"x".repeat(20)}`,
    `sk_batch_b_${uniqueId}_${"x".repeat(20)}`,
    `sk_batch_c_${uniqueId}_${"x".repeat(20)}`,
  ];
  let importedKeyIds = [];

  group("1. Batch Import 3 Keys", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/importedApiKeys:batchImport`,
      JSON.stringify({
        requests: rawKeys.map((rawKey, i) => ({
          raw_key: rawKey,
          name: `Batch Key ${i} ${uniqueId}`,
          actor_id: `batch-${uniqueId}`,
          scopes: ["read"],
        })),
      }),
      { headers: authHeaders() },
    );

    if (res.status !== 200 && res.status !== 201) {
      console.error(`Batch import failed: ${res.status} - ${res.body}`);
    }

    const success = check(res, {
      "batch-import: status 200": (r) => r.status === 200 || r.status === 201,
      "batch-import: success_count is 3": (r) => {
        if (r.status !== 200 && r.status !== 201) return false;
        try {
          return JSON.parse(r.body).success_count === 3;
        } catch {
          return false;
        }
      },
      "batch-import: failure_count is 0": (r) => {
        if (r.status !== 200 && r.status !== 201) return false;
        try {
          return JSON.parse(r.body).failure_count === 0;
        } catch {
          return false;
        }
      },
      "batch-import: has 3 results": (r) => {
        if (r.status !== 200 && r.status !== 201) return false;
        try {
          return JSON.parse(r.body).results.length === 3;
        } catch {
          return false;
        }
      },
    });

    if (success && (res.status === 200 || res.status === 201)) {
      const body = JSON.parse(res.body);
      importedKeyIds = body.results
        .filter((r) => r.imported_api_key)
        .map((r) => r.imported_api_key.key_id);
      keyImports.add(importedKeyIds.length);
    }
  });

  if (importedKeyIds.length === 0) {
    fail("Cannot continue batch import lifecycle: no keys imported");
  }

  group("2. Verify First Batch-Imported Key Works", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:verify`,
      JSON.stringify({ credential: rawKeys[0] }),
      { headers: publicHeaders(), tags: { name: "verify" } },
    );

    check(res, {
      "batch-verify: status 200": (r) => r.status === 200,
      "batch-verify: active true": (r) => JSON.parse(r.body).is_active === true,
      "batch-verify: correct key_id": (r) => JSON.parse(r.body).key_id === importedKeyIds[0],
    });
  });

  group("3. Clean Up: Delete All Batch-Imported Keys", () => {
    for (const keyId of importedKeyIds) {
      const res = http.del(`${BASE_URL}/v2alpha1/admin/importedApiKeys/${keyId}`, null, {
        headers: authHeaders(),
      });

      check(res, {
        "batch-cleanup: status 204": (r) => r.status === 204,
      });
    }
    keyRevocations.add(importedKeyIds.length);
  });
}

// ============================================================================
// NID ISOLATION: Cross-tenant credential isolation test
// ============================================================================
export function nidIsolation() {
  const uniqueId = `${RUN_ID}_vu${__VU}_iter${__ITER}`;
  const tenantA = "tenant-a.localhost";
  const tenantB = "tenant-b.localhost";
  let keyId = null;
  let secret = null;

  group("1. Create Key in Tenant A", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/issuedApiKeys`,
      JSON.stringify({
        name: `NID Isolation ${uniqueId}`,
        actor_id: `nid-test-${uniqueId}`,
        scopes: ["read"],
      }),
      { headers: authHeadersForTenant(tenantA) },
    );

    if (res.status !== 201) {
      console.error(`NID create failed: ${res.status} - ${res.body}`);
    }

    const success = check(res, {
      "nid-create: status 201": (r) => r.status === 201,
    });

    if (success && res.status === 201) {
      const body = JSON.parse(res.body);
      keyId = body.issued_api_key.key_id;
      secret = body.secret;
      keyCreations.add(1);
    }
  });

  if (!keyId) {
    fail("Cannot continue NID isolation: key creation in tenant A failed");
  }

  group("2. Verify Key Works in Tenant A", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:verify`,
      JSON.stringify({ credential: secret }),
      {
        headers: publicHeadersForTenant(tenantA),
        tags: { name: "verify" },
      },
    );

    check(res, {
      "nid-verify-a: status 200": (r) => r.status === 200,
      "nid-verify-a: active true": (r) => JSON.parse(r.body).is_active === true,
      "nid-verify-a: correct key_id": (r) => JSON.parse(r.body).key_id === keyId,
    });
  });

  group("3. Verify Key Fails in Tenant B (Cross-Tenant)", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:verify`,
      JSON.stringify({ credential: secret }),
      {
        headers: Object.assign(publicHeadersForTenant(tenantB), { "Cache-Control": "no-cache" }),
        tags: { name: "verify" },
      },
    );

    check(res, {
      "nid-verify-b: status 200": (r) => r.status === 200,
      "nid-verify-b: active false": (r) => JSON.parse(r.body).is_active === false,
      "nid-verify-b: rejected": (r) => {
        const body = JSON.parse(r.body);
        // Cross-tenant credentials are rejected either by prefix mismatch (INVALID_FORMAT)
        // or by NID-scoped DB lookup (NOT_FOUND). Both indicate correct tenant isolation.
        return (
          body.error_code === "VERIFICATION_ERROR_INVALID_FORMAT" ||
          body.error_code === 1 ||
          body.error_code === "VERIFICATION_ERROR_NOT_FOUND" ||
          body.error_code === 4
        );
      },
    });
  });

  group("4. Cleanup: Revoke Key in Tenant A", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys/${keyId}:revoke`,
      JSON.stringify({ reason: "REVOCATION_REASON_UNSPECIFIED" }),
      { headers: authHeadersForTenant(tenantA) },
    );

    check(res, {
      "nid-cleanup: status 204": (r) => r.status === 204,
    });
    keyRevocations.add(1);
  });
}

// ============================================================================
// MACAROON DERIVATION: Derive macaroon token and verify it
// ============================================================================
export function macaroonDerivation(data) {
  if (!data.macaroonKey) {
    fail("No macaroon key available from setup");
  }

  const key = data.macaroonKey;

  group("1. Derive Macaroon Token", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:derive`,
      JSON.stringify({
        credential: key.secret,
        algorithm: "TOKEN_ALGORITHM_MACAROON",
        ttl: "3600s",
        scopes: ["read"],
      }),
      { headers: authHeaders() },
    );

    if (res.status !== 200) {
      console.error(`Macaroon derive failed: ${res.status} - ${res.body}`);
    }

    let token = null;
    const success = check(res, {
      "macaroon-derive: status 200": (r) => r.status === 200,
      "macaroon-derive: has token": (r) => {
        if (r.status !== 200) return false;
        try {
          token = JSON.parse(r.body).token.token;
          return token.length > 0;
        } catch {
          return false;
        }
      },
      "macaroon-derive: token has mc prefix": () => {
        return token !== null && token.startsWith("mc_v1_");
      },
    });

    if (success) tokenDerivations.add(1);

    if (token) {
      group("2. Verify Derived Macaroon", () => {
        const verifyRes = http.post(
          `${BASE_URL}/v2alpha1/admin/apiKeys:verify`,
          JSON.stringify({ credential: token }),
          { headers: publicHeaders(), tags: { name: "verify" } },
        );

        check(verifyRes, {
          "macaroon-verify: status 200": (r) => r.status === 200,
          "macaroon-verify: active true": (r) => JSON.parse(r.body).is_active === true,
        });

        verifications.add(1);
      });
    }
  });
}

// ============================================================================
// PAGINATION CURSOR: Verify page_token round-trip returns different keys
// ============================================================================
export function paginationCursor() {
  let page1Keys = [];
  let nextToken = null;

  group("1. List Page 1", () => {
    const res = http.get(`${BASE_URL}/v2alpha1/admin/issuedApiKeys?page_size=3`, {
      headers: authHeaders(),
    });

    const success = check(res, {
      "page1: status 200": (r) => r.status === 200,
      "page1: has keys": (r) => {
        if (r.status !== 200) return false;
        try {
          return JSON.parse(r.body).issued_api_keys.length > 0;
        } catch {
          return false;
        }
      },
      "page1: has next_page_token": (r) => {
        if (r.status !== 200) return false;
        try {
          const body = JSON.parse(r.body);
          return body.next_page_token && body.next_page_token.length > 0;
        } catch {
          return false;
        }
      },
    });

    if (success && res.status === 200) {
      const body = JSON.parse(res.body);
      page1Keys = body.issued_api_keys.map((k) => k.key_id);
      nextToken = body.next_page_token;
    }
  });

  if (!nextToken) {
    fail("Cannot continue pagination: no next_page_token on page 1");
  }

  group("2. List Page 2", () => {
    const res = http.get(
      `${BASE_URL}/v2alpha1/admin/issuedApiKeys?page_size=3&page_token=${encodeURIComponent(nextToken)}`,
      { headers: authHeaders() },
    );

    check(res, {
      "page2: status 200": (r) => r.status === 200,
      "page2: has keys": (r) => {
        if (r.status !== 200) return false;
        try {
          return JSON.parse(r.body).issued_api_keys.length > 0;
        } catch {
          return false;
        }
      },
      "page2: no overlap with page 1": (r) => {
        if (r.status !== 200) return false;
        try {
          const page2Keys = JSON.parse(r.body).issued_api_keys.map((k) => k.key_id);
          return page2Keys.every((k) => !page1Keys.includes(k));
        } catch {
          return false;
        }
      },
    });
  });
}

// ============================================================================
// BATCH BOUNDARY: Test batch-verify at the limit (100) and over (101)
// ============================================================================
export function batchBoundaryTest(data) {
  if (!data.batchBoundaryKeys || data.batchBoundaryKeys.length < 100) {
    fail("Not enough batch boundary keys from setup");
  }

  group("1. Batch Verify 100 Keys (At Limit)", () => {
    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:batchVerify`,
      JSON.stringify({
        requests: data.batchBoundaryKeys.map((k) => ({ credential: k.secret })),
      }),
      { headers: publicHeaders() },
    );

    check(res, {
      "batch-100: status 200": (r) => r.status === 200,
      "batch-100: has 100 results": (r) => {
        if (r.status !== 200) return false;
        try {
          return JSON.parse(r.body).results.length === 100;
        } catch {
          return false;
        }
      },
      "batch-100: all active": (r) => {
        if (r.status !== 200) return false;
        try {
          return JSON.parse(r.body).results.every((resp) => resp.is_active === true);
        } catch {
          return false;
        }
      },
    });
  });

  group("2. Batch Verify 101 Keys (Over Limit)", () => {
    const overLimitRequests = data.batchBoundaryKeys.map((k) => ({ credential: k.secret }));
    overLimitRequests.push({ credential: "sk_extra_over_limit_key" });

    const res = http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys:batchVerify`,
      JSON.stringify({ requests: overLimitRequests }),
      {
        headers: publicHeaders(),
        responseCallback: http.expectedStatuses(400),
      },
    );

    check(res, {
      "batch-101: rejected": (r) => r.status === 400,
    });
  });
}

// ============================================================================
// TEARDOWN: Clean up all setup-created keys
// ============================================================================
export function teardown(data) {
  console.log("Teardown starting...");

  // Revoke read keys
  for (const key of data.readKeys || []) {
    http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys/${key.keyId}:revoke`,
      JSON.stringify({ reason: "REVOCATION_REASON_UNSPECIFIED" }),
      { headers: authHeaders() },
    );
  }

  // Delete imported read keys
  for (const key of data.importedReadKeys || []) {
    http.del(`${BASE_URL}/v2alpha1/admin/importedApiKeys/${key.keyId}`, null, {
      headers: authHeaders(),
    });
  }

  // Revoke macaroon test key
  if (data.macaroonKey) {
    http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys/${data.macaroonKey.keyId}:revoke`,
      JSON.stringify({ reason: "REVOCATION_REASON_UNSPECIFIED" }),
      { headers: authHeaders() },
    );
  }

  // Revoke batch boundary keys
  for (const key of data.batchBoundaryKeys || []) {
    http.post(
      `${BASE_URL}/v2alpha1/admin/apiKeys/${key.keyId}:revoke`,
      JSON.stringify({ reason: "REVOCATION_REASON_UNSPECIFIED" }),
      { headers: authHeaders() },
    );
  }

  console.log("Teardown complete.");
}
