// SPDX-License-Identifier: Apache-2.0
import { dismissUploadAttention, initialUploadAttention, recordUploadAttention } from "../src/session-upload-attention";

it("deduplicates an old result across dismissal while preserving newly learned risk", () => {
  const old = {
    transportId: "old-transport",
    operationId: "old-operation",
    status: "unknown",
    stagingMayRemain: false,
  } as const;
  const first = recordUploadAttention(initialUploadAttention, old);
  expect(first).toMatchObject({ unknown: true, stagingMayRemain: false });
  expect(recordUploadAttention(first, old)).toBe(first);

  const dismissed = dismissUploadAttention(first);
  expect(dismissed).toMatchObject({ unknown: false, stagingMayRemain: false });
  expect(recordUploadAttention(dismissed, old)).toBe(dismissed);

  const stronger = recordUploadAttention(dismissed, { ...old, stagingMayRemain: true });
  expect(stronger).toMatchObject({ unknown: true, stagingMayRemain: true });
  expect(stronger.recent).toHaveLength(1);
});

it("retains cumulative warnings while bounding operation identifiers", () => {
  let attention = initialUploadAttention;
  for (let index = 0; index < 100; index++) {
    attention = recordUploadAttention(attention, {
      transportId: `transport-${index % 3}`,
      operationId: `operation-${index}`,
      status: index === 0 ? "unknown" : "failed",
      stagingMayRemain: index > 0,
    });
  }
  expect(attention.recent).toHaveLength(32);
  expect(attention.recent[0]?.operationId).toBe("operation-68");
  expect(attention).toMatchObject({ unknown: true, stagingMayRemain: true });

  const dismissed = dismissUploadAttention(attention);
  const next = recordUploadAttention(dismissed, {
    transportId: "new-transport",
    operationId: "new-operation",
    status: "failed",
    stagingMayRemain: true,
  });
  expect(next).toMatchObject({ unknown: false, stagingMayRemain: true });
  expect(next.recent).toHaveLength(32);
});

it("keeps a staging warning after its operation leaves the recent window", () => {
  let attention = recordUploadAttention(initialUploadAttention, {
    transportId: "old-transport",
    operationId: "old-staging",
    status: "failed",
    stagingMayRemain: true,
  });
  for (let index = 0; index < 40; index++) {
    attention = recordUploadAttention(attention, {
      transportId: "new-transport",
      operationId: `unknown-${index}`,
      status: "unknown",
      stagingMayRemain: false,
    });
  }
  expect(attention.recent).toHaveLength(32);
  expect(attention.recent.some((item) => item.operationId === "old-staging")).toBe(false);
  expect(attention).toMatchObject({ unknown: true, stagingMayRemain: true });
});
