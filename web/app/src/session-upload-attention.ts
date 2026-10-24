// SPDX-License-Identifier: Apache-2.0
import type { RemoteFileOutcome } from "./session-files";

const recentLimit = 32;

type RecentUpload = {
  transportId: string;
  operationId: string;
  unknown: boolean;
  stagingMayRemain: boolean;
};

export type UploadAttention = {
  recent: RecentUpload[];
  unknown: boolean;
  stagingMayRemain: boolean;
};

export const initialUploadAttention: UploadAttention = { recent: [], unknown: false, stagingMayRemain: false };

export function recordUploadAttention(current: UploadAttention, outcome: RemoteFileOutcome): UploadAttention {
  const unknown = outcome.status === "unknown";
  if (!unknown && !outcome.stagingMayRemain) return current;
  const index = current.recent.findIndex(
    (item) => item.transportId === outcome.transportId && item.operationId === outcome.operationId,
  );
  if (index !== -1) {
    const previous = current.recent[index]!;
    if ((!unknown || previous.unknown) && (!outcome.stagingMayRemain || previous.stagingMayRemain)) return current;
    const recent = [...current.recent];
    recent[index] = {
      ...previous,
      unknown: previous.unknown || unknown,
      stagingMayRemain: previous.stagingMayRemain || outcome.stagingMayRemain,
    };
    return {
      recent,
      unknown: current.unknown || unknown,
      stagingMayRemain: current.stagingMayRemain || outcome.stagingMayRemain,
    };
  }
  return {
    recent: [
      ...current.recent.slice(-(recentLimit - 1)),
      {
        transportId: outcome.transportId,
        operationId: outcome.operationId,
        unknown,
        stagingMayRemain: outcome.stagingMayRemain,
      },
    ],
    unknown: current.unknown || unknown,
    stagingMayRemain: current.stagingMayRemain || outcome.stagingMayRemain,
  };
}

export function dismissUploadAttention(current: UploadAttention): UploadAttention {
  return current.unknown || current.stagingMayRemain
    ? { ...current, unknown: false, stagingMayRemain: false }
    : current;
}
