// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef } from "react";
import { events, type RecordType, type StoreChanged } from "./bindings";
import { useProfile } from "../account-profiles";

/**
 * Calls `onChange` whenever objects of one of `types` change in the local
 * store, after the change is committed. Views use it to reload what they show.
 */
export function useStoreChanges(types: readonly RecordType[], onChange: (change: StoreChanged) => void) {
  const generation = useProfile()?.snapshot.generation;
  const latest = useRef(onChange);
  useEffect(() => {
    latest.current = onChange;
  });
  const key = types.join(",");
  useEffect(() => {
    const wanted = new Set(key.split(","));
    let stop: (() => void) | undefined;
    let cancelled = false;
    void events.storeChanged
      .listen((event) => {
        if (
          !cancelled &&
          (generation === undefined || event.payload.profileGeneration === generation) &&
          wanted.has(event.payload.recordType)
        )
          latest.current(event.payload);
      })
      .then((unlisten) => {
        if (cancelled) unlisten();
        else stop = unlisten;
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
      stop?.();
    };
  }, [key, generation]);
}
