// SPDX-License-Identifier: Apache-2.0
import { Button } from "@scoplen/ui";
import { useState } from "react";
import { useI18n } from "./i18n";
import { useInventory, type OpenSshExportPreview, type OpenSshImportPreview } from "./inventory/api";
import { OpenSshExportDialog, openSshExportErrorText } from "./inventory/openssh-export";
import { OpenSshImportDialog, openSshImportErrorText } from "./inventory/openssh-import";

/** Reviewed OpenSSH migration for the current Local or Account profile. */
export function InventoryTransferSettings() {
  const { t } = useI18n();
  const api = useInventory();
  const [importPreview, setImportPreview] = useState<OpenSshImportPreview | null>(null);
  const [exportPreview, setExportPreview] = useState<OpenSshExportPreview | null>(null);
  const [preparing, setPreparing] = useState<"import" | "export" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  const prepare = async (kind: "import" | "export") => {
    if (preparing) return;
    setPreparing(kind);
    setError(null);
    setDone(null);
    try {
      if (kind === "import") {
        const path = await api.chooseOpenSshConfig();
        if (!path) return;
        const result = await api.previewOpenSshConfig(path);
        if (result.status === "ok") setImportPreview(result.data);
        else setError(`${t("import.previewError")} ${openSshImportErrorText(t, result.error)}`);
      } else {
        const result = await api.previewOpenSshExport();
        if (result.status === "ok") setExportPreview(result.data);
        else setError(openSshExportErrorText(t, result.error));
      }
    } catch {
      setError(t(kind === "import" ? "import.error.picker" : "export.error.preview"));
    } finally {
      setPreparing(null);
    }
  };

  return (
    <section aria-labelledby="inventory-transfer-title" className="mt-8 border-t border-border pt-8">
      <h2 id="inventory-transfer-title" className="ui-display text-lg">
        {t("settings.transfer.title")}
      </h2>
      <p className="mt-2 max-w-lg text-sm text-muted-foreground">{t("settings.transfer.body")}</p>
      <div className="mt-4 flex flex-wrap gap-3">
        <Button busy={preparing === "import"} disabled={preparing !== null} onClick={() => void prepare("import")}>
          {t("hosts.importOpenSsh")}
        </Button>
        <Button busy={preparing === "export"} disabled={preparing !== null} onClick={() => void prepare("export")}>
          {t("hosts.exportOpenSsh")}
        </Button>
      </div>
      {error ? (
        <p role="alert" className="mt-3 text-sm text-attention">
          {error}
        </p>
      ) : null}
      {done ? (
        <p role="status" className="mt-3 text-sm text-muted-foreground">
          {done}
        </p>
      ) : null}
      {importPreview ? (
        <OpenSshImportDialog
          initial={importPreview}
          onClose={() => setImportPreview(null)}
          onImported={(result) => {
            setImportPreview(null);
            setDone(
              t("import.done", {
                created: result.created,
                updated: result.updated,
                unchanged: result.unchanged,
                skipped: result.skippedHosts.length,
                trust: result.trustRecords,
              }),
            );
          }}
        />
      ) : null}
      {exportPreview ? <OpenSshExportDialog initial={exportPreview} onClose={() => setExportPreview(null)} /> : null}
    </section>
  );
}
