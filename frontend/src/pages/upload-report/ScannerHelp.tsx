import type { ScannerDescriptor } from "@/types/api";

/**
 * What the chosen scanner reads: each format with the extensions the page takes, the command
 * that produces the file, and the version it was checked with. It sits under the picker so a
 * person who picked the wrong tool sees it before uploading.
 */
export function ScannerHelp({ scanner }: { readonly scanner: ScannerDescriptor | undefined; }) {
  if (!scanner || !scanner.formats?.length) return null;
  return (
    <section
      aria-label={`How to produce a ${scanner.display_name} file`}
      className="border-border mt-2 space-y-3 rounded-md border p-3"
    >
      <h3 className="text-body font-semibold">{scanner.display_name} reads</h3>
      <ul className="m-0 list-none space-y-3 p-0">
        {scanner.formats.map((format) => (
          <li key={format.name} className="space-y-1">
            <p className="text-body">
              <span className="font-medium">{format.name}</span>
              <span className="text-muted-foreground">{` (${format.extensions.join(", ")})`}</span>
            </p>
            <code className="bg-muted block rounded px-2 py-1 font-mono text-code break-all">
              {format.command}
            </code>
            <p className="text-muted-foreground text-meta">Checked with {format.tested_with}</p>
            {format.note && <p className="text-muted-foreground text-meta">{format.note}</p>}
          </li>
        ))}
      </ul>
    </section>
  );
}
