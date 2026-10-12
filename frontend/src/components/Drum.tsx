import { cn } from "@/lib/utils";

/**
 * The waiting mark: three dots that tap in sequence, like a woodpecker on timber. It replaces a
 * spinner wherever the app waits for a scan. It is decoration only; the words next to it say what
 * is happening, so it is hidden from assistive technology. Reduced motion stills it.
 */
export function Drum({ className }: { readonly className?: string; }) {
  return (
    <span aria-hidden="true" className={cn("drum inline-flex h-3.5 items-center gap-1", className)}>
      <i />
      <i />
      <i />
    </span>
  );
}
