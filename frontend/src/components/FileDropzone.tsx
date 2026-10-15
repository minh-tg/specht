import { Button } from "@/components/ui/button";
import { buttonVariants } from "@/components/ui/button-variants";
import { cn } from "@/lib/utils";
import { type ChangeEvent, type DragEvent, type RefObject, useState } from "react";

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

interface FileDropzoneProps {
  /** Id of the real file input, which the page's own <label> points at. */
  readonly id: string;
  readonly inputRef: RefObject<HTMLInputElement | null>;
  /** Extensions with their dot, such as ".json". The picker filters by them; a drop is checked against them. */
  readonly accept: readonly string[];
  /** Id of the hint text the input should also be described by. */
  readonly describedBy?: string;
  readonly fileName: string | null;
  readonly fileSize: number | null;
  /** Why the file the person chose was refused. */
  readonly error: string | null;
  readonly disabled?: boolean;
  /** The picker's change event. */
  readonly onChange: (event: ChangeEvent<HTMLInputElement>) => void;
  /** A file that was dropped and passed the drop checks here. */
  readonly onFile: (file: File) => void;
  readonly onClear: () => void;
}

/**
 * A file field with a drop area. The visible "Choose file" is a label bound to the visually hidden
 * input, so Tab stops once. While a file is held, the input leaves the tab order and Remove takes
 * its place. A drop ignores `accept`, so the extension and the file count are checked here.
 */
export function FileDropzone({
  id,
  inputRef,
  accept,
  describedBy,
  fileName,
  fileSize,
  error,
  disabled = false,
  onChange,
  onFile,
  onClear,
}: FileDropzoneProps) {
  const [dragging, setDragging] = useState(false);
  const [dropError, setDropError] = useState<string | null>(null);
  const shownError = dropError ?? error;
  const errorId = `${id}-error`;
  const filled = fileName !== null;

  function handleDragOver(event: DragEvent<HTMLDivElement>) {
    if (disabled) return;
    // Without this the browser opens the file instead of firing drop.
    event.preventDefault();
    setDragging(true);
  }

  function handleDragLeave(event: DragEvent<HTMLDivElement>) {
    if (event.relatedTarget instanceof Node && event.currentTarget.contains(event.relatedTarget)) {
      return;
    }
    setDragging(false);
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    if (disabled) return;
    const files = event.dataTransfer.files;
    if (files.length === 0) return;
    if (files.length > 1) {
      setDropError("Drop one file at a time.");
      return;
    }
    const dropped = files[0]!;
    const lower = dropped.name.toLowerCase();
    if (!accept.some((ext) => lower.endsWith(ext))) {
      setDropError(
        `${dropped.name} is not a supported file. Use ${accept.slice(0, -1).join(", ")} or ${
          accept.at(-1)
        }.`,
      );
      return;
    }
    setDropError(null);
    onFile(dropped);
  }

  function handleChange(event: ChangeEvent<HTMLInputElement>) {
    setDropError(null);
    onChange(event);
  }

  function handleClear() {
    setDropError(null);
    onClear();
    inputRef.current?.focus();
  }

  return (
    <div>
      <div
        data-testid="file-dropzone"
        data-dragging={dragging ? "true" : undefined}
        onDragEnter={handleDragOver}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={cn(
          "mt-1 flex flex-col items-start gap-2 rounded-lg border border-dashed p-4 sm:flex-row sm:items-center sm:gap-3",
          "transition-[border-color,background-color] duration-(--dur-quick) ease-entering",
          "border-input hover:border-ring hover:bg-muted/40",
          "data-[dragging=true]:border-action data-[dragging=true]:bg-muted",
          filled && "border-solid",
          shownError && "border-destructive",
          disabled && "pointer-events-none opacity-50",
          "has-[input:focus-visible]:outline-(length:--focus-ring-width) has-[input:focus-visible]:outline-action has-[input:focus-visible]:outline-offset-(--focus-ring-offset)",
        )}
      >
        <input
          id={id}
          ref={inputRef}
          type="file"
          accept={accept.join(",")}
          disabled={disabled}
          tabIndex={filled ? -1 : undefined}
          aria-invalid={shownError ? true : undefined}
          aria-describedby={[describedBy, shownError ? errorId : undefined].filter(Boolean).join(
            " ",
          ) || undefined}
          onChange={handleChange}
          className="sr-only"
        />
        {filled
          ? (
            <>
              <p className="min-w-0 text-sm break-all">
                <span className="font-medium">{fileName}</span>
                {fileSize !== null && (
                  <span className="text-muted-foreground ml-2 text-xs tabular-nums">
                    {formatSize(fileSize)}
                  </span>
                )}
              </p>
              <Button
                type="button"
                variant="outline"
                size="sm"
                aria-label={`Remove ${fileName}`}
                onClick={handleClear}
              >
                Remove
              </Button>
            </>
          )
          : (
            <>
              <label
                htmlFor={id}
                className={cn(buttonVariants({ variant: "outline" }), "cursor-pointer")}
              >
                Choose file
              </label>
              <span className="text-muted-foreground text-sm">or drop it here</span>
            </>
          )}
      </div>
      {shownError && (
        <p id={errorId} role="alert" className="text-destructive mt-1 text-xs">{shownError}</p>
      )}
    </div>
  );
}
