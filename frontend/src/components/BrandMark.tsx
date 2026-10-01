/**
 * The Specht mark: a woodpecker head in profile (a bird that taps to find what
 * is hollow). Decorative, so it is hidden from assistive technology; the word
 * "Specht" next to it carries the name. It inherits the text colour.
 */
export function BrandMark({ className }: { readonly className?: string; }) {
  return (
    <svg
      viewBox="0 0 32 32"
      fill="currentColor"
      aria-hidden="true"
      focusable="false"
      className={className}
    >
      <path
        fillRule="evenodd"
        d="M13 5a9.5 9.5 0 1 0 0 19a9.5 9.5 0 1 0 0-19Zm1.5 5.5a2.2 2.2 0 1 1 0 4.4a2.2 2.2 0 1 1 0-4.4Z"
      />
      <path d="M21 12.2 31 15.4 21 18.6Z" />
      <path d="M6.5 8.2 2.5 3.5 11 5.2Z" />
    </svg>
  );
}
