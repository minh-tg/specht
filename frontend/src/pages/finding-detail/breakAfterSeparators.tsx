import { Fragment, type ReactNode } from "react";

/**
 * An identifier with a line-break chance after each separator, so a narrow column breaks
 * "CVE-2026-4800:pkg:npm/lodash@4.17.20" between its parts and never inside "npm".
 */
export function breakAfterSeparators(text: string): ReactNode {
  return text.split(/(?<=[:/|@])/).map((part, i) => (
    <Fragment key={i}>
      {i > 0 && <wbr />}
      {part}
    </Fragment>
  ));
}
