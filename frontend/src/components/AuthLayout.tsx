import type { ReactNode } from "react";

/**
 * The frame of a signed-out page: a small label, the title, one sentence, the ink tab on its
 * hairline, then the content. The forms sit on the paper; only dialogs float.
 */
export function AuthLayout({ eyebrow, title, subtitle, children }: {
  readonly eyebrow: string;
  readonly title: string;
  readonly subtitle?: string;
  readonly children: ReactNode;
}) {
  return (
    <div className="mx-auto w-full max-w-[30rem] px-4 pt-10 pb-16 sm:pt-14">
      <p className="font-label text-muted-foreground mb-2.5 text-label">{eyebrow}</p>
      <h1 className="text-title font-bold text-balance">
        {title}
      </h1>
      {subtitle && <p className="text-muted-foreground mt-3 max-w-[56ch] text-pretty">{subtitle}
      </p>}
      <div aria-hidden="true" className="page-rule" />
      <div className="mt-6">{children}</div>
    </div>
  );
}
