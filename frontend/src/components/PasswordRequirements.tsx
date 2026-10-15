import { passwordRules } from "@/lib/passwordRules";
import { CheckIcon, XIcon } from "lucide-react";

/**
 * The password rules, shown once the person starts typing. Each rule is red with
 * a cross until it holds and green with a check once it does. The state is also
 * written out for screen readers, so colour is never the only signal. The byte
 * rule appears only near the limit.
 */
export function PasswordRequirements({ id, value }: {
  readonly id: string;
  readonly value: string;
}) {
  if (value === "") return null;
  return (
    <ul id={id} aria-label="Requirements" className="grid gap-1 text-[0.8125rem]">
      {passwordRules.filter((rule) => rule.shown(value)).map((rule) => {
        const met = rule.met(value);
        return (
          <li
            key={rule.id}
            data-met={met}
            className={`flex items-center gap-1.5 ${
              met ? "text-sev-success-fg" : "text-destructive"
            }`}
          >
            {met
              ? <CheckIcon aria-hidden="true" className="size-3.5 shrink-0" />
              : <XIcon aria-hidden="true" className="size-3.5 shrink-0" />}
            <span>
              {rule.label(value)}
              <span className="sr-only">{` (${met ? "met" : "not met"})`}</span>
            </span>
          </li>
        );
      })}
    </ul>
  );
}
