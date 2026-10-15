import { FormField } from "@/components/FormField";
import { PasswordRequirements } from "@/components/PasswordRequirements";
import { PasswordStrength } from "@/components/PasswordStrength";
import { type ComponentProps, useState } from "react";

/**
 * A field for choosing a new password: the input, the rules the server enforces, and a strength
 * meter as advice. The meter's estimator loads only once the field is focused or has a value.
 * `userInputs` are words from the person's own account, such as their email, that the meter counts
 * against the password.
 */
export function PasswordField({ rulesId, userInputs, value, onFocus, ...field }: {
  /** The id of the rules list, which the input names as its description. */
  readonly rulesId: string;
  readonly userInputs?: readonly string[];
  readonly value: string;
} & Omit<ComponentProps<typeof FormField>, "type" | "extra" | "value">) {
  const [focused, setFocused] = useState(false);
  return (
    <FormField
      type="password"
      autoComplete="new-password"
      {...field}
      value={value}
      onFocus={(e) => {
        setFocused(true);
        onFocus?.(e);
      }}
      extra={{
        id: rulesId,
        node: (
          <>
            <PasswordRequirements id={rulesId} value={value} />
            <PasswordStrength
              value={value}
              active={focused || value !== ""}
              {...(userInputs ? { userInputs } : {})}
            />
          </>
        ),
      }}
    />
  );
}
