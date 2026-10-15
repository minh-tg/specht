import { APIError } from "@/api/client";

/** The password limits the server enforces. The upper one is in bytes, because the hash reads bytes. */
export const PASSWORD_MIN_LENGTH = 8;
export const PASSWORD_MAX_BYTES = 72;
/** The byte rule shows once the password is this close to the limit, or over it. */
export const PASSWORD_BYTES_WARNING_MARGIN = 12;

export interface PasswordRule {
  readonly id: string;
  readonly label: (password: string) => string;
  readonly met: (password: string) => boolean;
  /** Whether the rule is worth showing for this password. A hidden rule still counts. */
  readonly shown: (password: string) => boolean;
}

export const passwordByteLength = (value: string) => new TextEncoder().encode(value).length;

export const passwordRules: readonly PasswordRule[] = [
  {
    id: "min",
    label: () => `At least ${PASSWORD_MIN_LENGTH} characters`,
    met: (password) => [...password].length >= PASSWORD_MIN_LENGTH,
    shown: () => true,
  },
  {
    id: "max",
    label: (password) =>
      `At most ${PASSWORD_MAX_BYTES} bytes: ${
        passwordByteLength(password)
      } of ${PASSWORD_MAX_BYTES} bytes`,
    met: (password) => passwordByteLength(password) <= PASSWORD_MAX_BYTES,
    // Most passwords are nowhere near the limit, so the rule only appears when it matters.
    shown: (password) =>
      passwordByteLength(password) >= PASSWORD_MAX_BYTES - PASSWORD_BYTES_WARNING_MARGIN,
  },
];

export function isPasswordValid(password: string): boolean {
  return passwordRules.every((rule) => rule.met(password));
}

/** The server's refusals of a password that meets the length rules: listed, or the account's own email or name. */
const PASSWORD_POLICY_CODES: ReadonlySet<string> = new Set([
  "password_too_common",
  "password_matches_account",
]);

/**
 * The server's message when it refused the password itself, for the password field to show. Any
 * other error returns null and stays with the form.
 */
export function passwordPolicyMessage(err: unknown): string | null {
  return err instanceof APIError && PASSWORD_POLICY_CODES.has(err.code) ? err.message : null;
}
