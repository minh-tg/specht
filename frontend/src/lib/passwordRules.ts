/** The password limits the server enforces. The upper one is in bytes, because the hash reads bytes. */
export const PASSWORD_MIN_LENGTH = 8;
export const PASSWORD_MAX_BYTES = 72;

export interface PasswordRule {
  readonly id: string;
  readonly label: string;
  readonly met: (password: string) => boolean;
}

const byteLength = (value: string) => new TextEncoder().encode(value).length;

export const passwordRules: readonly PasswordRule[] = [
  {
    id: "min",
    label: `At least ${PASSWORD_MIN_LENGTH} characters`,
    met: (password) => [...password].length >= PASSWORD_MIN_LENGTH,
  },
  {
    id: "max",
    label: `At most ${PASSWORD_MAX_BYTES} bytes`,
    met: (password) => byteLength(password) <= PASSWORD_MAX_BYTES,
  },
];

export function isPasswordValid(password: string): boolean {
  return passwordRules.every((rule) => rule.met(password));
}
