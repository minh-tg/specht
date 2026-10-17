import { APIError } from "@/api/client";

/** What the form says when the server refused an address for holding a character the reader cannot see. */
export const HIDDEN_EMAIL_CHARACTERS_MESSAGE =
  "This email has hidden characters. Retype it instead of pasting it.";

/**
 * The hidden-character message when the server refused the address for that reason. Any other
 * error returns null and stays with the form's own message.
 */
export function hiddenEmailCharactersMessage(err: unknown): string | null {
  return err instanceof APIError && err.code === "invalid_email_characters"
    ? HIDDEN_EMAIL_CHARACTERS_MESSAGE
    : null;
}
