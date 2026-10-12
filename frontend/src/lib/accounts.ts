/**
 * The account the server seeds to act for things that have no person behind them, such as an API key
 * created before keys recorded their owner. It is not someone to manage, so account lists leave it out.
 */
export const SYSTEM_ACCOUNT_EMAIL = "system@specht.local";

export function isSystemAccount(user: { readonly email: string; }): boolean {
  return user.email.toLowerCase() === SYSTEM_ACCOUNT_EMAIL;
}
