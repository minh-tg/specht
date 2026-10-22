import type { LoginResponse } from "@/types/api";

interface Rotation {
  currentToken: string;
  result?: LoginResponse;
  pending?: Promise<LoginResponse>;
  tokens: Set<string>;
  forgotten: boolean;
}

/** One owner for a refresh family. Spent tokens resolve to the rotation already
 * in progress or completed, rather than reaching the server a second time.
 * The worker keeps this state in memory only, until its last tab closes. */
export function createRefreshBroker(refresh: (token: string) => Promise<LoginResponse>) {
  const families = new Map<string, Rotation>();

  function forget(token: string) {
    const family = families.get(token);
    if (!family) return;
    family.forgotten = true;
    for (const key of family.tokens) families.delete(key);
  }

  async function rotate(token: string): Promise<LoginResponse> {
    let family = families.get(token);
    if (!family) {
      family = { currentToken: token, tokens: new Set([token]), forgotten: false };
      families.set(token, family);
    }
    if (family.pending) return family.pending;
    if (token !== family.currentToken && family.result) return family.result;
    const active = family;
    active.pending = refresh(token).then((result) => {
      if (active.forgotten) throw new Error("The session ended while it was refreshing");
      active.currentToken = result.refresh_token;
      active.result = result;
      active.tokens.add(result.refresh_token);
      families.set(result.refresh_token, active);
      return result;
    }).finally(() => {
      active.pending = undefined;
    });
    return active.pending;
  }

  function peek(token: string): LoginResponse | undefined {
    const family = families.get(token);
    return family && token !== family.currentToken ? family.result : undefined;
  }

  function adopt(token: string, result: LoginResponse) {
    let family = families.get(token);
    // Late replies about an older ancestor must not replace a newer rotation.
    if (family && token !== family.currentToken) return;
    if (!family) {
      family = { currentToken: token, tokens: new Set([token]), forgotten: false };
      families.set(token, family);
    }
    family.currentToken = result.refresh_token;
    family.result = result;
    family.tokens.add(result.refresh_token);
    families.set(result.refresh_token, family);
  }

  return { rotate, forget, peek, adopt };
}
