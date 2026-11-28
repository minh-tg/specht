import type { ChangeScope } from "@/lib/entryMode";
import { createContext, useContext } from "react";

/**
 * The gate the change view judged its blockers with. Only the blocker section provides it: a
 * finding opened from existing debt is judged by the project gate, since that is the gate it blocks.
 */
export const ChangeScopeContext = createContext<ChangeScope | undefined>(undefined);

export function useChangeScope(): ChangeScope | undefined {
  return useContext(ChangeScopeContext);
}
