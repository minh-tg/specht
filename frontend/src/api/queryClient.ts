import { playCue } from "@/lib/sound";
import { MutationCache, QueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { APIError } from "./client";
import { shouldRetryQuery } from "./retry";
import { undoOptions, type UndoPlan } from "./undo";

declare module "@tanstack/react-query" {
  interface Register {
    mutationMeta: {
      /**
       * Toast shown when the mutation succeeds. A function builds the message
       * from the response, for outcomes that report what the server decided.
       */
      success?: string | ((data: never, variables: never) => string);
      /**
       * Set `"none"` for a removal or revocation: the toast stays but the rising cue is skipped. A
       * function decides from the response and the variables, and returns `undefined` to keep the
       * default cue.
       */
      sound?: "none" | ((data: never, variables: never) => "none" | undefined);
      /**
       * The inverse of this mutation, offered as an Undo button on the success toast. Returns
       * nothing when this outcome has no safe inverse, and the toast then has no button. The plan
       * runs outside the mutation, so it does not toast or play a cue a second time.
       */
      undo?: (data: never, variables: never) => UndoPlan | undefined;
    };
  }
}

/** Shows the success toast a mutation declared in its meta, if it declared one. */
export function announceMutationSuccess(
  success: string | ((data: never, variables: never) => string) | undefined,
  data: unknown,
  variables: unknown,
  sound?: "none" | ((data: never, variables: never) => "none" | undefined),
  undo?: (data: never, variables: never) => UndoPlan | undefined,
): void {
  if (!success) return;
  const message = typeof success === "function"
    ? (success as (data: unknown, variables: unknown) => string)(data, variables)
    : success;
  const plan =
    (undo as ((data: unknown, variables: unknown) => UndoPlan | undefined) | undefined)?.(
      data,
      variables,
    );
  if (plan) toast.success(message, undoOptions(plan));
  else toast.success(message);
  const choice = typeof sound === "function"
    ? (sound as (data: unknown, variables: unknown) => "none" | undefined)(data, variables)
    : sound;
  if (choice !== "none") playCue("accepted");
}

/**
 * The app's query client. Mutations announce their own success through
 * `meta.success`, so call sites do not each keep a "saved" message in state.
 */
export function createQueryClient(
  retry: typeof shouldRetryQuery | false = shouldRetryQuery,
): QueryClient {
  return new QueryClient({
    mutationCache: new MutationCache({
      onSuccess: (data, variables, _result, mutation) => {
        announceMutationSuccess(
          mutation.meta?.success,
          data,
          variables,
          mutation.meta?.sound,
          mutation.meta?.undo,
        );
      },
      // Only mutations that announce their success are user actions worth a failure cue; a 401
      // is the session ending, which redirects instead.
      onError: (error, _variables, _result, mutation) => {
        if (!mutation.meta?.success) return;
        if (error instanceof APIError && error.status === 401) return;
        playCue("error");
      },
    }),
    defaultOptions: { queries: { retry } },
  });
}
