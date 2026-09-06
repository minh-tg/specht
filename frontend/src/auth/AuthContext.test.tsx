import { setAuthToken } from "@/api/client";
import { render, screen } from "@testing-library/react";
import { AuthProvider } from "./AuthContext";
import { SSO_SESSION_KEY, ssoTokenFromHash } from "./sso";
import { useAuth } from "./useAuth";

function Probe() {
  const auth = useAuth();
  return (
    <div>
      <span data-testid="token">{auth.token ?? "none"}</span>
      <span data-testid="user-id">{auth.userId ?? "none"}</span>
      <span data-testid="email">{auth.email ?? "none"}</span>
    </div>
  );
}

function renderWithHash(hash: string) {
  window.history.replaceState(null, "", hash);
  return render(
    <AuthProvider>
      <Probe />
    </AuthProvider>,
  );
}

/** Builds an unsigned JWT-shaped token (client only decodes the payload). */
function jwt(payload: Record<string, unknown>): string {
  const enc = (o: unknown): string =>
    btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${enc({ alg: "HS256", typ: "JWT" })}.${enc(payload)}.signature`;
}

beforeEach(() => {
  setAuthToken(null);
});

afterEach(() => {
  setAuthToken(null);
  window.history.replaceState(null, "", "/");
});

describe("ssoTokenFromHash", () => {
  it("returns null for a hash without the sso_token parameter", () => {
    expect(ssoTokenFromHash("")).toBeNull();
    expect(ssoTokenFromHash("#other=value")).toBeNull();
    expect(ssoTokenFromHash("not-a-fragment")).toBeNull();
  });

  it("returns null for a malformed or non-JWT token", () => {
    expect(ssoTokenFromHash(`#${SSO_SESSION_KEY}=`)).toBeNull();
    expect(ssoTokenFromHash(`#${SSO_SESSION_KEY}=not-a-jwt`)).toBeNull();
    expect(ssoTokenFromHash(`#${SSO_SESSION_KEY}=a.b`)).toBeNull();
  });

  it("returns null when the token has no subject claim", () => {
    expect(ssoTokenFromHash(`#${SSO_SESSION_KEY}=${jwt({ email: "a@b.c" })}`)).toBeNull();
  });

  it("decodes subject and email claims from a base64url payload", () => {
    const token = jwt({ sub: "oidc-user-1", email: "oidc@example.com" });
    const sso = ssoTokenFromHash(`#${SSO_SESSION_KEY}=${token}`);

    expect(sso?.token).toBe(token);
    expect(sso?.claims.sub).toBe("oidc-user-1");
    expect(sso?.claims.email).toBe("oidc@example.com");
  });

  it("keeps an unrelated fragment parameter alongside sso_token", () => {
    const token = jwt({ sub: "oidc-user-1" });
    const sso = ssoTokenFromHash(`#some=anchor&${SSO_SESSION_KEY}=${token}`);

    expect(sso?.token).toBe(token);
    expect(sso?.claims.sub).toBe("oidc-user-1");
  });
});

describe("AuthProvider SSO fragment delivery", () => {
  it("adopts the sso_token fragment into the session and strips it from the URL", () => {
    const token = jwt({ sub: "oidc-user-1", email: "oidc@example.com" });
    renderWithHash(`/#sso_token=${token}`);

    expect(screen.getByTestId("token")).toHaveTextContent(token);
    expect(screen.getByTestId("user-id")).toHaveTextContent("oidc-user-1");
    expect(screen.getByTestId("email")).toHaveTextContent("oidc@example.com");
    expect(window.location.hash).toBe("");
    expect(window.location.pathname).toBe("/");
  });

  it("ignores a fragment without sso_token", () => {
    renderWithHash("/#some-other-fragment");

    expect(screen.getByTestId("token")).toHaveTextContent("none");
    expect(screen.getByTestId("user-id")).toHaveTextContent("none");
    expect(screen.getByTestId("email")).toHaveTextContent("none");
  });

  it("ignores and clears a malformed sso_token", () => {
    renderWithHash("/#sso_token=not-a-jwt");

    expect(screen.getByTestId("token")).toHaveTextContent("none");
    expect(screen.getByTestId("user-id")).toHaveTextContent("none");
    expect(screen.getByTestId("email")).toHaveTextContent("none");
    expect(window.location.hash).toBe("");
  });

  it("leaves the email absent when the token has no email claim", () => {
    const token = jwt({ sub: "oidc-user-1" });
    renderWithHash(`/#sso_token=${token}`);

    expect(screen.getByTestId("token")).toHaveTextContent(token);
    expect(screen.getByTestId("user-id")).toHaveTextContent("oidc-user-1");
    expect(screen.getByTestId("email")).toHaveTextContent("none");
  });
});
