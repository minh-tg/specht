export const repository = "https://github.com/minh-tg/specht";

export function local(path = ""): string {
  const base = import.meta.env.BASE_URL;
  return `${base.endsWith("/") ? base : `${base}/`}${path.replace(/^\/+/, "")}`;
}
