import { copyFile, mkdir } from "node:fs/promises";

const licenses = new URL("../demo-dist/licenses/", import.meta.url);
await mkdir(licenses, { recursive: true });
await copyFile(new URL("../../LICENSE", import.meta.url), new URL("AGPL-3.0.txt", licenses));
for (const font of ["archivo", "jetbrains-mono"]) {
  await copyFile(
    new URL(`../node_modules/@fontsource-variable/${font}/LICENSE`, import.meta.url),
    new URL(`${font}.txt`, licenses),
  );
}
