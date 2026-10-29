// openapi-typescript builds api.gen.ts with ts.factory, which TypeScript 7 no
// longer exports from the package root, and its typescript peer would resolve
// to the project's TypeScript 7. Give the generator its own TypeScript 6 until
// it supports 7; tsc, the tests and the build keep using the project's version.
// Remove this file once openapi-typescript accepts TypeScript 7.
module.exports = {
  hooks: {
    readPackage(pkg) {
      if (pkg.name === "openapi-typescript") {
        delete pkg.peerDependencies?.typescript;
        pkg.dependencies = { ...pkg.dependencies, typescript: "~6.0.3" };
      }
      return pkg;
    },
  },
};
