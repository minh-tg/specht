# Dependency-Check fixtures

`no-purl-same-cve.json` is a Dependency-Check 12.1.0 report reduced to two
dependencies matched by file evidence only (`nginx-1.0.exe` and
`openssl.dll`), so neither carries a package purl, with the same CVE. The two
entries were written from one real dependency entry; only the file names and
paths differ.
