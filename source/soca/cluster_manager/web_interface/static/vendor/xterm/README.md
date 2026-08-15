# xterm.js (vendored)

Prebuilt xterm.js assets bundled into the SOCA web UI so the /ssh Web Terminal
tab works in clusters without egress to public registries.

## Provenance

| File | Version | Tarball | SRI Hash |
|------|---------|---------|----------|
| xterm.min.js / xterm.min.css | 6.0.0 | [https://registry.npmjs.org/@xterm/xterm/-/xterm-6.0.0.tgz](https://registry.npmjs.org/@xterm/xterm/-/xterm-6.0.0.tgz) | `sha512-TQwDdQGtwwDt+2cgKDLn0IRaSxYu1tSUjgKarSDkUM0ZNiSRXFpjxEsvc/Zgc5kq5omJ+V0a8/kIM2WD3sMOYg==` |
| xterm-addon-fit.min.js | 0.11.0 | [https://registry.npmjs.org/@xterm/addon-fit/-/addon-fit-0.11.0.tgz](https://registry.npmjs.org/@xterm/addon-fit/-/addon-fit-0.11.0.tgz) | `sha512-jYcgT6xtVYhnhgxh3QgYDnnNMYTcf8ElbxxFzX0IZo+vabQqSPAjC3c1wJrKB5E19VwQei89QCiZZP86DCPF7g==` |

## Verification

Extracted file SHA-256 hashes are committed alongside in [`SHA256SUMS`](./SHA256SUMS).
To verify the vendored files match what `fetch_xterm_assets.sh` would produce:

    cd source/soca/cluster_manager/web_interface/static/vendor/xterm
    sha256sum -c SHA256SUMS

## Updating

1. Edit `source/soca/cluster_manager/login_node_webshell/fetch_xterm_assets.sh`,
   bumping `XTERM_VERSION` / `FIT_VERSION`.
2. Update the corresponding `*_SHA512` constant -- fetch the new hash from
   the npm registry:
       curl -s 'https://registry.npmjs.org/@xterm/xterm/<VERSION>' \
           | python3 -c "import json,sys;print(json.load(sys.stdin)['dist']['integrity'])"
3. Re-run the script. It will refuse to overwrite the vendored files if the
   downloaded tarball does not match the pinned hash.
4. Commit both the script change and the new vendor/ contents in the same
   commit so reviewers can verify them together.

## Why npm registry, not jsdelivr/unpkg

xterm.js GitHub releases are source-only (.tar.gz / .zip of the repo). The
prebuilt minified files come from the npm publish pipeline. The registry
publishes a SHA-512 integrity hash with each release, signed by the publisher
-- so verifying the tarball hash is equivalent to verifying the publisher's
release signature. Public CDNs are transparent mirrors of the same npm
contents but cannot offer the same publisher-signed integrity guarantee.

## License

xterm.js is MIT-licensed. See https://github.com/xtermjs/xterm.js/blob/master/LICENSE.
