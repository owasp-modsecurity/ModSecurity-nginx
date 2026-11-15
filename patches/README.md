# NGINX host correction for HTTP/2 reset delivery

`nginx-http2-close-stream-flush.patch` schedules the physical HTTP/2 write
event when a stream closes with queued output while another stream remains
active. This lets a queued reset reach the client without waiting for another
socket read or the sibling stream to finish. The sibling connection remains
usable.

The patch is copied from
[ModSecurity-test-Framework at 95f228936efe17fda24f21323ad87cd698940b48](https://github.com/Easton97-Jens/ModSecurity-test-Framework/blob/95f228936efe17fda24f21323ad87cd698940b48/ci/provisioning/patches/nginx/h2-close-stream-flush.patch).
It changes NGINX core code, not libModSecurity or the connector's rule policy.

Before configuring and building NGINX, run from the connector checkout:

```sh
sh .github/scripts/apply-nginx-http2-patch.sh /path/to/nginx/source
```

Then configure NGINX with `--with-http_v2_module` and this connector as usual.
For a dynamic connector, rebuild and deploy the patched NGINX host as well.
Replacing only the module leaves an existing host's HTTP/2 core unchanged.

The helper requires GNU `patch`, rejects mismatched source
without fuzzy matching, and accepts an already-applied copy. Review this
dependency correction when changing NGINX versions or when an equivalent fix
lands upstream. NGINX binaries supplied by a distribution need the equivalent
host correction from their distributor or a locally rebuilt NGINX binary.

CI applies the patch to its NGINX sources before native Linux/Windows builds.
A focused native regression checks that a Strict phase-4 reset arrives while
a separate allowed stream is still open, then verifies that the allowed
stream and another request complete on the same HTTP/2 connection. One Linux
job also runs the controlled unpatched baseline before applying the fix.
