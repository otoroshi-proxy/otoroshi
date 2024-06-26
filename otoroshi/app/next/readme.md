# next-gen proxy engine

## Tasks

- [x] remove apikey stuff from request before the forward
- [x] tricky plugins
- [x] handle ws
- [x] Loader Job to keep all route in memory
- [x] Loader Job to keep all apikeys in memory
- [x] Loader Job to keep all certificates in memory
- [x] Loader Job to keep all auth. modules in memory
- [x] Loader Job to keep all jwt verifiers in memory
- [x] Some kind of reporting mecanism to keep track of everything (useful for debug)

## new entities

- [x] Route
- [x] Backend
- [x] Target

## needed plugins

- [x] apikey extractor asap (pre route)
- [x] apikey plugin
  - [x] extraction (from allowed locations)
  - [x] validate enabled
  - [x] validate expiration date
  - [x] validate readonly
  - [x] validate route restriction
  - [x] validate apikeys constraints (should be autonomous actually)
  - [x] validate quotas
- [x] jwt verifier (access validator)
- [x] auth. module validation (access validator)
- [x] route restrictions (access validator)
- [x] public/private path plugin (access validator)
- [x] otoroshi state plugin (transformer)
- [x] otoroshi claim plugin (transformer)
- [x] CORS (transformer)
- [x] tricky plugins
  - [x] gzip (transformer)
  - [x] tcp/udp tunneling (?? - if possible, implies support for WS)
  - [x] snow monkey (transformer)
  - [x] canary (??)
- [x] headers related plugins
  - [x] add headers in (transformer)
  - [x] add headers out (transformer)
  - [x] add missing headers in (transformer)
  - [x] add missing headers out (transformer)
  - [x] remove headers in (transformer)
  - [x] remove headers out (transformer)
  - [x] send otoroshi headers back (transformer)
  - [x] send xforwarded headers (transformer)
  - [x] headers validation (access validator)
- [x] endless response clients (transformer)
- [x] maintenance mode (transformer)
- [x] construction mode (transformer)
- [x] override host header (transformer)
- [x] ip blocklist (access validator)
- [x] ip allowed list (access validator)
- [x] force https traffic (pre route)
- [x] allow http/1.0 traffic (pre route or access validator)
- [x] redirection plugin
- [x] readonly route (access validator)

## killed features

- [x] sidecar (handled with kube stuff now)
- [x] local redirection
- [x] detect apikeys sooner
