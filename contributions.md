# Contributing to ShieldCI

Thanks for wanting to contribute! This file explains how to file issues, propose changes, and get your code merged.

## Quick checklist

- [ ] Open an issue first for non-trivial changes or new features
- [ ] Fork the repo and create a short-lived feature branch
- [ ] Follow the branch and commit naming conventions below
- [ ] Add or update tests for new functionality
- [ ] Run the linters/formatters and ensure `cargo check` passes
- [ ] Open a pull request (PR) describing the change and linking any related issues

## Filing issues

- Use issues for bugs, feature requests, and questions.
- Provide a short title and a reproducible test case or steps to reproduce.
- Include logs, platform (OS), and versions if relevant.

## Branch & commit conventions

- Branches: use `feature/<short-desc>`, `fix/<short-desc>`, or `chore/<short-desc>`.
- Example: `feature/docker-allinone`, `fix/readme-link`
- Commits: use imperative, present-tense messages:
  - `Add Dockerfile.allinone and docker-compose`
  - `Fix: rewrite README architecture image link`
- Squash or tidy commits before merging if the PR history is noisy.

## Coding style & tools

Rust
- Use `rustfmt` to format Rust code: `rustup component add rustfmt && cargo fmt`
- Run the compiler checks: `cargo check` and tests: `cargo test`

Node (test app)
- Use the Node version specified in `tests/package.json` (if any)
- Install deps: `cd tests && npm install`
- Run the test app: `node app.js`

Python
- Virtualenv recommended for running `push_results.py` or `kali_mcp.py`.

General
- Keep changes focused and small. One PR per logical change.
- Add comments for non-obvious logic and update `README.md` or docs when behavior changes.

## Running and testing locally (recommended flow)

1. Start Ollama (local LLM) and Docker Desktop.
2. Build the Rust binary:

```bash
cargo build --release
```

3. Build the Kali image (if testing tools):

```bash
docker build -t shieldci-kali-image .
```

4. Run the vulnerable test app:

```bash
cd tests
npm install
node app.js
```

5. Run the engine from repo root (it reads `tests/shieldci.yml`):

```bash
./target/release/shield-ci
# or during dev
cargo run --release --manifest-path Cargo.toml
```

6. (Optional) Push results to the dashboard:

```bash
export SHIELDCI_API_URL=http://localhost:3000
export SHIELDCI_API_KEY=your-secret-key
export SHIELDCI_REPO=owner/repo
python3 push_results.py
```

## Tests

- There is a deliberately vulnerable test app in `tests/` used for local smoke runs.
- Add unit or integration tests for any new Rust logic where feasible.
- Before submitting a PR, ensure `cargo check` passes and the test app still runs.

## Pull request checklist

- [ ] PR links to an issue (if applicable)
- [ ] Code is formatted and linted
- [ ] Tests added or updated
- [ ] Documentation/README updated where applicable
- [ ] No obvious secrets committed

## Security disclosures

If you find a security vulnerability in ShieldCI itself (not the test app):
- Do not open a public issue. Instead contact the maintainers privately by email: security@shieldci.local (replace with the appropriate address for your organization) or open an encrypted issue if the upstream project provides one.
- Provide clear reproduction steps and a suggested mitigation if possible.

## Code of Conduct

By participating, you agree to follow the project's Code of Conduct. Be respectful and constructive in reviews and discussions.

## License

Contributions are accepted under the project's existing license (Apache 2.0). By submitting a PR you agree to license your contribution under the same terms.

---

Thanks — we appreciate your help making ShieldCI better.
