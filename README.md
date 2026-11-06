# ProofLayer — local repository connection

ProofLayer is a local React + TypeScript dashboard and Node.js + TypeScript API for investigating SQL injection findings, checking npm dependencies, reviewing patches, and recording session activity for one connected Git repository.

## Requirements

- Node.js 20 or newer
- npm
- Git installed and available on the machine's PATH

## Start the app

From this folder, install dependencies and start both services:

```sh
npm install
npm run dev
```

Open the Vite URL printed in the terminal (normally `http://127.0.0.1:5173`). The frontend uses Vite; the API listens on `http://127.0.0.1:4317`.

To run the services separately, open two terminals in this folder and run `npm run server:dev` in one and `npm run client:dev` in the other. For a production frontend build, run `npm run build`.

## Validate the feature manually

1. Start the app and open **Repositories**.
2. Enter an absolute path to a local Git repository, such as `C:\\Users\\you\\projects\\my-app` on Windows or `/Users/you/projects/my-app` on macOS.
3. Connect and confirm the dashboard shows its name, path, branch, latest commit (when the repository has commits), and **Connected** status. The Overview page shows the same connected repository.
4. Try a nonexistent path and a normal folder without Git metadata. Each should show an error and leave the repository unconnected.
5. Submit an empty path and confirm the API rejects it.
6. Disconnect the valid repository. Confirm the UI asks first and returns to the empty state after confirmation; the source folder remains untouched.

The API also rejects file paths, relative paths, unreadable folders, unavailable Git, and attempts to connect a second repository while one is already connected. Connection state and scan results are held in API process memory, so restarting the backend clears them.

## Dependency scanning

Open **Dependencies** and choose **Scan dependencies**. ProofLayer reads `package-lock.json` or `npm-shrinkwrap.json` and checks exact npm package versions against the public OSV database. It shows direct and transitive packages, known advisories, severity when supplied, and available fixed versions. The scanner reports inconclusive results when OSV cannot be reached or a package query fails. A missing npm lockfile is reported clearly; other ecosystems are not parsed. The package name and version queries are sent to OSV. Source files and repository contents are not sent. A clean result means OSV returned no matching advisory for the scanned versions; it is not a general security guarantee.

Dependency parsing and API-response behavior are covered by `npm run test:dependencies`.

## Activity log

Open **Activity log** to review repository connections, scans, Git investigations, patch suggestions and decisions, verification, and dependency scans. The log is kept in the API process memory, shows up to 500 newest events, and clears when the server restarts. It records event summaries and repository names, not source code.

Activity event ordering and the 500-event bound are covered by `npm run test:activity-log`.

## SQL injection scanner

With a repository connected, open **Security scans** and run **SQL injection pattern scan**. `POST /api/scans/sql-injection` scans only `.ts` and `.tsx` paths returned by Git's tracked and non-ignored file listing. It excludes `node_modules`, `.git`, and common output/cache folders (`build`, `dist`, `out`, `coverage`, `.next`, `.nuxt`, `.output`, `.turbo`, `.cache`, and `target`). Files over 2 MB and files that cannot be read or analyzed are listed as skipped. The scanner reads source files and does not modify them.

The TypeScript AST scanner reports SQL-like text dynamically combined through template interpolation or string concatenation when it reaches a recognized SQL sink (`query`, `execute`, `exec`, `raw`, `prepare`, and common raw-query variants). It also follows simple variable initializers in the same file. This is an MVP heuristic: it can flag safe SQL template tags or methods with unrelated names, and can miss indirect helper calls, reassignment-based data flow, unsupported sink names, or SQL construction that does not include a recognized SQL keyword. A clean scan is not proof that code is safe.

### Security findings in the dashboard

When a scan finishes, its actual result becomes the latest dashboard scan. The Overview and **Investigations** section show the finding total; **Security scans** also shows the total and links to the same findings. Each finding card can be expanded to inspect its rule ID, rule title, severity, relative file path and name, exact construction line, query sink line when it differs, and numbered source context (up to three lines before and after the detected construction). The highlighted line is the scanner's reported construction line. Current rules assign **High** severity to both supported SQL construction patterns; this is rule metadata attached to those detections.

The Investigations page uses an explicit empty state before the first scan and when a completed scan returns no findings. API or scanner failures are displayed as errors and do not create findings. Skipped files from a completed scan remain visible with their skip reasons. Findings are held in the frontend's latest-scan state and are refreshed when another scan completes; they are not persisted across page reloads or backend restarts.

### Git history investigation

Expand a finding and choose **Investigate Git history**. `POST /api/scans/git-history` accepts only the ID of a finding from the latest successful scan held by the backend. The investigator checks that the finding still matches the working file, walks up to 250 reachable commits for that file, loads each available source version, runs the same SQL pattern detector on before and after versions, and examines parent-to-commit Git diffs. It associates a commit only when the matching detector signature appears in changed lines and is absent from the corresponding parent lines.

When evidence is available, the finding details show a **Git Evidence** section with the full commit hash, message, author metadata, commit date, affected file, source snippets from the parent and introducing commit, and the relevant actual Git diff. The diff includes old/new line numbers, added and removed line colors, and emphasis on lines overlapping the finding. The explanation summarizes why the changed SQL construction matches the finding. Author information is descriptive metadata; it is not an attribution of intent or fault. If the parent source or printable diff is unavailable, the dashboard explains that limitation instead of inventing code. Uncertain history remains labeled **Introducing commit could not be determined**.

The result says **Introducing commit could not be determined** when the finding is ambiguous, uncommitted, already present in the earliest available file version, affected by history that cannot be mapped completely (such as an unsupported rename), or beyond the 250-commit / 64 MB comparison limits. This is evidence from the reachable local Git history only; it cannot establish where code came from before it entered that history. Investigation results are held in the current dashboard session and are cleared when a new scan or repository connection replaces the findings.

### Root cause analysis

Each expanded finding includes a **Root Cause Analysis** built from the scanner's actual finding and, after investigation, the actual Git history result. It separates observed evidence (the construction pattern and query sink) from the risk assessment (dynamic values can alter SQL syntax if they are untrusted). The scanner does not trace value origins or prove exploitability. When history is undetermined or unavailable, the analysis says so and does not attribute the change to a commit.

### Suggested SQL injection patches

Choose **Suggest patch** in a finding's details to request a read-only diff. `POST /api/scans/patch-suggestion` accepts only a finding ID from the latest scan. The generator re-reads the affected file, confirms that the finding still matches, and verifies a direct `pg` import plus a `const` receiver instantiated from `Pool` or `Client`. It only transforms direct `.query(...)` arguments whose dynamic expressions occur in recognized SQL value positions, moving those expressions into PostgreSQL `$n` parameters. The output is an in-memory unified diff; ProofLayer never writes to the connected repository. If the driver, query flow, SQL context, or current source cannot be confirmed, the dashboard explains why no patch was suggested. The diff remains a review suggestion and still needs validation against the application's database behavior.

### Patch review and application

A suggested diff includes **Apply Patch** and **Reject Patch** actions. Apply opens a separate confirmation dialog; the API also requires an explicit `confirmed: true` request. Before writing, ProofLayer verifies the repository path, file type, exact source snapshot hash and content, replacement span, and that the reviewed diff reconstructs the proposed source. It rechecks the original file immediately before an atomic replacement. A changed file is left untouched, the review is marked stale, and a fresh scan and suggestion are required. Reject records the decision without writing any source. Only the affected file is replaced; no Git commit or push is performed. Review records live in the server process memory.

Run `npm test` to exercise patch review, fix verification, dependency scanning, and activity logging with temporary fixtures.

## How validation works

The browser sends the path to `POST /api/repository/connect`. The server checks that it is non-empty and absolute, calls `stat` to verify that it exists and is a directory, checks `git --version`, then uses `execFile` with fixed Git argument arrays to read the repository root, current branch, and latest commit. The entered path is passed as a Git argument; it is never interpreted as shell input. `GET /api/repository` returns the current connection and `DELETE /api/repository` clears only the application state.

# Rescan and fix verification

After a reviewed patch is applied, the finding details offer **Rescan Repository**. ProofLayer runs the SQL injection scanner against the connected repository and compares the fresh results with the original finding snapshot. It reports **Resolved** only when the original file was successfully scanned and its matching unsafe SQL construction is absent, **Still Detected** when the same pattern remains, and **Verification Inconclusive** when the original file could not be scanned or only a similar, changed pattern remains. The original finding remains visible with its patch and investigation history, and the developer can rescan again after making further changes. Verification never changes source files.
