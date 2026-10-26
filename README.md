# LogiQual QMS

LogiQual is a prototype Software Quality Management System for the development and maintenance of a logistics and delivery management product. It supports the quality lifecycle **Plan → Define → Execute → Verify → Measure → Report → Improve**, including quality plans, reviews, tests, defects, controlled artifacts, metrics, CAPA, and release-readiness checks.

This follows the supplied project brief: the prototype manages the quality of the logistics software; it is not a production order-dispatch, driver-tracking, or customer-notification application.

## Technology

- HTML, CSS, and browser JavaScript for the existing responsive dashboard.
- Java 17+ built-in HTTP server for authentication and API endpoints.
- SQLite for users, login history, audit events, and QMS records.
- Maven for building and running tests.

## Run locally (Windows PowerShell)

1. Install a JDK 17 or later and Apache Maven 3.9 or later. Confirm both are on `PATH`:

   ```powershell
   java -version
   mvn -version
   ```

2. Open PowerShell in the folder containing `pom.xml` and `LogiQual_Updated_Dashboard.html`.

3. Run the automated tests:

   ```powershell
   mvn test
   ```

4. Build the runnable application:

   ```powershell
   mvn package
   ```

5. Start the app from the project folder:

   ```powershell
   java -jar target\logiqual-qms-1.0.0.jar
   ```

6. Open <http://localhost:8080> and sign in with one of these first-run accounts:

   | Username | Initial password |
   | --- | --- |
   | Mohan | `m@123` |
   | Nruthya | `@n@123` |
   | Sinchana | `s@123` |

   The default accounts are inserted only when their usernames are absent; application restarts do not reset their passwords or delete application data. These short initial credentials are retained as required by the project. Change them after first sign-in where practical.

7. Use **User Management → Add User** to register accounts. New-account passwords must be at least 8 characters. Any authenticated user can create accounts in this academic prototype; that is an explicit project requirement, not a recommended production enterprise policy.

## Deploy the prototype on a private Windows host

1. On the build machine, run `mvn test` and `mvn package`.
2. Create a deployment folder, for example `D:\LogiQual`. Copy `target\logiqual-qms-1.0.0.jar` and `LogiQual_Updated_Dashboard.html` into it. Create `D:\LogiQual\data` and grant write access only to the account that runs the app. Keep a backup of any existing SQLite database before upgrading.
3. Configure the host to accept traffic only through an HTTPS reverse proxy on a trusted network. Do not expose the Java HTTP port directly to the public internet.
4. Start the app from the deployment folder, with a persistent database path:

   ```powershell
   Set-Location D:\LogiQual
   $env:PORT = '8080'
   $env:LOGIQUAL_DB_PATH = 'D:\LogiQual\data\logiqual.sqlite'
   $env:LOGIQUAL_COOKIE_SECURE = 'true'
   java -jar D:\LogiQual\logiqual-qms-1.0.0.jar
   ```

5. Configure the HTTPS proxy to forward requests to `http://127.0.0.1:8080`, then check `https://your-internal-host/health` and open the dashboard through that HTTPS hostname.
6. For automatic startup, create a Windows Task Scheduler task running under the restricted service account: trigger **At startup**, program `java.exe`, arguments `-jar D:\LogiQual\logiqual-qms-1.0.0.jar`, and **Start in** `D:\LogiQual`. Set the three environment variables above for that service account before enabling the task.
7. Sign in, change each default password using **Change password**, and verify that `D:\LogiQual\data\logiqual.sqlite` is included in the host's protected backup routine.

## Database and configuration

- The database is created at `data\logiqual.sqlite` on first run. Keep this file to preserve accounts, audit events, login history, and QMS records across restarts.
- Override the location with a PowerShell environment variable:

  ```powershell
  $env:LOGIQUAL_DB_PATH = 'D:\LogiQual\data\logiqual.sqlite'
  java -jar target\logiqual-qms-1.0.0.jar
  ```

- Override the port with `$env:PORT = '8080'`.
- To put the prototype behind an HTTPS-terminating reverse proxy, set `$env:LOGIQUAL_COOKIE_SECURE = 'true'` before startup. Do not expose the prototype directly to the public internet; use HTTPS, access controls, backups, monitoring, and a production-grade authorization policy.
- The server uses SQLite transactions, foreign keys, a case-insensitive username constraint, and a busy timeout. Back up the database file while the app is stopped or use SQLite's online backup facilities.
- Existing dashboard data saved in the browser's `logiqualDB` key is imported into an empty SQLite QMS store on the first authenticated visit. Passwords are never written to browser storage. Subsequent QMS edits are stored server-side in SQLite; the browser copy is only refreshed after a successful save.
- The initial system-created accounts use `created_by_user_id = NULL` to represent creation by the database bootstrap process. Normal user creation stores the authenticated creator's user ID.
- Database initialization uses `CREATE TABLE IF NOT EXISTS` and inserts default accounts only when missing. It never drops or recreates the SQLite database.

## API

All endpoints except `POST /api/login`, `GET /health`, and static dashboard delivery require the server-side session cookie. The cookie is HttpOnly and SameSite=Strict. The browser does not submit a creator ID; the backend takes the actor identity from the authenticated session.

| Method and path | Purpose |
| --- | --- |
| `POST /api/login` | Authenticate with `{ "username": "...", "password": "..." }`. |
| `GET /api/session` | Return the current safe session identity. |
| `POST /api/logout` | End the current session. |
| `GET /api/users?search=&status=` | Search accounts by username/creator and optionally filter by `ACTIVE` or `DISABLED`. |
| `GET /api/users/{id}` | Read safe account information. |
| `POST /api/users` | Create a user with `{ "username": "...", "password": "...", "confirmPassword": "..." }`. |
| `GET /api/records` | Read the QMS record collections. |
| `POST /api/records` | Transactionally save QMS record collections. Add `"replace": true` to atomically replace all persisted QMS collections (used when replacing sample data from a workbook). |
| `GET /api/sqa-metrics` | Read saved SQA formula inputs; requires authentication. |
| `PUT /api/sqa-metrics` | Validate and persist the ten non-negative, numeric Unit 5 measurement inputs; requires authentication. |

User creation returns `201`; invalid input returns `400`; duplicate case-insensitive usernames return `409`; unauthenticated requests return `401`; missing users return `404`. User-list, user-detail, and creation responses omit password hashes. Passwords are hashed with a per-account random salt and PBKDF2-HMAC-SHA-256 (210,000 iterations). Successful account creation and its `USER_CREATED` audit record commit in one SQLite transaction. Failed registration attempts are also recorded with their outcome, without storing a password or hash.

The `audit_events` table records actor, target, username, action, UTC timestamp, and outcome. `login_history` records successful and failed login outcomes. Neither table contains credential material.

## Unit 5 SQA formulas

The dashboard's SQA Metrics section implements the formulas shown in the supplied Unit 5 slides 13–17:

- **NCE** = low code errors + medium code errors + high code errors.
- **WCE** = (low × 1) + (medium × 3) + (high × 9). The deck's severity weights are low 1, medium 3, high 9; Critical defects are grouped with High for this prototype.
- **CED** = NCE / KLOC.
- **DED** = NDE / KLOC.
- **WCED** = WCE / KLOC.
- **WCEF** = WCE / NFP (number of function points).
- **DevP** = DevH / KLOC (development person-hours per KLOC).
- **CRe** = reused KLOC / total KLOC.
- **DocRe** = reused documents / total documents.

Enter project sizing, error-severity counts, effort, and reuse figures in the SQA measurement panel. Values are stored in SQLite in `sqa_measurements`, are separate from illustrative defect-dashboard records, and persist after restart. When a ratio denominator is zero or missing, the result identifies the missing measurement rather than presenting a fabricated value. The same metric names, formulas, and calculated results are included in the Excel report. Unit 5 slide 17 flags error-removal effectiveness as self-study, and slide 18 does not give operational product-metric formulas; the dashboard therefore does not invent formulas for those activities.

The Metrics & Reports page also separates **before-deployment** evidence (review completion, integration-test pass/fail counts, and pre-release defects) from **after-deployment** monitoring (escaped defects, open production defects, high/critical production defects, and defect escape rate). Its defect-stage table uses each defect's recorded "first detected after release" value; these are live QMS records, not assumed estimates. Unit 5 formula cards use larger type, and when a denominator is missing the result tells you which measurement to enter (for example, `Enter Software size (KLOC)`) rather than showing `N/A`. Rates with no source records are labelled `No records`.

## Testing

`mvn test` exercises the three default creators, newly created account login, duplicate/case-only usernames, password validation, unauthenticated access, password-hash and response safety, audit attribution, persistence after restart, simultaneous attempts to register the same username, and authenticated SQA measurement validation and persistence.
