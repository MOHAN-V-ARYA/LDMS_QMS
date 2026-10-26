package com.logiqual;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class LogiQualServer {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int HASH_ITERATIONS = 210_000;
    private static final int MAX_BODY_BYTES = 1_048_576;
    private static final Map<String, String> DEFAULT_USERS = Map.of(
            "Mohan", "m@123", "Nruthya", "@n@123", "Sinchana", "s@123");
    private static final List<String> RECORD_TYPES =
            List.of("plans", "reviews", "tests", "defects", "documents", "capa");
    private static final List<String> SQA_INPUT_FIELDS = List.of(
            "nceLow", "nceMedium", "nceHigh", "nde", "kloc", "functionPoints",
            "developmentHours", "reusedKloc", "reusedDocuments", "totalDocuments");

    private final String jdbcUrl;
    private final Map<String, UserSession> sessions = new ConcurrentHashMap<>();
    private final ExecutorService executor;
    private final HttpServer server;

    public LogiQualServer(Path databasePath, int port) throws IOException, SQLException {
        Path absoluteDatabasePath = databasePath.toAbsolutePath();
        Path parent = absoluteDatabasePath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        jdbcUrl = "jdbc:sqlite:" + absoluteDatabasePath;
        initializeDatabase();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/", this::handle);
        executor = Executors.newFixedThreadPool(16);
        server.setExecutor(executor);
    }

    public void start() {
        server.start();
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public void stop() {
        server.stop(0);
        executor.shutdownNow();
    }

    private Connection connection() throws SQLException {
        Connection connection = DriverManager.getConnection(jdbcUrl);
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA foreign_keys = ON");
            statement.execute("PRAGMA busy_timeout = 5000");
        }
        return connection;
    }

    private void initializeDatabase() throws SQLException {
        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA journal_mode = WAL");
            connection.setAutoCommit(false);
            try {
                if (!tableExists(connection, "users")) {
                    statement.execute("""
                            CREATE TABLE users (
                                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                                password_hash TEXT NOT NULL,
                                account_status TEXT NOT NULL DEFAULT 'ACTIVE'
                                    CHECK (account_status IN ('ACTIVE', 'DISABLED')),
                                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                                created_by_user_id INTEGER REFERENCES users(user_id),
                                updated_at TEXT
                            )
                            """);
                } else {
                    migrateUsers(connection, statement);
                }
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS audit_events (
                        audit_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        actor_user_id INTEGER REFERENCES users(user_id),
                        created_user_id INTEGER REFERENCES users(user_id),
                        created_username TEXT NOT NULL,
                        action_type TEXT NOT NULL,
                        occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                        outcome TEXT NOT NULL
                    )
                    """);
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS login_history (
                        login_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER REFERENCES users(user_id),
                        username TEXT NOT NULL,
                        occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                        outcome TEXT NOT NULL
                    )
                    """);
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version INTEGER PRIMARY KEY,
                        applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                    )
                    """);
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS qms_records (
                        record_type TEXT NOT NULL,
                        record_id INTEGER NOT NULL,
                        payload_json TEXT NOT NULL,
                        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                        PRIMARY KEY (record_type, record_id)
                    )
                    """);
                statement.execute("""
                        CREATE TABLE IF NOT EXISTS sqa_measurements (
                            measurement_id INTEGER PRIMARY KEY CHECK (measurement_id = 1),
                            payload_json TEXT NOT NULL,
                            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                        )
                        """);
                statement.execute("INSERT OR IGNORE INTO schema_migrations(version) VALUES (1)");
                connection.commit();
            } catch (SQLException | RuntimeException error) {
                connection.rollback();
                throw error;
            }
        }
        seedDefaultUsers();
    }

    private static boolean tableExists(Connection connection, String tableName) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?")) {
            statement.setString(1, tableName);
            try (ResultSet result = statement.executeQuery()) {
                return result.next();
            }
        }
    }

    private static void migrateUsers(Connection connection, Statement statement) throws SQLException {
        Set<String> columns = new HashSet<>();
        try (ResultSet result = statement.executeQuery("PRAGMA table_info(users)")) {
            while (result.next()) {
                columns.add(result.getString("name").toLowerCase());
            }
        }
        if (!columns.contains("username")) {
            throw new SQLException("Existing users table has no username column; database was left unchanged");
        }
        if (!columns.contains("user_id")) {
            statement.execute("ALTER TABLE users ADD COLUMN user_id INTEGER");
            String sourceId = columns.contains("id") ? "id" : "rowid";
            statement.execute("UPDATE users SET user_id = " + sourceId + " WHERE user_id IS NULL");
            columns.add("user_id");
        }
        if (!columns.contains("password_hash")) {
            if (!columns.contains("password")) {
                throw new SQLException("Existing users table has no password credential to migrate; database was left unchanged");
            }
            statement.execute("ALTER TABLE users ADD COLUMN password_hash TEXT");
            columns.add("password_hash");
        }
        if (columns.contains("password")) {
            try (PreparedStatement read = connection.prepareStatement(
                         "SELECT rowid AS migration_rowid, password_hash, password FROM users");
                 ResultSet result = read.executeQuery();
                 PreparedStatement update = connection.prepareStatement(
                         "UPDATE users SET password_hash = ? WHERE rowid = ?")) {
                while (result.next()) {
                    String existingHash = result.getString("password_hash");
                    String legacyPassword = result.getString("password");
                    if (existingHash == null || existingHash.isBlank()) {
                        if (legacyPassword == null) {
                            throw new SQLException("A legacy user has no usable credential; database was left unchanged");
                        }
                        update.setString(1, hashPassword(legacyPassword));
                        update.setLong(2, result.getLong("migration_rowid"));
                        update.executeUpdate();
                    }
                }
            }
            statement.execute("ALTER TABLE users DROP COLUMN password");
            columns.remove("password");
        }
        if (!columns.contains("account_status")) {
            statement.execute("ALTER TABLE users ADD COLUMN account_status TEXT NOT NULL DEFAULT 'ACTIVE'");
        }
        if (!columns.contains("created_at")) {
            statement.execute("ALTER TABLE users ADD COLUMN created_at TEXT");
        }
        if (!columns.contains("created_by_user_id")) {
            statement.execute("ALTER TABLE users ADD COLUMN created_by_user_id INTEGER REFERENCES users(user_id)");
        }
        if (!columns.contains("updated_at")) {
            statement.execute("ALTER TABLE users ADD COLUMN updated_at TEXT");
        }
        statement.execute("""
                UPDATE users SET created_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                WHERE created_at IS NULL OR created_at = ''
                """);
        statement.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_user_id ON users(user_id)");
        statement.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_username_nocase ON users(username COLLATE NOCASE)");
        statement.execute("""
                CREATE TRIGGER IF NOT EXISTS users_assign_user_id
                AFTER INSERT ON users
                WHEN NEW.user_id IS NULL
                BEGIN
                    UPDATE users
                    SET user_id = (SELECT COALESCE(MAX(user_id), 0) + 1 FROM users WHERE rowid != NEW.rowid)
                    WHERE rowid = NEW.rowid;
                END
                """);
    }

    private void seedDefaultUsers() throws SQLException {
        try (Connection connection = connection()) {
            connection.setAutoCommit(false);
            try (PreparedStatement find = connection.prepareStatement(
                         "SELECT user_id FROM users WHERE username = ? COLLATE NOCASE");
                 PreparedStatement insert = connection.prepareStatement(
                             """
                             INSERT INTO users(username, password_hash, created_by_user_id, created_at)
                             VALUES (?, ?, NULL, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                             """,
                             Statement.RETURN_GENERATED_KEYS);
                 PreparedStatement audit = connection.prepareStatement("""
                         INSERT INTO audit_events(actor_user_id, created_user_id, created_username,
                             action_type, outcome) VALUES (NULL, ?, ?, 'USER_CREATED', 'SUCCESS')
                         """)) {
                for (Map.Entry<String, String> account : DEFAULT_USERS.entrySet()) {
                    find.setString(1, account.getKey());
                    try (ResultSet result = find.executeQuery()) {
                        if (result.next()) {
                            continue;
                        }
                    }
                    insert.setString(1, account.getKey());
                    insert.setString(2, hashPassword(account.getValue()));
                    insert.executeUpdate();
                    audit.setLong(1, lastInsertedUserId(connection));
                    audit.setString(2, account.getKey());
                    audit.executeUpdate();
                }
                connection.commit();
            } catch (SQLException | RuntimeException error) {
                connection.rollback();
                throw error;
            }
        }
    }

    private void handle(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            if (path.equals("/") || path.equals("/LogiQual_Updated_Dashboard.html")) {
                serveDashboard(exchange);
                return;
            }
            if (path.equals("/health") && method.equals("GET")) {
                sendJson(exchange, 200, Map.of("status", "ok"));
                return;
            }
            if (path.equals("/api/login") && method.equals("POST")) {
                login(exchange);
                return;
            }
            if (path.equals("/api/session") && method.equals("GET")) {
                sendJson(exchange, 200, sessionUser(requireSession(exchange)));
                return;
            }
            if (path.equals("/api/logout") && method.equals("POST")) {
                logout(exchange);
                return;
            }

            UserSession session = requireSession(exchange);
            if (path.equals("/api/password") && method.equals("POST")) {
                changePassword(exchange, session);
            } else if (path.equals("/api/users") && method.equals("GET")) {
                listUsers(exchange);
            } else if (path.equals("/api/users") && method.equals("POST")) {
                createUser(exchange, session);
            } else if (path.startsWith("/api/users/") && method.equals("GET")) {
                getUser(exchange, path.substring("/api/users/".length()));
            } else if (path.equals("/api/records") && method.equals("GET")) {
                listRecords(exchange);
            } else if (path.equals("/api/records") && method.equals("POST")) {
                saveRecords(exchange);
            } else if (path.equals("/api/sqa-metrics") && method.equals("GET")) {
                getSqaMeasurements(exchange);
            } else if (path.equals("/api/sqa-metrics") && method.equals("PUT")) {
                saveSqaMeasurements(exchange);
            } else {
                sendError(exchange, 404, "Not found");
            }
        } catch (AuthenticationRequired error) {
            sendError(exchange, 401, "Authentication required");
        } catch (BadRequest error) {
            sendError(exchange, 400, error.getMessage());
        } catch (SQLException error) {
            sendError(exchange, 500, "The request could not be completed. Please try again.");
        } catch (Exception error) {
            System.err.println("Request failed: " + error.getClass().getSimpleName());
            sendError(exchange, 500, "The request could not be completed. Please try again.");
        } finally {
            exchange.close();
        }
    }

    private void serveDashboard(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }
        Path dashboard = Path.of("LogiQual_Updated_Dashboard.html");
        if (!Files.isRegularFile(dashboard)) {
            sendError(exchange, 404, "Dashboard file is missing");
            return;
        }
        byte[] content = Files.readAllBytes(dashboard);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-cache");
        exchange.sendResponseHeaders(200, content.length);
        exchange.getResponseBody().write(content);
    }

    private void login(HttpExchange exchange) throws IOException, SQLException {
        Map<String, Object> body = readObject(exchange);
        String username = stringValue(body.get("username")).trim();
        String password = stringValue(body.get("password"));
        UserRecord user = null;
        if (username.length() <= 80 && password.length() <= 256) {
            try (Connection connection = connection();
                 PreparedStatement query = connection.prepareStatement("""
                         SELECT user_id, username, password_hash, account_status, created_at, created_by_user_id
                         FROM users WHERE username = ? COLLATE NOCASE
                         """)) {
                query.setString(1, username);
                try (ResultSet result = query.executeQuery()) {
                    if (result.next()) {
                        user = readUser(result);
                        String encodedHash = result.getString("password_hash");
                        if (!user.accountStatus.equals("ACTIVE") || !verifyPassword(password, encodedHash)) {
                            user = null;
                        }
                    }
                }
            }
        }
        try (Connection connection = connection();
             PreparedStatement history = connection.prepareStatement(
                     "INSERT INTO login_history(user_id, username, outcome) VALUES (?, ?, ?)")) {
            if (user == null) {
                history.setNull(1, java.sql.Types.INTEGER);
                history.setString(2, username.substring(0, Math.min(username.length(), 80)));
                history.setString(3, "FAILURE");
                history.executeUpdate();
                sendError(exchange, 401, "Incorrect username or password");
                return;
            }
            history.setLong(1, user.userId);
            history.setString(2, user.username);
            history.setString(3, "SUCCESS");
            history.executeUpdate();
        }
        byte[] tokenBytes = new byte[32];
        RANDOM.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        sessions.put(token, new UserSession(user.userId, user.username));
        exchange.getResponseHeaders().add("Set-Cookie", sessionCookie(token, 43_200));
        sendJson(exchange, 200, sessionUser(new UserSession(user.userId, user.username)));
    }

    private void logout(HttpExchange exchange) throws IOException {
        String token = cookieValue(exchange, "LOGIQUAL_SESSION");
        if (token != null) {
            sessions.remove(token);
        }
        exchange.getResponseHeaders().add("Set-Cookie", sessionCookie("", 0));
        sendJson(exchange, 200, Map.of("status", "logged_out"));
    }

    private void changePassword(HttpExchange exchange, UserSession actor) throws IOException, SQLException {
        Map<String, Object> body = readObject(exchange);
        String currentPassword = stringValue(body.get("currentPassword"));
        String newPassword = stringValue(body.get("newPassword"));
        String confirmation = stringValue(body.get("confirmPassword"));
        if (currentPassword.isEmpty() || newPassword.isEmpty()) {
            sendError(exchange, 400, "Current and new passwords are required");
            return;
        }
        if (newPassword.length() < 8 || newPassword.length() > 256) {
            sendError(exchange, 400, "New password must be 8–256 characters");
            return;
        }
        if (!newPassword.equals(confirmation)) {
            sendError(exchange, 400, "Password and confirmation do not match");
            return;
        }
        if (currentPassword.equals(newPassword)) {
            sendError(exchange, 400, "Choose a password different from the current password");
            return;
        }

        try (Connection connection = connection()) {
            connection.setAutoCommit(false);
            try {
                String currentHash;
                try (PreparedStatement query = connection.prepareStatement(
                        "SELECT password_hash FROM users WHERE user_id = ? AND account_status = 'ACTIVE'")) {
                    query.setLong(1, actor.userId);
                    try (ResultSet result = query.executeQuery()) {
                        if (!result.next()) {
                            connection.rollback();
                            sendError(exchange, 401, "The account is not active");
                            return;
                        }
                        currentHash = result.getString(1);
                    }
                }
                if (!verifyPassword(currentPassword, currentHash)) {
                    connection.rollback();
                    auditPasswordChange(connection, actor, "FAILURE");
                    connection.commit();
                    sendError(exchange, 400, "Current password is incorrect");
                    return;
                }
                try (PreparedStatement update = connection.prepareStatement("""
                        UPDATE users
                        SET password_hash = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                        WHERE user_id = ?
                        """)) {
                    update.setString(1, hashPassword(newPassword));
                    update.setLong(2, actor.userId);
                    update.executeUpdate();
                }
                auditPasswordChange(connection, actor, "SUCCESS");
                connection.commit();
                sendJson(exchange, 200, Map.of("status", "updated"));
            } catch (SQLException | RuntimeException error) {
                connection.rollback();
                throw error;
            }
        }
    }

    private static void auditPasswordChange(Connection connection, UserSession actor, String outcome)
            throws SQLException {
        try (PreparedStatement audit = connection.prepareStatement("""
                INSERT INTO audit_events(actor_user_id, created_user_id, created_username,
                    action_type, outcome) VALUES (?, ?, ?, 'USER_PASSWORD_CHANGED', ?)
                """)) {
            audit.setLong(1, actor.userId);
            audit.setLong(2, actor.userId);
            audit.setString(3, actor.username);
            audit.setString(4, outcome);
            audit.executeUpdate();
        }
    }

    private UserSession requireSession(HttpExchange exchange) {
        String token = cookieValue(exchange, "LOGIQUAL_SESSION");
        UserSession session = token == null ? null : sessions.get(token);
        if (session == null) {
            throw new AuthenticationRequired();
        }
        return session;
    }

    private void listUsers(HttpExchange exchange) throws IOException, SQLException {
        String query = exchange.getRequestURI().getRawQuery();
        Map<String, String> parameters = queryParameters(query);
        String search = parameters.getOrDefault("search", "").trim();
        String status = parameters.getOrDefault("status", "").trim();
        StringBuilder sql = new StringBuilder("""
                SELECT u.user_id, u.username, u.account_status, u.created_at, u.created_by_user_id,
                       creator.username AS creator_username
                FROM users u LEFT JOIN users creator ON creator.user_id = u.created_by_user_id
                WHERE 1 = 1
                """);
        if (!search.isEmpty()) {
            sql.append(" AND (u.username LIKE ? COLLATE NOCASE OR creator.username LIKE ? COLLATE NOCASE)");
        }
        if (!status.isEmpty()) {
            sql.append(" AND u.account_status = ?");
        }
        sql.append(" ORDER BY u.created_at DESC, u.user_id DESC");
        List<Map<String, Object>> users = new ArrayList<>();
        try (Connection connection = connection(); PreparedStatement statement = connection.prepareStatement(sql.toString())) {
            int index = 1;
            if (!search.isEmpty()) {
                statement.setString(index++, "%" + search + "%");
                statement.setString(index++, "%" + search + "%");
            }
            if (!status.isEmpty()) {
                statement.setString(index, status);
            }
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    users.add(safeUser(result));
                }
            }
        }
        sendJson(exchange, 200, users);
    }

    private void getUser(HttpExchange exchange, String idText) throws IOException, SQLException {
        long userId;
        try {
            userId = Long.parseLong(idText);
        } catch (NumberFormatException error) {
            throw new BadRequest("User ID must be a number");
        }
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT u.user_id, u.username, u.account_status, u.created_at, u.created_by_user_id,
                            creator.username AS creator_username
                     FROM users u LEFT JOIN users creator ON creator.user_id = u.created_by_user_id
                     WHERE u.user_id = ?
                     """)) {
            statement.setLong(1, userId);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    sendError(exchange, 404, "User not found");
                    return;
                }
                sendJson(exchange, 200, safeUser(result));
            }
        }
    }

    private void createUser(HttpExchange exchange, UserSession actor) throws IOException, SQLException {
        Map<String, Object> body = readObject(exchange);
        String username = stringValue(body.get("username")).trim();
        String password = stringValue(body.get("password"));
        String confirmation = stringValue(body.get("confirmPassword"));
        if (username.isEmpty()) {
            auditFailure(actor, username);
            sendError(exchange, 400, "Username is required");
            return;
        }
        if (username.length() > 80 || username.chars().anyMatch(Character::isISOControl)) {
            auditFailure(actor, username);
            sendError(exchange, 400, "Username must be 1–80 characters without control characters");
            return;
        }
        if (password.isEmpty()) {
            auditFailure(actor, username);
            sendError(exchange, 400, "Password is required");
            return;
        }
        if (password.length() < 8) {
            auditFailure(actor, username);
            sendError(exchange, 400, "Password must be at least 8 characters");
            return;
        }
        if (password.length() > 256) {
            auditFailure(actor, username);
            sendError(exchange, 400, "Password must be no more than 256 characters");
            return;
        }
        if (!password.equals(confirmation)) {
            auditFailure(actor, username);
            sendError(exchange, 400, "Password and confirmation do not match");
            return;
        }

        try (Connection connection = connection()) {
            connection.setAutoCommit(false);
            try {
                long userId;
                try (PreparedStatement insert = connection.prepareStatement("""
                        INSERT INTO users(username, password_hash, account_status, created_by_user_id, created_at)
                        VALUES (?, ?, 'ACTIVE', ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                        """, Statement.RETURN_GENERATED_KEYS)) {
                    insert.setString(1, username);
                    insert.setString(2, hashPassword(password));
                    insert.setLong(3, actor.userId);
                    insert.executeUpdate();
                    userId = lastInsertedUserId(connection);
                }
                try (PreparedStatement audit = connection.prepareStatement("""
                        INSERT INTO audit_events(actor_user_id, created_user_id, created_username,
                            action_type, outcome) VALUES (?, ?, ?, 'USER_CREATED', 'SUCCESS')
                        """)) {
                    audit.setLong(1, actor.userId);
                    audit.setLong(2, userId);
                    audit.setString(3, username);
                    audit.executeUpdate();
                }
                connection.commit();
                sendJson(exchange, 201, findSafeUser(connection, userId));
            } catch (SQLException error) {
                connection.rollback();
                if (isUniqueConstraint(error)) {
                    auditFailure(actor, username);
                    sendError(exchange, 409, "That username is already registered");
                    return;
                }
                throw error;
            }
        }
    }

    private void auditFailure(UserSession actor, String username) throws SQLException {
        try (Connection connection = connection();
             PreparedStatement audit = connection.prepareStatement("""
                     INSERT INTO audit_events(actor_user_id, created_user_id, created_username,
                         action_type, outcome) VALUES (?, NULL, ?, 'USER_CREATED', 'FAILURE')
                     """)) {
            audit.setLong(1, actor.userId);
            audit.setString(2, username.substring(0, Math.min(username.length(), 80)));
            audit.executeUpdate();
        }
    }

    private void listRecords(HttpExchange exchange) throws IOException, SQLException {
        Map<String, List<Map<String, Object>>> records = new HashMap<>();
        RECORD_TYPES.forEach(type -> records.put(type, new ArrayList<>()));
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT record_type, payload_json FROM qms_records ORDER BY record_id")) {
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    String type = result.getString("record_type");
                    List<Map<String, Object>> items = records.get(type);
                    if (items != null) {
                        items.add(JSON.readValue(result.getString("payload_json"),
                                new TypeReference<Map<String, Object>>() {}));
                    }
                }
            }
        }
        sendJson(exchange, 200, records);
    }

    private void saveRecords(HttpExchange exchange) throws IOException, SQLException {
        Map<String, Object> body = readObject(exchange);
        try (Connection connection = connection()) {
            connection.setAutoCommit(false);
            try (PreparedStatement save = connection.prepareStatement("""
                    INSERT INTO qms_records(record_type, record_id, payload_json)
                    VALUES (?, ?, ?)
                    ON CONFLICT(record_type, record_id) DO UPDATE SET
                        payload_json = excluded.payload_json,
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                    """)) {
                if (Boolean.TRUE.equals(body.get("replace"))) {
                    try (Statement delete = connection.createStatement()) {
                        delete.executeUpdate("DELETE FROM qms_records");
                    }
                }
                for (String type : RECORD_TYPES) {
                    Object value = body.get(type);
                    if (value == null) {
                        continue;
                    }
                    if (!(value instanceof List<?> items)) {
                        throw new BadRequest("QMS record collections must be arrays");
                    }
                    for (Object item : items) {
                        if (!(item instanceof Map<?, ?> record) || !(record.get("id") instanceof Number id)) {
                            throw new BadRequest("Each QMS record must have a numeric ID");
                        }
                        save.setString(1, type);
                        save.setLong(2, id.longValue());
                        save.setString(3, JSON.writeValueAsString(item));
                        save.addBatch();
                    }
                }
                save.executeBatch();
                connection.commit();
            } catch (IOException | SQLException | RuntimeException error) {
                connection.rollback();
                throw error;
            }
        }
        sendJson(exchange, 200, Map.of("status", "saved"));
    }

    private void getSqaMeasurements(HttpExchange exchange) throws IOException, SQLException {
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT payload_json FROM sqa_measurements WHERE measurement_id = 1");
             ResultSet result = statement.executeQuery()) {
            if (result.next()) {
                sendJson(exchange, 200, JSON.readValue(
                        result.getString("payload_json"), new TypeReference<Map<String, Object>>() {}));
                return;
            }
            Map<String, Object> empty = new HashMap<>();
            SQA_INPUT_FIELDS.forEach(field -> empty.put(field, 0));
            sendJson(exchange, 200, empty);
        }
    }

    private void saveSqaMeasurements(HttpExchange exchange) throws IOException, SQLException {
        Map<String, Object> body = readObject(exchange);
        if (body.size() != SQA_INPUT_FIELDS.size() || !body.keySet().containsAll(SQA_INPUT_FIELDS)) {
            throw new BadRequest("Provide all ten SQA measurement fields");
        }
        Set<String> integerFields = Set.of("nceLow", "nceMedium", "nceHigh", "nde", "functionPoints",
                "reusedDocuments", "totalDocuments");
        Map<String, Object> values = new HashMap<>();
        for (String field : SQA_INPUT_FIELDS) {
            Object raw = body.get(field);
            if (!(raw instanceof Number number)) {
                throw new BadRequest(field + " must be a non-negative number");
            }
            double value = number.doubleValue();
            if (!Double.isFinite(value) || value < 0 || value > 1_000_000_000d) {
                throw new BadRequest(field + " must be between 0 and 1,000,000,000");
            }
            if (integerFields.contains(field) && value != Math.floor(value)) {
                throw new BadRequest(field + " must be a whole number");
            }
            values.put(field, number);
        }
        if (((Number) values.get("reusedKloc")).doubleValue()
                > ((Number) values.get("kloc")).doubleValue()) {
            throw new BadRequest("Reused KLOC cannot exceed total KLOC");
        }
        if (((Number) values.get("reusedDocuments")).doubleValue()
                > ((Number) values.get("totalDocuments")).doubleValue()) {
            throw new BadRequest("Reused documents cannot exceed total documents");
        }
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement("""
                     INSERT INTO sqa_measurements(measurement_id, payload_json, updated_at)
                     VALUES (1, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                     ON CONFLICT(measurement_id) DO UPDATE SET
                         payload_json = excluded.payload_json,
                         updated_at = excluded.updated_at
                     """)) {
            statement.setString(1, JSON.writeValueAsString(values));
            statement.executeUpdate();
        }
        sendJson(exchange, 200, values);
    }

    private Map<String, Object> findSafeUser(Connection connection, long userId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT u.user_id, u.username, u.account_status, u.created_at, u.created_by_user_id,
                       creator.username AS creator_username
                FROM users u LEFT JOIN users creator ON creator.user_id = u.created_by_user_id
                WHERE u.user_id = ?
                """)) {
            statement.setLong(1, userId);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new SQLException("New account could not be retrieved");
                }
                return safeUser(result);
            }
        }
    }

    private static long lastInsertedUserId(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(
                     "SELECT user_id FROM users WHERE rowid = last_insert_rowid()")) {
            if (!result.next()) {
                throw new SQLException("Could not retrieve the inserted user ID");
            }
            return result.getLong(1);
        }
    }

    private static Map<String, Object> safeUser(ResultSet result) throws SQLException {
        Map<String, Object> user = new HashMap<>();
        user.put("userId", result.getLong("user_id"));
        user.put("username", result.getString("username"));
        user.put("accountStatus", result.getString("account_status"));
        user.put("createdAt", result.getString("created_at"));
        long creatorId = result.getLong("created_by_user_id");
        user.put("createdByUserId", result.wasNull() ? null : creatorId);
        user.put("createdByUsername", result.getString("creator_username"));
        return user;
    }

    private static UserRecord readUser(ResultSet result) throws SQLException {
        long creatorId = result.getLong("created_by_user_id");
        Long nullableCreatorId = result.wasNull() ? null : creatorId;
        return new UserRecord(result.getLong("user_id"), result.getString("username"),
                result.getString("account_status"), result.getString("created_at"), nullableCreatorId);
    }

    private static Map<String, Object> sessionUser(UserSession user) {
        return Map.of("userId", user.userId, "username", user.username);
    }

    private static Map<String, Object> readObject(HttpExchange exchange) throws IOException {
        byte[] bytes = exchange.getRequestBody().readNBytes(MAX_BODY_BYTES + 1);
        if (bytes.length > MAX_BODY_BYTES) {
            throw new BadRequest("Request is too large");
        }
        try {
            Map<String, Object> value = JSON.readValue(bytes, new TypeReference<Map<String, Object>>() {});
            if (value == null) {
                throw new BadRequest("Request must contain a JSON object");
            }
            return value;
        } catch (IOException error) {
            throw new BadRequest("Request must contain valid JSON");
        }
    }

    private static void sendJson(HttpExchange exchange, int status, Object value) throws IOException {
        byte[] body = JSON.writeValueAsBytes(value);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
    }

    private static void sendError(HttpExchange exchange, int status, String message) throws IOException {
        sendJson(exchange, status, Map.of("error", message));
    }

    private static String stringValue(Object value) {
        return value instanceof String text ? text : "";
    }

    private static String cookieValue(HttpExchange exchange, String name) {
        List<String> headers = exchange.getRequestHeaders().get("Cookie");
        if (headers == null) {
            return null;
        }
        for (String header : headers) {
            for (String cookie : header.split(";")) {
                String[] parts = cookie.trim().split("=", 2);
                if (parts.length == 2 && parts[0].equals(name)) {
                    String value = parts[1];
                    if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
                        return value.substring(1, value.length() - 1);
                    }
                    return value;
                }
            }
        }
        return null;
    }

    private static String sessionCookie(String token, int maxAge) {
        String secure = Boolean.parseBoolean(System.getenv().getOrDefault("LOGIQUAL_COOKIE_SECURE", "false"))
                ? "; Secure" : "";
        return "LOGIQUAL_SESSION=" + token + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=" + maxAge + secure;
    }

    private static Map<String, String> queryParameters(String query) {
        Map<String, String> parameters = new HashMap<>();
        if (query == null || query.isBlank()) {
            return parameters;
        }
        for (String part : query.split("&")) {
            String[] pair = part.split("=", 2);
            parameters.put(java.net.URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
                    pair.length == 2 ? java.net.URLDecoder.decode(pair[1], StandardCharsets.UTF_8) : "");
        }
        return parameters;
    }

    private static String hashPassword(String password) {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        byte[] hash = derive(password.toCharArray(), salt, HASH_ITERATIONS);
        return "pbkdf2-sha256$" + HASH_ITERATIONS + "$" + Base64.getEncoder().encodeToString(salt)
                + "$" + Base64.getEncoder().encodeToString(hash);
    }

    private static boolean verifyPassword(String password, String encoded) {
        String[] parts = encoded.split("\\$", -1);
        if (parts.length != 4 || !parts[0].equals("pbkdf2-sha256")) {
            return false;
        }
        try {
            int iterations = Integer.parseInt(parts[1]);
            if (iterations < 1 || iterations > 2_000_000) {
                return false;
            }
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            return MessageDigest.isEqual(expected, derive(password.toCharArray(), salt, iterations));
        } catch (IllegalArgumentException error) {
            return false;
        }
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (Exception error) {
            throw new IllegalStateException("Password hashing is not available", error);
        } finally {
            spec.clearPassword();
            java.util.Arrays.fill(password, '\0');
        }
    }

    private static boolean isUniqueConstraint(SQLException error) {
        return error.getErrorCode() == 19 || error.getMessage().toLowerCase().contains("unique constraint");
    }

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        Path database = Path.of(System.getenv().getOrDefault("LOGIQUAL_DB_PATH", "data/logiqual.sqlite"));
        LogiQualServer application = new LogiQualServer(database, port);
        application.start();
        System.out.println("LogiQual QMS is available at http://localhost:" + application.port());
        Runtime.getRuntime().addShutdownHook(new Thread(application::stop));
    }

    private record UserSession(long userId, String username) {}
    private record UserRecord(long userId, String username, String accountStatus, String createdAt, Long createdByUserId) {}

    private static final class AuthenticationRequired extends RuntimeException {}
    private static final class BadRequest extends RuntimeException {
        private BadRequest(String message) {
            super(message);
        }
    }
}
