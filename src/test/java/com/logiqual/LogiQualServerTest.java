package com.logiqual;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;

class LogiQualServerTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    @TempDir
    Path temporaryDirectory;

    private Path database;
    private LogiQualServer server;
    private String baseUrl;

    @BeforeEach
    void startServer() throws Exception {
        database = temporaryDirectory.resolve("qms.sqlite");
        start();
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    void eachDefaultUserCanCreateAnAccountAndNewAccountCanSignIn() throws Exception {
        Map<String, String> initialUsers = Map.of(
                "Mohan", "m@123", "Nruthya", "@n@123", "Sinchana", "s@123");
        int counter = 0;
        for (Map.Entry<String, String> entry : initialUsers.entrySet()) {
            HttpClient creator = client();
            assertEquals(200, login(creator, entry.getKey(), entry.getValue()).statusCode());
            HttpResponse<String> session = request(creator, "GET", "/api/session", null);
            assertEquals(200, session.statusCode());
            String newUsername = "NewUser" + counter++;
            HttpResponse<String> created = createUser(creator, newUsername, "secure-pass-123", "secure-pass-123");
            assertEquals(201, created.statusCode(), created.body());
            Map<String, Object> safeAccount = object(created.body());
            assertEquals(newUsername, safeAccount.get("username"));
            assertFalse(created.body().contains("password_hash"));
            assertFalse(created.body().contains("secure-pass-123"));

            HttpClient newUser = client();
            assertEquals(200, login(newUser, newUsername, "secure-pass-123").statusCode());
        }
    }

    @Test
    void rejectsDuplicateNamesRegardlessOfCaseAndInvalidPasswords() throws Exception {
        HttpClient client = authenticatedClient("Mohan", "m@123");
        assertEquals(201, createUser(client, "CaseSensitive", "strong-pass-1", "strong-pass-1").statusCode());
        assertEquals(409, createUser(client, "casesensitive", "strong-pass-2", "strong-pass-2").statusCode());
        assertEquals(400, createUser(client, "Mismatch", "strong-pass-1", "different-pass").statusCode());
        assertEquals(400, createUser(client, "Weak", "short", "short").statusCode());
        assertEquals(400, createUser(client, "", "strong-pass-1", "strong-pass-1").statusCode());
        assertEquals(400, request(client, "POST", "/api/users", "").statusCode());
        assertEquals(400, request(client, "POST", "/api/users", "null").statusCode());
    }

    @Test
    void protectsEndpointsAndDoesNotExposeHashesOrPasswords() throws Exception {
        HttpClient anonymous = client();
        assertEquals(401, request(anonymous, "GET", "/api/users", null).statusCode());
        assertEquals(401, createUser(anonymous, "Intruder", "secure-pass-123", "secure-pass-123").statusCode());

        HttpClient mohan = authenticatedClient("Mohan", "m@123");
        long actorId = ((Number) object(request(mohan, "GET", "/api/session", null).body()).get("userId")).longValue();
        HttpResponse<String> created = request(mohan, "POST", "/api/users", JSON.writeValueAsString(Map.of(
                "username", "AuditedUser",
                "password", "secure-pass-123",
                "confirmPassword", "secure-pass-123",
                "createdByUserId", 999_999)));
        assertEquals(201, created.statusCode());
        Map<String, Object> user = object(created.body());
        long createdUserId = ((Number) user.get("userId")).longValue();
        assertEquals("Mohan", user.get("createdByUsername"));
        assertEquals(actorId, ((Number) user.get("createdByUserId")).longValue());
        assertNotNull(user.get("createdAt"));
        assertEquals("ACTIVE", user.get("accountStatus"));

        HttpResponse<String> list = request(mohan, "GET", "/api/users", null);
        assertEquals(200, list.statusCode());
        assertFalse(list.body().contains("password_hash"));
        assertFalse(list.body().contains("secure-pass-123"));
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             PreparedStatement query = connection.prepareStatement("""
                     SELECT a.action_type, a.outcome, a.created_username, actor.username, target.user_id
                     FROM audit_events a
                     JOIN users actor ON actor.user_id = a.actor_user_id
                     JOIN users target ON target.user_id = a.created_user_id
                     WHERE target.user_id = ?
                     """)) {
            query.setLong(1, createdUserId);
            try (ResultSet result = query.executeQuery()) {
                assertTrue(result.next());
                assertEquals("USER_CREATED", result.getString(1));
                assertEquals("SUCCESS", result.getString(2));
                assertEquals("AuditedUser", result.getString(3));
                assertEquals("Mohan", result.getString(4));
            }
        }
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             PreparedStatement query = connection.prepareStatement(
                     "SELECT password_hash FROM users WHERE username = 'AuditedUser'")) {
            try (ResultSet result = query.executeQuery()) {
                assertTrue(result.next());
                String hash = result.getString(1);
                assertTrue(hash.startsWith("pbkdf2-sha256$"));
                assertFalse(hash.contains("secure-pass-123"));
            }
        }
        HttpResponse<String> auditEvent = request(mohan, "GET", "/api/users/" + createdUserId, null);
        assertFalse(auditEvent.body().contains("password_hash"));
        assertFalse(auditEvent.body().contains("secure-pass-123"));
    }

    @Test
    void persistsAccountsAndQualityRecordsAcrossServerRestart() throws Exception {
        HttpClient mohan = authenticatedClient("Mohan", "m@123");
        assertEquals(201, createUser(mohan, "PersistentUser", "persistent-pass", "persistent-pass").statusCode());
        String recordPayload = """
                {"plans":[{"id":90,"title":"Delivery interface validation"}]}
                """;
        assertEquals(200, request(mohan, "POST", "/api/records", recordPayload).statusCode());
        String replacementPayload = """
                {"replace":true,"plans":[{"id":91,"title":"Imported logistics quality plan"}]}
                """;
        assertEquals(200, request(mohan, "POST", "/api/records", replacementPayload).statusCode());
        Map<String, Object> measurements = Map.of(
                "nceLow", 42, "nceMedium", 17, "nceHigh", 11, "nde", 80,
                "kloc", 40, "functionPoints", 40, "developmentHours", 800,
                "reusedKloc", 20, "reusedDocuments", 4, "totalDocuments", 8);
        assertEquals(200, request(mohan, "PUT", "/api/sqa-metrics", JSON.writeValueAsString(measurements)).statusCode());

        server.stop();
        server = null;
        start();
        HttpClient afterRestart = client();
        assertEquals(200, login(afterRestart, "PersistentUser", "persistent-pass").statusCode());
        Map<String, Object> records = object(request(afterRestart, "GET", "/api/records", null).body());
        List<?> plans = (List<?>) records.get("plans");
        assertEquals(1, plans.size());
        assertEquals("Imported logistics quality plan", object(JSON.writeValueAsString(plans.get(0))).get("title"));
        assertTrue(((List<?>) records.get("defects")).isEmpty());
        assertEquals(measurements, object(request(afterRestart, "GET", "/api/sqa-metrics", null).body()));
    }

    @Test
    void concurrentDuplicateRegistrationsCreateExactlyOneAccount() throws Exception {
        HttpClient first = authenticatedClient("Mohan", "m@123");
        HttpClient second = authenticatedClient("Nruthya", "@n@123");
        String body = JSON.writeValueAsString(Map.of(
                "username", "RaceAccount", "password", "race-password-123", "confirmPassword", "race-password-123"));
        CompletableFuture<HttpResponse<String>> firstRequest = first.sendAsync(
                requestBuilder("POST", "/api/users", body).build(), HttpResponse.BodyHandlers.ofString());
        CompletableFuture<HttpResponse<String>> secondRequest = second.sendAsync(
                requestBuilder("POST", "/api/users", body).build(), HttpResponse.BodyHandlers.ofString());
        List<Integer> statuses = List.of(firstRequest.join().statusCode(), secondRequest.join().statusCode());
        assertEquals(1, statuses.stream().filter(status -> status == 201).count());
        assertEquals(1, statuses.stream().filter(status -> status == 409).count());
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             PreparedStatement query = connection.prepareStatement(
                     "SELECT COUNT(*) FROM users WHERE username = 'RaceAccount' COLLATE NOCASE");
             ResultSet result = query.executeQuery()) {
            assertTrue(result.next());
            assertEquals(1, result.getInt(1));
        }
    }

    @Test
    void migratesLegacyUserRowsWithoutRecreatingTheDatabase() throws Exception {
        server.stop();
        server = null;
        database = temporaryDirectory.resolve("legacy.sqlite");
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        password TEXT NOT NULL,
                        created_at TEXT
                    )
                    """);
            statement.execute("INSERT INTO users(username, password, created_at) "
                    + "VALUES ('ExistingUser', 'legacy-pass', '2025-01-01T00:00:00Z')");
        }
        start();
        HttpClient existingUser = authenticatedClient("ExistingUser", "legacy-pass");
        assertEquals(201, createUser(existingUser, "AfterMigration", "modern-password", "modern-password").statusCode());

        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement();
             ResultSet columns = statement.executeQuery("PRAGMA table_info(users)")) {
            boolean hasPassword = false;
            boolean hasPasswordHash = false;
            while (columns.next()) {
                hasPassword |= columns.getString("name").equalsIgnoreCase("password");
                hasPasswordHash |= columns.getString("name").equalsIgnoreCase("password_hash");
            }
            assertFalse(hasPassword);
            assertTrue(hasPasswordHash);
        }
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             PreparedStatement query = connection.prepareStatement(
                     "SELECT password_hash FROM users WHERE username = 'ExistingUser'");
             ResultSet result = query.executeQuery()) {
            assertTrue(result.next());
            assertTrue(result.getString(1).startsWith("pbkdf2-sha256$"));
        }
    }

    @Test
    void allowsUsersToReplaceShortInitialPasswordsWithoutLoggingCredentials() throws Exception {
        HttpClient mohan = authenticatedClient("Mohan", "m@123");
        HttpResponse<String> changed = request(mohan, "POST", "/api/password", JSON.writeValueAsString(Map.of(
                "currentPassword", "m@123",
                "newPassword", "mohan-strong-password",
                "confirmPassword", "mohan-strong-password")));
        assertEquals(200, changed.statusCode(), changed.body());
        assertEquals(401, login(client(), "Mohan", "m@123").statusCode());
        HttpClient updatedCredentials = client();
        assertEquals(200, login(updatedCredentials, "Mohan", "mohan-strong-password").statusCode());

        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             PreparedStatement query = connection.prepareStatement("""
                     SELECT action_type, outcome FROM audit_events
                     WHERE created_username = 'Mohan' AND action_type = 'USER_PASSWORD_CHANGED'
                     ORDER BY audit_event_id DESC LIMIT 1
                     """);
             ResultSet result = query.executeQuery()) {
            assertTrue(result.next());
            assertEquals("USER_PASSWORD_CHANGED", result.getString(1));
            assertEquals("SUCCESS", result.getString(2));
        }
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database);
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT created_username, action_type, outcome FROM audit_events")) {
            while (rows.next()) {
                assertFalse(rows.getString(1).contains("mohan-strong-password"));
                assertFalse(rows.getString(2).contains("mohan-strong-password"));
                assertFalse(rows.getString(3).contains("mohan-strong-password"));
            }
        }
    }

    @Test
    void validatesAndPersistsAuthenticatedSqaMeasurementInputs() throws Exception {
        HttpClient anonymous = client();
        assertEquals(401, request(anonymous, "GET", "/api/sqa-metrics", null).statusCode());
        assertEquals(401, request(anonymous, "PUT", "/api/sqa-metrics", "{}").statusCode());

        HttpClient mohan = authenticatedClient("Mohan", "m@123");
        Map<String, Object> measurements = Map.of(
                "nceLow", 42, "nceMedium", 17, "nceHigh", 11, "nde", 80,
                "kloc", 40, "functionPoints", 40, "developmentHours", 800,
                "reusedKloc", 20, "reusedDocuments", 4, "totalDocuments", 8);
        HttpResponse<String> saved = request(mohan, "PUT", "/api/sqa-metrics", JSON.writeValueAsString(measurements));
        assertEquals(200, saved.statusCode(), saved.body());
        assertEquals(measurements, object(request(mohan, "GET", "/api/sqa-metrics", null).body()));

        Map<String, Object> invalidFraction = new java.util.HashMap<>(measurements);
        invalidFraction.put("nceLow", 1.5);
        assertEquals(400, request(mohan, "PUT", "/api/sqa-metrics", JSON.writeValueAsString(invalidFraction)).statusCode());
        Map<String, Object> invalidReuse = new java.util.HashMap<>(measurements);
        invalidReuse.put("reusedKloc", 41);
        assertEquals(400, request(mohan, "PUT", "/api/sqa-metrics", JSON.writeValueAsString(invalidReuse)).statusCode());
        assertEquals(400, request(mohan, "PUT", "/api/sqa-metrics", "{}").statusCode());
    }

    private void start() throws Exception {
        server = new LogiQualServer(database, 0);
        server.start();
        baseUrl = "http://127.0.0.1:" + server.port();
    }

    private HttpClient client() {
        CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        return HttpClient.newBuilder().cookieHandler(cookies).build();
    }

    private HttpClient authenticatedClient(String username, String password) throws Exception {
        HttpClient client = client();
        assertEquals(200, login(client, username, password).statusCode());
        assertEquals(200, request(client, "GET", "/api/session", null).statusCode());
        return client;
    }

    private HttpResponse<String> login(HttpClient client, String username, String password) throws Exception {
        return request(client, "POST", "/api/login", JSON.writeValueAsString(Map.of(
                "username", username, "password", password)));
    }

    private HttpResponse<String> createUser(HttpClient client, String username, String password, String confirmation)
            throws Exception {
        return request(client, "POST", "/api/users", JSON.writeValueAsString(Map.of(
                "username", username, "password", password, "confirmPassword", confirmation)));
    }

    private HttpResponse<String> request(HttpClient client, String method, String path, String body) throws Exception {
        return client.send(requestBuilder(method, path, body).build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpRequest.Builder requestBuilder(String method, String path, String body) {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Content-Type", "application/json");
        if (body == null) {
            request.method(method, HttpRequest.BodyPublishers.noBody());
        } else {
            request.method(method, HttpRequest.BodyPublishers.ofString(body));
        }
        return request;
    }

    private Map<String, Object> object(String json) throws Exception {
        return JSON.readValue(json, new TypeReference<>() {});
    }
}
