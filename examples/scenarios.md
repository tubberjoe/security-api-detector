# Test scenarios

Paste each JSON object separately into the web application.

## 1. Normal authenticated request — expected Benign

```json
{
  "timestamp": "2026-07-21T14:32:15Z",
  "sourceIp": "203.0.113.25",
  "destinationHost": "api.company.com",
  "method": "GET",
  "path": "/api/v1/orders",
  "query": {"page": "1", "limit": "20", "status": "open"},
  "headers": {"User-Agent": "ExampleMobileApp/2.1", "Content-Type": "application/json"},
  "body": {}
}
```

## 2. Normal JSON search — expected Benign

```json
{
  "method": "POST",
  "path": "/api/v1/users/search",
  "query": {},
  "headers": {"Content-Type": "application/json"},
  "body": {"username": "alice", "email": "alice@example.com"}
}
```

## 3. SQL injection in the body — expected Malicious

```json
{
  "method": "POST",
  "path": "/api/v1/users/search",
  "headers": {"Content-Type": "application/json"},
  "body": {"username": "admin' OR 1=1--", "email": ""}
}
```

## 4. SQL injection in a query parameter — expected Malicious

```json
{
  "method": "GET",
  "path": "/api/v1/products",
  "query": {"category": "' UNION SELECT username,password FROM users--"},
  "headers": {"User-Agent": "Mozilla/5.0"}
}
```

## 5. Basic path traversal — expected Malicious

```json
{
  "method": "GET",
  "path": "/api/v1/files/../../../../etc/passwd",
  "headers": {"User-Agent": "curl/8.5.0"}
}
```

## 6. URL-encoded path traversal — expected Malicious

```json
{
  "method": "GET",
  "path": "/download?file=%2e%2e%2f%2e%2e%2fconfig.json",
  "headers": {"User-Agent": "automated-client/1.0"}
}
```

## 7. SSRF against localhost — expected Malicious

```json
{
  "method": "POST",
  "path": "/api/v1/fetch-preview",
  "headers": {"Content-Type": "application/json"},
  "body": {"url": "http://127.0.0.1:8080/admin"}
}
```

## 8. SSRF against cloud metadata — expected Malicious

```json
{
  "method": "POST",
  "path": "/api/v1/import",
  "body": {"sourceUrl": "http://169.254.169.254/latest/meta-data/"}
}
```

## 9. Multiple suspicious signals — expected Malicious

```json
{
  "method": "POST",
  "path": "/api/v1/import?file=../../config.json",
  "headers": {"Content-Type": "application/json"},
  "body": {"callback": "http://127.0.0.1:9000/admin", "filter": "' OR 1=1--"}
}
```

## 10. Missing optional fields — expected Benign

```json
{
  "method": "GET",
  "path": "/health"
}
```

## 11. Malformed JSON — expected input error

This is deliberately not valid JSON:

```text
{"method": "GET", "path": "/api/v1/users"
```

## 12. JSON with nested values — expected Malicious

```json
{
  "method": "POST",
  "path": "/api/v1/profile",
  "body": {
    "profile": {
      "displayName": "normal name",
      "redirect": "http://192.168.1.10/internal",
      "notes": "ordinary text"
    }
  }
}
```

These examples test the current detectors. They do not represent every possible attack or benign request; no small rule-based detector can do that. They are deliberately chosen to exercise normal traffic, each supported detector, combined signals, nested JSON, missing fields, and invalid input.
