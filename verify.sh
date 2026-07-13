#!/bin/bash
set -e

# Load DATABASE_URL from .env
if [ -f .env ]; then
  export DATABASE_URL=$(grep '^DATABASE_URL=' .env | cut -d'=' -f2-)
fi

if [ -z "$DATABASE_URL" ]; then
  echo "DATABASE_URL not set. Cannot run tests."
  exit 1
fi

# Track the test email so we can clean it up
EMAIL="test_$(date +%s)@example.com"

# Cleanup function: stop server + delete test user from DB
cleanup() {
    echo ""
    echo "--- CLEANUP ---"
    echo "Stopping Auth Service..."
    kill $CARGO_PID 2>/dev/null || true
    wait $CARGO_PID 2>/dev/null || true

    echo "Cleaning up test user '$EMAIL' from database..."
    # Delete refresh tokens first (FK constraint), then the user
    psql "$DATABASE_URL" -q -c "DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE email = '$EMAIL');" 2>/dev/null || true
    psql "$DATABASE_URL" -q -c "DELETE FROM users WHERE email = '$EMAIL';" 2>/dev/null || true
    echo "Database cleanup complete."
}
trap cleanup EXIT

echo "Starting Auth Service in background..."
cargo run &
CARGO_PID=$!

echo "Waiting for service to start and apply migrations..."
sleep 5

PASSWORD="Password123!!"
NEW_PASSWORD="NewPassword123!!"

echo "--- 1. GET /health ---"
HEALTH_RES=$(curl -s http://localhost:8080/health)
echo "Health Response: $HEALTH_RES"
if [[ "$HEALTH_RES" != *"\"success\":true"* || "$HEALTH_RES" != *"\"status\":\"healthy\""* ]]; then
  echo "Health check failed!"
  exit 1
fi

echo "--- 2. GET /.well-known/jwks.json ---"
JWKS_RES=$(curl -s http://localhost:8080/.well-known/jwks.json)
echo "JWKS Response: $JWKS_RES"
if [[ "$JWKS_RES" != *"\"kid\":\"2026-01\""* || "$JWKS_RES" != *"\"kty\":\"OKP\""* || "$JWKS_RES" != *"\"crv\":\"Ed25519\""* || "$JWKS_RES" != *"\"alg\":\"EdDSA\""* ]]; then
  echo "JWKS response does not match specification!"
  exit 1
fi

echo "--- 3. POST /register ---"
REGISTER_RES=$(curl -s -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\", \"password\":\"$PASSWORD\"}")

echo "Register Response: $REGISTER_RES"
if [[ "$REGISTER_RES" != *"\"success\":true"* ]]; then
  echo "Registration failed!"
  exit 1
fi

ACCESS_TOKEN=$(echo "$REGISTER_RES" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
REFRESH_TOKEN=$(echo "$REGISTER_RES" | grep -o '"refresh_token":"[^"]*' | cut -d'"' -f4)

echo "--- 4. Verify 'kid' header in JWT ---"
JWT_HEADER=$(echo "$ACCESS_TOKEN" | cut -d'.' -f1)
DECODED_HEADER=$(echo "$JWT_HEADER" | base64 --decode 2>/dev/null || echo "$JWT_HEADER" | base64 -d 2>/dev/null)
echo "Decoded JWT Header: $DECODED_HEADER"
if [[ "$DECODED_HEADER" != *"\"kid\":\"2026-01\""* ]]; then
  echo "JWT header is missing correct 'kid'!"
  exit 1
fi

echo "--- 5. POST /register duplicate email (should fail) ---"
DUP_RES=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\", \"password\":\"$PASSWORD\"}")
DUP_STATUS=$(echo "$DUP_RES" | tail -n1 | cut -d':' -f2)
echo "Duplicate Register Status: $DUP_STATUS"
if [[ "$DUP_STATUS" != "400" ]]; then
  echo "Expected 400 for duplicate email, got $DUP_STATUS!"
  exit 1
fi

echo "--- 6. POST /register with weak password (should fail) ---"
WEAK_RES=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"weak_$(date +%s)@example.com\", \"password\":\"short\"}")
WEAK_STATUS=$(echo "$WEAK_RES" | tail -n1 | cut -d':' -f2)
echo "Weak Password Register Status: $WEAK_STATUS"
if [[ "$WEAK_STATUS" != "400" ]]; then
  echo "Expected 400 for weak password, got $WEAK_STATUS!"
  exit 1
fi

echo "--- 7. POST /register with invalid email (should fail) ---"
BADEMAIL_RES=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"not-an-email\", \"password\":\"$PASSWORD\"}")
BADEMAIL_STATUS=$(echo "$BADEMAIL_RES" | tail -n1 | cut -d':' -f2)
echo "Bad Email Register Status: $BADEMAIL_STATUS"
if [[ "$BADEMAIL_STATUS" != "400" ]]; then
  echo "Expected 400 for invalid email, got $BADEMAIL_STATUS!"
  exit 1
fi

echo "--- 8. GET /me (With valid token) ---"
ME_RES=$(curl -s -X GET http://localhost:8080/me \
  -H "Authorization: Bearer $ACCESS_TOKEN")
echo "Me Response: $ME_RES"
if [[ "$ME_RES" != *"$EMAIL"* ]]; then
  echo "Me request failed!"
  exit 1
fi

echo "--- 9. GET /me (With invalid token) ---"
ME_ERR_RES=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X GET http://localhost:8080/me \
  -H "Authorization: Bearer invalidtoken")
ME_ERR_STATUS=$(echo "$ME_ERR_RES" | tail -n1 | cut -d':' -f2)
echo "Me Error Response: $ME_ERR_RES"
if [[ "$ME_ERR_STATUS" != "401" ]]; then
  echo "Expected 401 for invalid token, got $ME_ERR_STATUS!"
  exit 1
fi

echo "--- 10. GET /me (No auth header) ---"
ME_NO_AUTH_RES=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X GET http://localhost:8080/me)
ME_NO_AUTH_STATUS=$(echo "$ME_NO_AUTH_RES" | tail -n1 | cut -d':' -f2)
echo "Me No Auth Status: $ME_NO_AUTH_STATUS"
if [[ "$ME_NO_AUTH_STATUS" != "401" ]]; then
  echo "Expected 401 for missing auth, got $ME_NO_AUTH_STATUS!"
  exit 1
fi

echo "--- 11. POST /login ---"
LOGIN_RES=$(curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\", \"password\":\"$PASSWORD\"}")
echo "Login Response: $LOGIN_RES"
if [[ "$LOGIN_RES" != *"\"success\":true"* ]]; then
  echo "Login failed!"
  exit 1
fi

NEW_ACCESS_TOKEN=$(echo "$LOGIN_RES" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
NEW_REFRESH_TOKEN=$(echo "$LOGIN_RES" | grep -o '"refresh_token":"[^"]*' | cut -d'"' -f4)

echo "--- 12. POST /login with wrong password (should fail) ---"
LOGIN_WRONG_RES=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\", \"password\":\"WrongPassword123!!\"}")
LOGIN_WRONG_STATUS=$(echo "$LOGIN_WRONG_RES" | tail -n1 | cut -d':' -f2)
echo "Wrong Password Login Status: $LOGIN_WRONG_STATUS"
if [[ "$LOGIN_WRONG_STATUS" != "401" ]]; then
  echo "Expected 401 for wrong password, got $LOGIN_WRONG_STATUS!"
  exit 1
fi

echo "--- 13. POST /login with nonexistent email (should fail with same error) ---"
LOGIN_NOUSER_RES=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"nonexistent_$(date +%s)@example.com\", \"password\":\"$PASSWORD\"}")
LOGIN_NOUSER_STATUS=$(echo "$LOGIN_NOUSER_RES" | tail -n1 | cut -d':' -f2)
echo "Nonexistent User Login Status: $LOGIN_NOUSER_STATUS"
if [[ "$LOGIN_NOUSER_STATUS" != "401" ]]; then
  echo "Expected 401 for nonexistent user, got $LOGIN_NOUSER_STATUS!"
  exit 1
fi
# Verify generic error message (no email/password hint)
if [[ "$LOGIN_NOUSER_RES" != *"\"error\":\"Invalid credentials.\""* ]]; then
  echo "Error message leaks information! Should be generic."
  exit 1
fi

echo "--- 14. POST /refresh ---"
REFRESH_RES=$(curl -s -X POST http://localhost:8080/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$NEW_REFRESH_TOKEN\"}")
echo "Refresh Response: $REFRESH_RES"
if [[ "$REFRESH_RES" != *"\"success\":true"* ]]; then
  echo "Refresh failed!"
  exit 1
fi

ROTATED_ACCESS_TOKEN=$(echo "$REFRESH_RES" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
ROTATED_REFRESH_TOKEN=$(echo "$REFRESH_RES" | grep -o '"refresh_token":"[^"]*' | cut -d'"' -f4)

echo "--- 15. POST /refresh with OLD token (should fail after rotation) ---"
REUSE_RES=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$NEW_REFRESH_TOKEN\"}")
REUSE_STATUS=$(echo "$REUSE_RES" | tail -n1 | cut -d':' -f2)
echo "Old Refresh Token Reuse Status: $REUSE_STATUS"
if [[ "$REUSE_STATUS" != "401" ]]; then
  echo "Expected 401 for reused refresh token, got $REUSE_STATUS!"
  exit 1
fi

echo "--- 16. POST /refresh with garbage token (should fail) ---"
GARBAGE_RES=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"aaaaaabbbbbbccccccddddddeeeeeeffffffff\"}")
GARBAGE_STATUS=$(echo "$GARBAGE_RES" | tail -n1 | cut -d':' -f2)
echo "Garbage Refresh Token Status: $GARBAGE_STATUS"
if [[ "$GARBAGE_STATUS" != "401" ]]; then
  echo "Expected 401 for garbage refresh token, got $GARBAGE_STATUS!"
  exit 1
fi

echo "--- 17. POST /change-password ---"
CHANGE_PW_RES=$(curl -s -X POST http://localhost:8080/change-password \
  -H "Authorization: Bearer $ROTATED_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"current_password\":\"$PASSWORD\", \"new_password\":\"$NEW_PASSWORD\"}")
echo "Change Password Response: $CHANGE_PW_RES"
if [[ "$CHANGE_PW_RES" != *"\"success\":true"* ]]; then
  echo "Password change failed!"
  exit 1
fi

echo "--- 18. POST /change-password with wrong current (should fail) ---"
CHANGE_PW_WRONG_RES=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/change-password \
  -H "Authorization: Bearer $ROTATED_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"current_password\":\"WrongOldPassword1!\", \"new_password\":\"AnotherNew123!!\"}")
CHANGE_PW_WRONG_STATUS=$(echo "$CHANGE_PW_WRONG_RES" | tail -n1 | cut -d':' -f2)
echo "Wrong Current Password Status: $CHANGE_PW_WRONG_STATUS"
if [[ "$CHANGE_PW_WRONG_STATUS" != "401" ]]; then
  echo "Expected 401 for wrong current password, got $CHANGE_PW_WRONG_STATUS!"
  exit 1
fi

echo "--- 19. POST /login with old password (should fail) ---"
LOGIN_FAIL_RES=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\", \"password\":\"$PASSWORD\"}")
LOGIN_FAIL_STATUS=$(echo "$LOGIN_FAIL_RES" | tail -n1 | cut -d':' -f2)
echo "Login Old Password Status: $LOGIN_FAIL_STATUS"
if [[ "$LOGIN_FAIL_STATUS" != "401" ]]; then
  echo "Expected 401 for old password, got $LOGIN_FAIL_STATUS!"
  exit 1
fi

echo "--- 20. POST /login with new password ---"
LOGIN_SUCCESS_RES=$(curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\", \"password\":\"$NEW_PASSWORD\"}")
echo "Login Success Response: $LOGIN_SUCCESS_RES"
if [[ "$LOGIN_SUCCESS_RES" != *"\"success\":true"* ]]; then
  echo "Login with new password failed!"
  exit 1
fi

FINAL_ACCESS_TOKEN=$(echo "$LOGIN_SUCCESS_RES" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

echo "--- 21. POST /logout ---"
LOGOUT_RES=$(curl -s -X POST http://localhost:8080/logout \
  -H "Authorization: Bearer $FINAL_ACCESS_TOKEN")
echo "Logout Response: $LOGOUT_RES"
if [[ "$LOGOUT_RES" != *"\"success\":true"* ]]; then
  echo "Logout failed!"
  exit 1
fi

echo "--- 22. POST /logout without auth (should fail) ---"
LOGOUT_NOAUTH_RES=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/logout)
LOGOUT_NOAUTH_STATUS=$(echo "$LOGOUT_NOAUTH_RES" | tail -n1 | cut -d':' -f2)
echo "Logout No Auth Status: $LOGOUT_NOAUTH_STATUS"
if [[ "$LOGOUT_NOAUTH_STATUS" != "401" ]]; then
  echo "Expected 401 for unauthenticated logout, got $LOGOUT_NOAUTH_STATUS!"
  exit 1
fi

echo "--- 23. Rate Limit Test (10 login requests allowed, then 429) ---"
RATE_LIMITED=false
for i in {1..15}; do
  RES=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EMAIL\", \"password\":\"$NEW_PASSWORD\"}")

  STATUS=$(echo "$RES" | tail -n1 | cut -d':' -f2)
  echo "  Attempt $i: Status $STATUS"

  if [[ "$STATUS" == "429" ]]; then
    RATE_LIMITED=true
    echo "  Rate limiting triggered at attempt $i!"
    break
  fi
done

if [ "$RATE_LIMITED" = false ]; then
  echo "Rate limit was NOT triggered!"
  exit 1
fi

echo "--- 24. Rate Limit Bypass Attempt (X-Forwarded-For spoof, should STILL be 429) ---"
SPOOF_RES=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 8.8.8.8" \
  -H "X-Real-IP: 8.8.8.8" \
  -d "{\"email\":\"$EMAIL\", \"password\":\"$NEW_PASSWORD\"}")

SPOOF_STATUS=$(echo "$SPOOF_RES" | tail -n1 | cut -d':' -f2)
echo "Spoof Attempt Status: $SPOOF_STATUS"

if [[ "$SPOOF_STATUS" != "429" ]]; then
  echo "Rate limit bypass succeeded! Expected 429 but got $SPOOF_STATUS."
  exit 1
else
  echo "Rate limit bypass blocked (server uses SocketAddr, not headers)."
fi

echo ""
echo "================================================"
echo "  All 24 tests passed successfully!"
echo "  Database cleanup will run on EXIT."
echo "================================================"
