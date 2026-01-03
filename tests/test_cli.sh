#!/usr/bin/env sh

echo "╔════════════════════════════════════════════════════════════╗"
echo "║              CLI Testing Script                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    echo "Testing: $1"
    if eval "$2" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}: $1"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}: $1"
        ((TESTS_FAILED++))
    fi
    echo ""
}

echo "=== Test 1: Hash Command ==="
run_test "Hash string with SHA-256" './crypto hash -a sha256 -s "Hello World"'
run_test "Hash string with MD5" './crypto hash -a md5 -s "Test"'

echo "Creating test file..."
echo "This is a test file" > test.txt

run_test "Hash file with SHA-256" './crypto hash -a sha256 -f test.txt'
run_test "Hash file with MD5" './crypto hash -a md5 -f test.txt'

echo "=== Test 2: Key Generation ==="
run_test "Generate 2048-bit key" './crypto keygen -b 2048 -o testkey'
run_test "Key files exist" 'test -f testkey_public.pem && test -f testkey_private.pem'

echo "=== Test 3: Encryption/Decryption ==="
echo "Secret message" > secret.txt

run_test "Encrypt with AES" './crypto encrypt -a aes -f secret.txt -p password123'
run_test "Decrypt with AES" './crypto decrypt -f secret.txt.enc -p password123 -o decrypted.txt'
run_test "Decrypted matches original" 'diff secret.txt decrypted.txt'

echo "=== Test 4: Digital Signatures ==="
echo "Important document" > document.txt

run_test "Sign file" './crypto sign -f document.txt -k testkey_private.pem'
run_test "Verify signature" './crypto verify -f document.txt -k testkey_public.pem'

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    TEST SUMMARY                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
echo ""

# Cleanup
rm -f test.txt secret.txt secret.txt.enc decrypted.txt
rm -f document.txt document.txt.sig
rm -f testkey_public.pem testkey_private.pem

if [ $TESTS_FAILED -eq 0 ]; then
    echo "✓✓✓ All tests passed! ✓✓✓"
    exit 0
else
    echo "✗✗✗ Some tests failed ✗✗✗"
    exit 1
fi
