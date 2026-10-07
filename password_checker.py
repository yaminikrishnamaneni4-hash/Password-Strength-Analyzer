import secrets
import string
from getpass import getpass
import hashlib
import sqlite3

print("================================")
print("     PASSWORD STRENGTH CHECKER")
print("================================")

# Get password securely
password = getpass("Enter your password: ")

# Create password hash
password_hash = hashlib.sha256(password.encode()).hexdigest()


# ==============================
# DATABASE SETUP
# ==============================

connection = sqlite3.connect("password_history.db")
cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    password_hash TEXT NOT NULL
)
""")

connection.commit()


# ==============================
# CHECK PASSWORD HISTORY
# ==============================

cursor.execute(
    "SELECT id FROM password_history WHERE password_hash = ?",
    (password_hash,)
)

previously_used = cursor.fetchone()

if previously_used:
    print("⚠️ Password was used before!")
else:
    print("✅ Password has not been used before.")


# ==============================
# PASSWORD SCORE
# ==============================

score = 0


# ==============================
# PASSWORD LENGTH
# ==============================

length = len(password)

print("\nPassword Length:", length)

if length < 8:
    print("Password is too short ❌")
else:
    print("Password length is good ✅")
    score += 1


# ==============================
# UPPERCASE CHECK
# ==============================

if any(char.isupper() for char in password):
    print("Uppercase letter: Present ✅")
    score += 1
else:
    print("Uppercase letter: Missing ❌")


# ==============================
# LOWERCASE CHECK
# ==============================

if any(char.islower() for char in password):
    print("Lowercase letter: Present ✅")
    score += 1
else:
    print("Lowercase letter: Missing ❌")


# ==============================
# NUMBER CHECK
# ==============================

if any(char.isdigit() for char in password):
    print("Number: Present ✅")
    score += 1
else:
    print("Number: Missing ❌")


# ==============================
# SPECIAL CHARACTER CHECK
# ==============================

if any(not char.isalnum() for char in password):
    print("Special character: Present ✅")
    score += 1
else:
    print("Special character: Missing ❌")


# ==============================
# COMMON / PREDICTABLE PASSWORD CHECK
# ==============================

normalized_password = "".join(
    char.lower()
    for char in password
    if char.isalnum()
)

common_patterns = [
    "password",
    "qwerty",
    "admin",
    "welcome",
    "letmein",
    "login",
    "guest",
    "user",
    "iloveyou",
    "monkey",
    "football",
    "abc123",
    "123456",
    "12345678",
    "12345"
]

common_detected = False

for pattern in common_patterns:

    if pattern in normalized_password:
        common_detected = True
        break


# Detect predictable number patterns
if (
    normalized_password.endswith("123")
    or normalized_password.endswith("1234")
    or normalized_password.endswith("2024")
    or normalized_password.endswith("2025")
    or normalized_password.endswith("2026")
):
    common_detected = True


if common_detected:

    print("Common/Predictable password: Detected ❌")
    score = 0

else:

    print("Common/Predictable password: Not detected ✅")


# ==============================
# REPEATED CHARACTER CHECK
# ==============================

repeated = False

for i in range(len(password) - 2):

    if password[i] == password[i + 1] == password[i + 2]:
        repeated = True
        break


if repeated:

    print("Repeated characters: Detected ❌")
    score = max(0, score - 1)

else:

    print("Repeated characters: Not detected ✅")


# ==============================
# SEQUENTIAL PATTERN CHECK
# ==============================

sequential_patterns = [
    "12345",
    "23456",
    "34567",
    "45678",
    "56789",
    "abcde",
    "bcdef",
    "cdefg"
]

sequential = False

for pattern in sequential_patterns:

    if pattern in password.lower():
        sequential = True
        break


if sequential:

    print("Sequential pattern: Detected ❌")
    score = max(0, score - 1)

else:

    print("Sequential pattern: Not detected ✅")


# ==============================
# DISPLAY SCORE
# ==============================

print("\nPassword Score:", score, "/ 5")


# ==============================
# PASSWORD STRENGTH
# ==============================

if score <= 2:

    strength = "WEAK"

elif score <= 4:

    strength = "MEDIUM"

else:

    strength = "STRONG"


print("Password Strength:", strength)


# ==============================
# STRONG PASSWORD GENERATOR
# ==============================

def generate_strong_password(length=16):

    if length < 12:
        length = 12

    password_characters = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(string.punctuation)
    ]

    characters = (
        string.ascii_uppercase
        + string.ascii_lowercase
        + string.digits
        + string.punctuation
    )

    for _ in range(length - 4):

        password_characters.append(
            secrets.choice(characters)
        )

    secrets.SystemRandom().shuffle(password_characters)

    return "".join(password_characters)


# ==============================
# PASSWORD SUGGESTIONS
# ==============================

if strength != "STRONG":

    print("\n💡 Suggested Strong Password:")

    print(generate_strong_password())

    print("\nSuggestions:")

    if length < 12:
        print("- Use at least 12 characters.")

    if not any(char.isupper() for char in password):
        print("- Add an uppercase letter.")

    if not any(char.islower() for char in password):
        print("- Add a lowercase letter.")

    if not any(char.isdigit() for char in password):
        print("- Add a number.")

    if not any(not char.isalnum() for char in password):
        print("- Add a special character.")

    if repeated:
        print("- Avoid repeating the same character.")

    if sequential:
        print("- Avoid predictable sequences like 12345.")

    if common_detected:
        print("- Avoid common or predictable password patterns.")


else:

    print("\n✅ Your password meets the basic strength checks!")


# ==============================
# SAVE PASSWORD HASH
# ==============================

if strength == "STRONG":

    if previously_used:

        print(
            "\n⚠️ This strong password was already stored "
            "in your password history."
        )

    else:

        cursor.execute(
            "INSERT INTO password_history (password_hash) VALUES (?)",
            (password_hash,)
        )

        connection.commit()

        print("\n🔐 Strong password hash saved to password history.")

else:

    print("\nℹ️ Weak/medium password was NOT saved to password history.")


# ==============================
# CLOSE DATABASE
# ==============================

connection.close()

print("\n================================")
print("        CHECK COMPLETE")
print("================================")