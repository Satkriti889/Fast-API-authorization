import pymysql

# --- IMPORTANT ---
# Manually enter the exact same values from your .env file here.
# Do not use os.getenv(). Type them directly into the strings.
# This eliminates any possibility that the .env file is the problem.

DB_HOST_TEST = "localhost"  # Or "127.0.0.1"
DB_USER_TEST = "your_db_user"
DB_PASSWORD_TEST = "your_db_password"
DB_NAME_TEST = "your_db_name"


print("Attempting to connect to the database...")
print(f"Host: {DB_HOST_TEST}")
print(f"User: {DB_USER_TEST}")
print(f"Database: {DB_NAME_TEST}")

connection = None
try:
    connection = pymysql.connect(
        host=DB_HOST_TEST,
        user=DB_USER_TEST,
        password=DB_PASSWORD_TEST,
        database=DB_NAME_TEST,
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )
    print("\n✅✅✅ --- CONNECTION SUCCESSFUL! --- ✅✅✅")
    print("This means your credentials are correct and the database is running.")

except Exception as e:
    print("\n❌❌❌ --- CONNECTION FAILED! --- ❌❌❌")
    print("\nHere is the detailed error information:")
    # We print multiple representations of the error to get more details
    print(f"Error Type: {type(e)}")
    print(f"Error as string: '{str(e)}'")
    print(f"Error representation: {repr(e)}")

finally:
    if connection:
        connection.close()
        print("\nConnection closed.")