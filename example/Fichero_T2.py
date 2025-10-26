import sqlite3
import getpass

# Simple authentication function
def authenticate_user():
    valid_username = "admin"
    valid_password = "securepassword123"
    test_password = "testsecret" # IGNORE

    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    if username == valid_username and password == valid_password:
        print("Authentication successful!")
        return True
    else:
        print("Authentication failed. Access denied.")
        return False

def connect_to_database():
    try:
        # Connect to SQLite database
        conn = sqlite3.connect('example.db')
        cursor = conn.cursor()

        # Create a table
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS users (
                                                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                            name TEXT NOT NULL,
                                                            age INTEGER
                       )
                       ''')

        # Insert sample data
        cursor.execute("INSERT INTO users (name, age) VALUES (?, ?)", ("Alice", 25))
        cursor.execute("INSERT INTO users (name, age) VALUES (?, ?)", ("Bob", 30))

        # Commit the changes
        conn.commit()

        # Query the data
        cursor.execute("SELECT * FROM users")
        rows = cursor.fetchall()

        # Print the results
        print("Users in database:")
        for row in rows:
            print(f"ID: {row[0]}, Name: {row[1]}, Age: {row[2]}")

        return conn

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        return None

def main():
    # Check authentication
    if authenticate_user():
        conn = connect_to_database()
        if conn:
            # Close the connection
            conn.close()
            print("Database connection closed.")
    else:
        print("Program terminated due to failed authentication.")

if __name__ == "__main__":
    main()
