from src.database import SessionLocal
from src.models import User


def create_new_admin(username: str):
    db = SessionLocal()

    db_user = db.query(User).filter(User.username == username).first()

    try:
        if db_user:
            db_user.role = "admin"  # type: ignore
            db.commit()
            print(f"User {username} has been promoted to admin")
        else:
            print(f"User {username} does not exist")
    except Exception as error:
        print(f"Error: {error}")
    finally:
        db.close()


# For when the file is run directly, not imported
if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python create_admin.py <username>")
        sys.exit(1)
    else:
        create_new_admin(sys.argv[1])
