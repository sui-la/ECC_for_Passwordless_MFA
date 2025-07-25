from .models import db, User, Session

def add_user(email, public_key):
    user = User(email=email, public_key=public_key)
    db.session.add(user)
    db.session.commit()
    return user

def get_user_by_email(email):
    return User.query.filter_by(email=email).first()

def add_session(user_id, expires_at):
    # TODO: Add session to the database
    pass

def get_session_by_id(session_id):
    # TODO: Retrieve session by ID
    pass 