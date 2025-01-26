import pytest
from app import create_app, db
from app.models import User

@pytest.fixture
def app():
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # In-memory DB for testing
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

def test_user_creation(app):
    with app.app_context():
        # Clear database before starting
        db.session.query(User).delete()

        user = User(username="testuser", password_hash="password123")
        db.session.add(user)
        db.session.commit()

        assert User.query.filter_by(username="testuser").first() is not None

def test_user_creation_unique(app):
    with app.app_context():
        user1 = User(username="uniqueuser1", password_hash="password123")
        user2 = User(username="uniqueuser2", password_hash="password456")

        db.session.add(user1)
        db.session.add(user2)
        db.session.commit()

        assert User.query.filter_by(username="uniqueuser1").first() is not None
        assert User.query.filter_by(username="uniqueuser2").first() is not None

from sqlalchemy.exc import IntegrityError

def test_user_duplicate_creation(app):
    with app.app_context():
        user = User(username="duplicateuser", password_hash="password123")
        db.session.add(user)
        db.session.commit()

        # Try inserting the same username again
        duplicate_user = User(username="duplicateuser", password_hash="password456")
        db.session.add(duplicate_user)
        try:
            db.session.commit()
            assert False, "Expected IntegrityError not raised"
        except IntegrityError:
            db.session.rollback()
            assert True  # Error correctly raised

