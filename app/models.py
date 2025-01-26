from app import db

class User(db.Model):
    __tablename__ = 'users'  # Explicitly name the table
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    notes = db.relationship('Note', backref='user', lazy=True, cascade="all, delete-orphan")

# Association table for Note-Tag many-to-many relationship
note_tags = db.Table('note_tags',
    db.Column('note_id', db.Integer, db.ForeignKey('note.id', ondelete='CASCADE'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id', ondelete='CASCADE'), primary_key=True),
    extend_existing=True
)

class Note(db.Model):
    __tablename__ = 'note'  # Explicitly name the table
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    content_encrypted = db.Column(db.Text, nullable=False)

    tags = db.relationship('Tag', secondary='note_tags', backref='notes', lazy='dynamic')

class Tag(db.Model):
    __tablename__ = 'tag'  # Explicitly name the table
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

shared_notes = db.Table('shared_notes',
    db.Column('note_id', db.Integer, db.ForeignKey('note.id', ondelete='CASCADE'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id', ondelete='CASCADE'), primary_key=True)
)