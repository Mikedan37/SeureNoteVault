import re

from cryptography.fernet import Fernet
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token
from flask_restx import Namespace, Resource, fields
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import shared_notes
from app import limiter, db
from app.models import User, Note, Tag


# Create a namespace
notes_namespace = Namespace("Notes", description="Notes-related operations")

# Define the Note model for input/output documentation
note_model = notes_namespace.model('Note', {
    'title': fields.String(required=True, description='The title of the note'),
    'content': fields.String(required=True, description='The content of the note')
})

# Define the User model for input documentation
user_model = notes_namespace.model('User', {
    'username': fields.String(required=True, description='The username of the user'),
    'password': fields.String(required=True, description='The password of the user')
})

class NoteVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())

    note = db.relationship('Note', backref='versions')

# Encryption setup (load or generate a key)
key = Fernet.generate_key()
cipher = Fernet(key)

@notes_namespace.route('/register')
class RegisterResource(Resource):
    @limiter.limit("5/minute")
    @notes_namespace.expect(user_model, validate=True)
    @notes_namespace.doc(
        description="Register a new user with a username and password.",
        responses={
            201: 'User registered successfully',
            400: 'Invalid input or user already exists'
        }
    )
    def post(self):
        """Register a new user"""
        data = request.json
        username = data.get("username")
        password = data.get("password")

        if User.query.filter_by(username=username).first():
            # Return a dictionary instead of a Response object
            return {"error": "User already exists"}, 400

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return {"message": "User registered successfully"}, 201

@notes_namespace.route('/login')
class LoginResource(Resource):
    @limiter.limit("5/minute")
    @notes_namespace.expect(user_model, validate=True)
    @notes_namespace.doc(
        description="Log in an existing user to generate a JWT access token.",
        responses={
            200: 'Login successful - Returns JWT token',
            401: 'Invalid credentials'
        }
    )
    def post(self):
        """Log in a user"""
        data = request.json
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({'error': 'Invalid credentials'}), 401

        token = create_access_token(identity=user.id)
        return jsonify({'access_token': token}), 200

@notes_namespace.route('/notes')
class NotesResource(Resource):
    @jwt_required()
    @notes_namespace.doc(
        description="Retrieve all notes for the current user.",
        responses={
            200: 'Success - Returns a list of notes',
            401: 'Unauthorized - Missing or invalid JWT token'
        }
    )
    def get(self):
        """Get all notes"""
        user_id = get_jwt_identity()
        notes = Note.query.filter_by(user_id=user_id).all()

        result = [
            {'id': note.id, 'title': note.title, 'content': cipher.decrypt(note.content_encrypted.encode()).decode()}
            for note in notes
        ]
        return jsonify({'notes': result}), 200

    @jwt_required()
    @notes_namespace.expect(note_model, validate=True)
    @notes_namespace.doc(
        description="Create a new note for the current user.",
        responses={
            201: 'Note created successfully',
            400: 'Invalid input',
            401: 'Unauthorized - Missing or invalid JWT token'
        }
    )
    def post(self):
        """Create a new note"""
        data = request.json
        title = data.get('title')
        content = data.get('content')

        user_id = get_jwt_identity()
        encrypted_content = cipher.encrypt(content.encode()).decode()

        new_note = Note(user_id=user_id, title=title, content_encrypted=encrypted_content)
        db.session.add(new_note)
        db.session.commit()

        return jsonify({'message': 'Note created successfully'}), 201

@notes_namespace.route('/notes/search')
class NotesSearchResource(Resource):
    @jwt_required()
    @notes_namespace.doc(
        params={'q': 'Query to search notes'},
        description="Search for notes by a query string.",
        responses={
            200: 'Success - Returns matching notes',
            401: 'Unauthorized - Missing or invalid JWT token'
        }
    )
    def get(self):
        """Search notes"""
        user_id = get_jwt_identity()
        query = request.args.get('q', '')

        notes = Note.query.filter(
            Note.user_id == user_id,
            Note.title.ilike(f'%{query}%')
        ).all()

        result = [
            {'id': note.id, 'title': note.title, 'content': cipher.decrypt(note.content_encrypted.encode()).decode()}
            for note in notes
        ]
        return jsonify(result), 200

def validate_user_input(username, password):
    if not re.match(r"^[a-zA-Z0-9_.-]{3,30}$", username):
        return False, "Username must be 3-30 characters long and contain only letters, numbers, underscores, or dashes."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    return True, None

@notes_namespace.route('/change-password')
class ChangePasswordResource(Resource):
    @jwt_required()
    @notes_namespace.doc(
        description="Change the current user's password.",
        responses={
            200: 'Password changed successfully',
            400: 'Invalid input',
            401: 'Unauthorized - Invalid JWT token',
        }
    )
    def post(self):
        """Change user password"""
        data = request.json
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if not check_password_hash(user.password_hash, data['current_password']):
            return jsonify({'error': 'Current password is incorrect'}), 400

        user.password_hash = generate_password_hash(data['new_password'])
        db.session.commit()
        return jsonify({'message': 'Password changed successfully'}), 200

@notes_namespace.route('/notes/<int:note_id>')
class NoteResource(Resource):
    @jwt_required()
    @notes_namespace.doc(
        description="Update an existing note.",
        params={'note_id': 'The ID of the note to update'},
        responses={
            200: 'Note updated successfully',
            400: 'Invalid input',
            404: 'Note not found',
            401: 'Unauthorized - Invalid JWT token',
        }
    )
    def put(self, note_id):
        """Update a note"""
        data = request.json
        user_id = get_jwt_identity()
        note = Note.query.filter_by(id=note_id, user_id=user_id).first()

        if not note:
            return jsonify({'error': 'Note not found'}), 404

        note.title = data.get('title', note.title)
        note.content_encrypted = cipher.encrypt(data.get('content', '').encode()).decode()
        db.session.commit()

        return jsonify({'message': 'Note updated successfully'}), 200

@notes_namespace.route('/notes/<int:note_id>')
class NoteResource(Resource):
    @jwt_required()
    @notes_namespace.doc(
        description="Delete an existing note.",
        params={'note_id': 'The ID of the note to delete'},
        responses={
            200: 'Note deleted successfully',
            404: 'Note not found',
            401: 'Unauthorized - Invalid JWT token',
        }
    )
    def delete(self, note_id):
        """Delete a note"""
        user_id = get_jwt_identity()
        note = Note.query.filter_by(id=note_id, user_id=user_id).first()

        if not note:
            return jsonify({'error': 'Note not found'}), 404

        db.session.delete(note)
        db.session.commit()

        return jsonify({'message': 'Note deleted successfully'}), 200

@notes_namespace.route('/refresh')
class RefreshTokenResource(Resource):
    @jwt_required(refresh=True)
    @notes_namespace.doc(
        description="Get a new access token using a refresh token.",
        responses={
            200: 'Access token refreshed successfully',
            401: 'Unauthorized - Invalid or missing refresh token',
        }
    )
    def post(self):
        """Refresh access token"""
        identity = get_jwt_identity()
        new_access_token = create_access_token(identity=identity)
        return jsonify({'access_token': new_access_token}), 200

@notes_namespace.route('/count')
class NotesCountResource(Resource):
    @jwt_required()
    @notes_namespace.doc(
        description="Get the total count of notes for the current user.",
        responses={
            200: 'Returns the total notes count',
            401: 'Unauthorized - Invalid JWT token',
        }
    )
    def get(self):
        """Get total notes count"""
        user_id = get_jwt_identity()
        notes_count = Note.query.filter_by(user_id=user_id).count()
        return jsonify({'total_notes': notes_count}), 200

@notes_namespace.route('/notes/<int:note_id>/share')
class ShareNoteResource(Resource):
    @jwt_required()
    @notes_namespace.doc(
        description="Share a note with another user.",
        params={'note_id': 'The ID of the note to share'},
        responses={
            200: 'Note shared successfully',
            400: 'Invalid input',
            404: 'Note or recipient not found',
            401: 'Unauthorized - Invalid JWT token',
        }
    )
    def post(self, note_id):
        """Share a note with another user"""
        data = request.json
        recipient_username = data.get('recipient_username')

        # Get the authenticated user
        user_id = get_jwt_identity()
        note = Note.query.filter_by(id=note_id, user_id=user_id).first()

        if not note:
            return jsonify({'error': 'Note not found'}), 404

        # Find the recipient
        recipient = User.query.filter_by(username=recipient_username).first()
        if not recipient:
            return jsonify({'error': 'Recipient not found'}), 404

        # Share the note
        note.shared_users.append(recipient)
        db.session.commit()

        return jsonify({'message': 'Note shared successfully'}), 200

@notes_namespace.route('/notes/<int:note_id>/versions')
class NoteVersionsResource(Resource):
    @jwt_required()
    @notes_namespace.doc(
        description="Retrieve all versions of a note.",
        params={'note_id': 'The ID of the note'},
        responses={
            200: 'Success - Returns note versions',
            404: 'Note not found',
            401: 'Unauthorized - Invalid JWT token',
        }
    )
    def get(self, note_id):
        """Get note versions"""
        user_id = get_jwt_identity()
        note = Note.query.filter_by(id=note_id, user_id=user_id).first()

        if not note:
            return jsonify({'error': 'Note not found'}), 404

        versions = [{'content': version.content, 'timestamp': version.timestamp}
                    for version in note.versions]
        return jsonify({'versions': versions}), 200

@notes_namespace.route('/notes/<int:note_id>/tags')
class NoteTagsResource(Resource):
    @jwt_required()
    @notes_namespace.expect(
        notes_namespace.model('Tags', {
            'tags': fields.List(fields.String, required=True, description='List of tags')
        })
    )
    @notes_namespace.doc(
        description="Add tags to a note.",
        params={'note_id': 'The ID of the note'},
        responses={
            200: 'Tags added successfully',
            404: 'Note not found',
            401: 'Unauthorized - Invalid JWT token',
        }
    )
    def post(self, note_id):
        """Add tags to a note"""
        data = request.json
        tags = data.get('tags')

        user_id = get_jwt_identity()
        note = Note.query.filter_by(id=note_id, user_id=user_id).first()

        if not note:
            return jsonify({'error': 'Note not found'}), 404

        for tag_name in tags:
            tag = Tag.query.filter_by(name=tag_name).first()
            if not tag:
                tag = Tag(name=tag_name)
                db.session.add(tag)
            if tag not in note.tags:
                note.tags.append(tag)

        db.session.commit()
        return jsonify({'message': 'Tags added successfully'}), 200

@notes_namespace.route('/notes/statistics')
class NoteStatisticsResource(Resource):
    @jwt_required()
    @notes_namespace.doc(
        description="Get statistics for the current user's notes.",
        responses={
            200: 'Success - Returns statistics',
            401: 'Unauthorized - Invalid JWT token',
        }
    )
    def get(self):
        """Get note statistics"""
        user_id = get_jwt_identity()

        # Total notes created by the user
        total_notes = Note.query.filter_by(user_id=user_id).count()

        # Total shared notes
        shared_notes_count = db.session.query(shared_notes).filter(shared_notes.c.user_id == user_id).count()

        return jsonify({
            'total_notes': total_notes,
            'shared_notes': shared_notes_count
        }), 200