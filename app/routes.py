from cryptography.fernet import Fernet
from flask import request, jsonify, Response
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token
from flask_restx import Namespace, Resource, fields
from werkzeug.security import generate_password_hash, check_password_hash

from app import limiter, db
from app.auth_service import verify_webauthn_credential, extract_user_from_credential
from app.device_service import mock_device_list, remove_device
from app.email_service import send_email
from app.models import User, Note, Tag
from app.utils import generate_totp_secret, generate_reset_token, generate_webauthn_challenge, convert_to_csv

# Create separate namespaces for HTTP methods
post_namespace = Namespace("POST", description="All POST operations")
get_namespace = Namespace("GET", description="All GET operations")
put_namespace = Namespace("PUT", description="All PUT operations")
delete_namespace = Namespace("DELETE", description="All DELETE operations")
auth_namespace = Namespace("AUTH", description="All Auth operations")
# Encryption setup
key = Fernet.generate_key()
cipher = Fernet(key)

# POST Models
note_model_post = post_namespace.model('Note', {
    'title': fields.String(required=True, description='The title of the note'),
    'content': fields.String(required=True, description='The content of the note')
})
user_model_post = post_namespace.model('User', {
    'username': fields.String(required=True, description='The username of the user'),
    'password': fields.String(required=True, description='The password of the user')
})

tag_model_post = post_namespace.model('Tags', {
    'tags': fields.List(fields.String, required=True, description='List of tags')
})

# GET Models
note_model_get = get_namespace.model('Note', {
    'id': fields.Integer(description='The ID of the note'),
    'title': fields.String(description='The title of the note'),
    'content': fields.String(description='The content of the note')
})

# POST Endpoints
@post_namespace.route('/register')
class RegisterResource(Resource):
    @limiter.limit("5/minute")
    @post_namespace.expect(user_model_post, validate=True)
    @post_namespace.doc(
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
            return {"error": "User already exists"}, 400

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return {"message": "User registered successfully"}, 201


@post_namespace.route('/login')
class LoginResource(Resource):
    @limiter.limit("5/minute")
    @post_namespace.expect(user_model_post, validate=True)
    @post_namespace.doc(
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


@post_namespace.route('/notes')
class CreateNoteResource(Resource):
    @jwt_required()
    @post_namespace.expect(note_model_post, validate=True)
    @post_namespace.doc(
        description="Create a new note for the current user.",
        responses={
            201: "Note created successfully",
            400: "Invalid input",
            401: "Unauthorized - Missing or invalid JWT token",
        }
    )
    def post(self):
        """Create a new note"""
        data = request.json
        title = data.get("title")
        content = data.get("content")

        user_id = get_jwt_identity()
        encrypted_content = cipher.encrypt(content.encode()).decode()

        new_note = Note(user_id=user_id, title=title, content_encrypted=encrypted_content)
        db.session.add(new_note)
        db.session.commit()

        return jsonify({"message": "Note created successfully"}), 201

@post_namespace.route('/notes/<int:note_id>/share')
class ShareNoteResource(Resource):
    @jwt_required()
    @post_namespace.expect(post_namespace.model('Share', {
        'recipient_username': fields.String(required=True, description='Username of the recipient')
    }))
    @post_namespace.doc(
        description="Share a note with another user.",
        responses={
            200: 'Note shared successfully',
            404: 'Note or recipient not found',
            401: 'Unauthorized - Invalid JWT token'
        }
    )
    def post(self, note_id):
        """Share a note with another user"""
        data = request.json
        recipient_username = data.get('recipient_username')

        user_id = get_jwt_identity()
        note = Note.query.filter_by(id=note_id, user_id=user_id).first()
        if not note:
            return jsonify({'error': 'Note not found'}), 404

        recipient = User.query.filter_by(username=recipient_username).first()
        if not recipient:
            return jsonify({'error': 'Recipient not found'}), 404

        note.shared_users.append(recipient)
        db.session.commit()
        return jsonify({'message': 'Note shared successfully'}), 200

@post_namespace.route('/refresh')
class RefreshTokenResource(Resource):
    @jwt_required(refresh=True)
    @post_namespace.doc(
        description="Get a new access token using a refresh token.",
        responses={
            200: 'Access token refreshed successfully',
            401: 'Unauthorized - Invalid or missing refresh token'
        }
    )
    def post(self):
        """Refresh access token"""
        identity = get_jwt_identity()
        new_access_token = create_access_token(identity=identity)
        return jsonify({'access_token': new_access_token}), 200

@post_namespace.route('/notes/<int:note_id>/tags')
class AddTagsToNoteResource(Resource):
    @jwt_required()
    @post_namespace.expect(tag_model_post, validate=True)
    @post_namespace.doc(
        description="Add tags to a specific note.",
        responses={
            200: "Tags added successfully",
            404: "Note not found",
            401: "Unauthorized - Invalid JWT token"
        }
    )
    def post(self, note_id):
        """Add tags to a note"""
        data = request.json
        tags = data.get('tags')
        user_id = get_jwt_identity()

        note = Note.query.filter_by(id=note_id, user_id=user_id).first()
        if not note:
            return {"error": "Note not found"}, 404

        for tag_name in tags:
            tag = Tag.query.filter_by(name=tag_name).first()
            if not tag:
                tag = Tag(name=tag_name)
                db.session.add(tag)
            note.tags.append(tag)

        db.session.commit()
        return {"message": "Tags added successfully"}, 200

@post_namespace.route('/enable-mfa')
class EnableMFAResource(Resource):
    @jwt_required()
    @post_namespace.doc(
        description="Enable Multi-Factor Authentication for the current user.",
        responses={
            200: "MFA enabled successfully",
            401: "Unauthorized - Invalid JWT token",
            400: "MFA setup failed"
        }
    )
    def post(self):
        """Enable MFA for the user"""
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        # Generate a secret key for MFA (e.g., TOTP)
        secret = generate_totp_secret()
        user.mfa_secret = secret
        db.session.commit()

        return jsonify({
            "message": "MFA enabled successfully",
            "secret": secret  # Show QR code for TOTP apps like Google Authenticator
        }), 200

@post_namespace.route('/password-reset/request')
class PasswordResetRequestResource(Resource):
    @post_namespace.expect(post_namespace.model('ResetRequest', {
        'email': fields.String(required=True, description='The user email')
    }))
    @post_namespace.doc(
        description="Request a password reset via email.",
        responses={
            200: "Password reset request sent successfully",
            404: "User not found"
        }
    )
    def post(self):
        """Request a password reset"""
        data = request.json
        email = data.get('email')

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Generate a password reset token (implement token logic)
        reset_token = generate_reset_token(user.id)
        send_email(email, "Password Reset", f"Your reset token: {reset_token}")

        return jsonify({'message': 'Password reset request sent successfully'}), 200

@post_namespace.route('/webauthn/register')
class WebAuthnRegisterResource(Resource):
    @jwt_required()
    @post_namespace.doc(
        description="Register a WebAuthn credential for biometric login.",
        responses={
            200: "WebAuthn registration successful",
            400: "Registration failed"
        }
    )
    def post(self):
        """Register WebAuthn credential"""
        user_id = get_jwt_identity()

        # Generate WebAuthn challenge (implement logic)
        challenge = generate_webauthn_challenge()
        return jsonify({
            "challenge": challenge,
            "user_id": user_id
        }), 200

@post_namespace.route('/webauthn/verify')
class WebAuthnVerifyResource(Resource):
    @post_namespace.doc(
        description="Verify a WebAuthn credential for biometric login.",
        responses={
            200: "WebAuthn verified successfully",
            401: "Invalid or missing credential"
        }
    )
    def post(self):
        """Verify WebAuthn credential"""
        data = request.json
        credential = data.get('credential')

        # Verify the credential (implement logic)
        if verify_webauthn_credential(credential):
            token = create_access_token(identity=extract_user_from_credential(credential))
            return jsonify({'access_token': token}), 200
        else:
            return jsonify({'error': 'Invalid credential'}), 401

# GET Endpoints
@get_namespace.route('/notes')
class GetNotesResource(Resource):
    @jwt_required()
    @get_namespace.doc(
        description="Retrieve all notes for the current user.",
        responses={
            200: "Success - Returns a list of notes",
            401: "Unauthorized - Missing or invalid JWT token",
        }
    )
    def get(self):
        """Get all notes"""
        user_id = get_jwt_identity()  # Ensure this is used in the query
        notes = Note.query.filter_by(user_id=user_id).all()

        result = [
            {
                'id': note.id,
                'title': note.title,
                'content': cipher.decrypt(note.content_encrypted.encode()).decode()
            }
            for note in notes
        ]
        return jsonify({'notes': result}), 200

@get_namespace.route('/notes/search')
class SearchNotesResource(Resource):
    @jwt_required()
    @get_namespace.doc(params={'q': 'Query string to search notes'})
    def get(self):
        """Search notes by title"""
        user_id = get_jwt_identity()
        query = request.args.get('q', '')

        notes = Note.query.filter(
            Note.user_id == user_id,
            Note.title.ilike(f'%{query}%')
        ).all()

        result = [
            {
                'id': note.id,
                'title': note.title,
                'content': cipher.decrypt(note.content_encrypted.encode()).decode()
            }
            for note in notes
        ]
        return {"results": result}, 200

@get_namespace.route('/notes/statistics')
class NoteStatisticsResource(Resource):
    @jwt_required()
    @get_namespace.doc(
        description="Get statistics for the current user's notes.",
        responses={
            200: 'Success - Returns statistics',
            401: 'Unauthorized - Invalid JWT token',
        }
    )
    def get(self):
        """Get note statistics"""
        user_id = get_jwt_identity()
        total_notes = Note.query.filter_by(user_id=user_id).count()
        return jsonify({'total_notes': total_notes}), 200

@get_namespace.route('/devices')
class DeviceManagementResource(Resource):
    @jwt_required()
    @get_namespace.doc(
        description="View all devices currently logged into the user's account.",
        responses={
            200: "Returns a list of devices",
            401: "Unauthorized - Invalid JWT token"
        }
    )
    def get(self):
        """List logged-in devices"""
        user_id = get_jwt_identity()

        # Mock device list (Replace with a real DB query)
        devices = [
            {"device": "iPhone 14", "ip": "192.168.1.10", "last_used": "2025-01-25"},
            {"device": "MacBook Pro", "ip": "192.168.1.11", "last_used": "2025-01-24"}
        ]

        return jsonify({'devices': devices}), 200

@get_namespace.route('/activity-log')
class ActivityLogResource(Resource):
    @jwt_required()
    @get_namespace.doc(
        description="Get the activity log for the current user.",
        responses={
            200: "Returns the activity log",
            401: "Unauthorized - Invalid JWT token"
        }
    )
    def get(self):
        """Get user activity log"""
        user_id = get_jwt_identity()

        # Mock log data (Replace with real DB query)
        activity_log = [
            {"action": "Login", "timestamp": "2025-01-25 14:32:10"},
            {"action": "Created Note", "timestamp": "2025-01-24 10:21:45"},
            {"action": "Shared Note", "timestamp": "2025-01-23 18:15:30"}
        ]

        return jsonify({'activity_log': activity_log}), 200

@get_namespace.route('/notes/export')
class ExportNotesResource(Resource):
    @jwt_required()
    @get_namespace.doc(
        description="Export all notes of the current user as JSON or CSV.",
        params={'file_format': 'Export format (json or csv)'},
        responses={
            200: "Export successful",
            401: "Unauthorized - Invalid JWT token"
        }
    )
    def get(self):
        """Export notes"""
        user_id = get_jwt_identity()
        file_format = request.args.get('file_format', 'json')

        notes = Note.query.filter_by(user_id=user_id).all()
        result = [
            {"id": note.id, "title": note.title, "content": cipher.decrypt(note.content_encrypted.encode()).decode()}
            for note in notes
        ]

        if file_format == 'csv':
            csv_data = convert_to_csv(result)
            return Response(csv_data, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=notes.csv"})
        return jsonify(result), 200

# PUT Endpoints
@put_namespace.route('/notes/<int:note_id>')
class UpdateNoteResource(Resource):
    @jwt_required()
    @put_namespace.doc(
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


# DELETE Endpoints
@delete_namespace.route('/notes/<int:note_id>')
class DeleteNoteResource(Resource):
    @jwt_required()
    @delete_namespace.doc(
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

@delete_namespace.route('/devices/<string:device_id>')
class RemoveDeviceResource(Resource):
    @jwt_required()
    @delete_namespace.doc(
        description="Remove a device from the list of logged-in devices.",
        responses={
            200: "Device removed successfully",
            404: "Device not found",
            401: "Unauthorized - Invalid JWT token"
        }
    )
    def delete(self, device_id):
        """Remove a logged-in device"""
        user_id = get_jwt_identity()

        # Mocked logic to validate device_id
        devices = mock_device_list(user_id)
        if device_id not in devices:
            return jsonify({'error': 'Device not found'}), 404

        remove_device(device_id)  # Implement actual device removal logic
        return jsonify({'message': 'Device removed successfully'}), 200

@auth_namespace.route('/webauthn/challenge')
class WebAuthnChallengeResource(Resource):
    @staticmethod
    def get():
        """Generate a WebAuthn challenge"""
        challenge = generate_webauthn_challenge()
        return {"challenge": challenge}, 200

@auth_namespace.route('/webauthn/verify')
class WebAuthnVerifyResource(Resource):
    @staticmethod
    def post():
        """Verify a WebAuthn credential"""
        data = request.json

        # Get necessary parameters
        credential = data.get('credential')
        challenge = data.get('challenge')
        rp_id = data.get('rp_id', "example.com")  # Default to your domain if not provided
        user_verification = data.get('user_verification', "required")  # Default if not provided

        # Validate inputs
        if not credential or not challenge:
            return {"error": "Missing required parameters (credential or challenge)."}, 400

        # Call the verification function
        result = verify_webauthn_credential(
            credential=credential,
            challenge=challenge,
            rp_id=rp_id,
            user_verification=user_verification,
        )

        # Return success or failure
        if result.get("verified"):
            token = create_access_token(identity=extract_user_from_credential(credential))
            return jsonify({'access_token': token}), 200
        else:
            return jsonify({'error': 'Invalid credential'}), 400