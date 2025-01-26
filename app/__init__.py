from flask import Flask, jsonify
from flask_restx import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

# Initialize extensions
db = SQLAlchemy()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address)

# Define grouping tags
tags = [
    {'name': 'POST', 'description': 'All POST operations'},
    {'name': 'PUT', 'description': 'All PUT operations'},
    {'name': 'GET', 'description': 'All GET operations'},
    {'name': 'DELETE', 'description': 'All DELETE operations'},
]

# Configuration classes
class Config:
    """Base configuration class."""
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'your-secret-key'  # Replace with an environment variable in production

class DevelopmentConfig(Config):
    """Development configuration."""
    SQLALCHEMY_DATABASE_URI = 'sqlite:///notes.db'
    DEBUG = True

class ProductionConfig(Config):
    """Production configuration."""
    SQLALCHEMY_DATABASE_URI = 'sqlite:///notes.db'  # Replace with a production database URI
    DEBUG = False

def create_app(config_class=DevelopmentConfig):
    """Factory function to create and configure the Flask app."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)
    CORS(app)

    # Register namespaces
    from app.routes import post_namespace,get_namespace,put_namespace,delete_namespace
    api = Api(app, version="1.0", title="SecureNoteVault API", description="API documentation for SecureNoteVault", tags=tags)
    api.add_namespace(post_namespace, path='/api/v1/notes/post')
    api.add_namespace(get_namespace, path='/api/v1/notes/get')
    api.add_namespace(put_namespace, path='/api/v1/notes/put')
    api.add_namespace(delete_namespace, path='/api/v1/notes/delete')

    # Register error handlers
    register_error_handlers(app)

    # Create database tables (useful for dev only, prefer migrations for prod)
    with app.app_context():
        db.create_all()

    return app

def register_error_handlers(app):
    """Register global error handlers for the application."""
    @app.errorhandler(404)
    def not_found_error(error):
        return jsonify({'error': 'Resource not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'An internal error occurred. Please try again later.'}), 500

# Create the Flask app instance
flask_app = create_app()