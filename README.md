SecureNoteVault
A Secure Notes Management Application with Swift and Python

Description
SecureNoteVault is a full-stack application designed to provide secure and efficient note management. The backend, built with Python (Flask), handles user authentication, encrypted note storage, and CRUD operations. The frontend, a SwiftUI application, offers a seamless user experience with features for registration, login, and managing notes.
The app ensures high-level security by encrypting all sensitive data on the server and securing client-server communication over HTTPS. It is ideal for users who value privacy and security when managing personal or professional notes.

Features
	1.	User Authentication:
	•	Secure registration and login.
	•	Passwords hashed using bcrypt.
	•	Token-based authentication with JWT.
	2.	Notes Management:
	•	Create, read, update, and delete notes.
	•	Notes are encrypted server-side for added security.
	3.	Secure Communication:
	•	Encrypted client-server communication using HTTPS.
	•	Input validation and rate limiting to protect against attacks.
	4.	Cross-Platform Compatibility:
	•	Backend developed in Python with Flask, compatible with multiple client platforms.
	•	Frontend built with SwiftUI for iOS, featuring a modern, user-friendly design.

Technologies Used

Backend (Python/Flask):
	•	Flask for API design.
	•	Flask-JWT-Extended for authentication.
	•	SQLAlchemy for database modeling and interaction.
	•	bcrypt for password hashing.
	•	cryptography for note encryption.
	•	Flask-Limiter for rate limiting.

Frontend (Swift/SwiftUI):
	•	SwiftUI for a responsive and interactive user interface.
	•	URLSession for networking and API communication.
	•	Keychain for secure JWT token storage.
	•	Codable for JSON parsing.

Installation Instructions

Backend Setup:
	1.	Clone the repository:

git clone https://github.com/your-repo-name/SecureNoteVault.git
cd SecureNoteVault/backend

	2.	Create a virtual environment and install dependencies:

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

	3.	Configure environment variables for Flask and JWT secrets.
	4.	Run the Flask server:

flask run

Frontend Setup:
	1.	Open the SecureNoteVault.xcodeproj file in Xcode.
	2.	Update the API endpoint URL in the project configuration file.
	3.	Build and run the app on a simulator or device.

Usage
	1.	Launch the backend server.
	2.	Open the Swift app and register a new account.
	3.	Log in and manage your notes securely:
	•	Add new notes.
	•	View, update, or delete existing notes.
	•	All notes are encrypted server-side.

Security Features
	•	All sensitive data (e.g., passwords, notes) is encrypted before storage.
	•	JWTs are used to authenticate API requests.
	•	HTTPS ensures secure communication.
	•	Input validation and rate limiting protect against attacks.

Future Improvements
	1.	Multi-Platform Support: Expand frontend to Android or web clients.
	2.	Multi-Factor Authentication: Add an additional layer of login security.
	3.	Advanced Encryption: Allow user-specific encryption keys for notes.
	4.	Sharing Notes: Enable secure sharing of notes between users.

License

This project is licensed under the MIT License.