from flask import Flask, request, jsonify, send_from_directory
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from pymongo import MongoClient
import os
import uuid

app = Flask(__name__)
CORS(app)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'fallback_secret_key')   # Change to a strong secret key
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# MongoDB Configuration
client = MongoClient("mongodb://localhost:27017/")
db = client.travel_reviews
users_collection = db.users
reviews_collection = db.reviews

# Configure Upload Folder
UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

### ---- USER AUTHENTICATION ---- ###

# User Signup
@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.json  # Ensure frontend is sending JSON
        name = data.get("name")
        email = data.get("email")
        password = data.get("password")

        if not name or not email or not password:
            return jsonify({"error": "Missing required fields"}), 400

        # Check if email already exists
        if users_collection.find_one({"email": email}):
            return jsonify({"error": "Email already registered"}), 409

        # Hash password before storing
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = {"name": name, "email": email, "password": hashed_password}
        users_collection.insert_one(new_user)

        return jsonify({"message": "Signup successful!"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500  # Proper indentation here

# User Login
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Missing email or password"}), 400

        user = users_collection.find_one({"email": email})

        if user and bcrypt.check_password_hash(user["password"], password):
            access_token = create_access_token(identity=user["email"])
            return jsonify({"token": access_token, "message": "Login successful!"}), 200
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Protected Route Example
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Hello, {current_user}"}), 200

### ---- PHOTO UPLOADS ---- ###

reviews = []

@app.route("/upload_photos", methods=["POST"])
def upload_photos():
    try:
        if "photos" not in request.files:
            return jsonify({"error": "No photos uploaded"}), 400

        files = request.files.getlist("photos")
        file_urls = []

        for file in files:
            filename = str(uuid.uuid4()) + os.path.splitext(file.filename)[1]  # Unique filename
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)
            file_urls.append(f"/uploads/{filename}")  # Store relative path

        return jsonify({"message": "Photos uploaded successfully!", "urls": file_urls}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/uploads/<filename>")
def get_uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

@app.route("/add_review", methods=["POST"])
def add_review():
    try:
        data = request.json
        new_review = {
            "Name": data["Name"],
            "location": data["location"],
            "purpose": data["purpose"],
            "budget": data["budget"],
            "transport": data["transport"],
            "review": data["review"],
            "images": data.get("photo_urls", [])
        }
        reviews.append(new_review)
        return jsonify({"message": "Review added successfully!"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/get_reviews", methods=["GET"])
def get_reviews():
    return jsonify(reviews)

if __name__ == "__main__":
    app.run(debug=True)