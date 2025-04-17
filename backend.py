from flask import Flask, request, jsonify, send_from_directory
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from pymongo import MongoClient
from bson import ObjectId

import os
import uuid

app = Flask(__name__)
CORS(app)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'fallback_secret_key')
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# MongoDB Configuration
client = MongoClient("mongodb://localhost:27017/")
db = client.travel_reviews
users_collection = db.users
reviews_collection = db.reviews
ratings_collection = db.ratings

# Configure Upload Folder
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# USER AUTHENTICATION
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    name, email, password = data.get("name"), data.get("email"), data.get("password")
    if not name or not email or not password:
        return jsonify({"error": "Missing required fields"}), 400
    if users_collection.find_one({"email": email}):
        return jsonify({"error": "Email already registered"}), 409
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    users_collection.insert_one({"name": name, "email": email, "password": hashed_password})
    return jsonify({"message": "Signup successful!"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email, password = data.get("email"), data.get("password")
    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400
    user = users_collection.find_one({"email": email})
    if user and bcrypt.check_password_hash(user["password"], password):
        access_token = create_access_token(identity=user["email"])
        return jsonify({"token": access_token, "message": "Login successful!", "name": user["name"]}), 200
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    return jsonify({"message": f"Hello, {get_jwt_identity()}"}), 200

# PHOTO UPLOADS
@app.route("/upload_photos", methods=["POST"])
def upload_photos():
    if "photos" not in request.files:
        return jsonify({"error": "No photos uploaded"}), 400
    files = request.files.getlist("photos")
    urls = []
    for file in files:
        filename = str(uuid.uuid4()) + os.path.splitext(file.filename)[1]
        path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(path)
        urls.append(f"/uploads/{filename}")
    return jsonify({"message": "Photos uploaded successfully!", "urls": urls}), 201

@app.route("/uploads/<filename>")
def get_uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# ADD REVIEW
@app.route("/add_review", methods=["POST"])
def add_review():
    data = request.json
    review = {
        "Name": data["Name"],
        "location": data["location"],
        "purpose": data["purpose"],
        "budget": data["budget"],
        "transport": data["transport"],
        "review": data["review"],
        "images": data.get("photo_urls", []),
        "rating": 0,
        "rating_count": 0,
        "comments": []
    }
    reviews_collection.insert_one(review)
    return jsonify({"message": "Review added successfully!"}), 201

# GET REVIEWS WITH FILTERS
@app.route("/get_reviews", methods=["GET"])
def get_reviews():
    query = {}
    location = request.args.get("location")
    purpose = request.args.get("purpose")
    budget = request.args.get("budget")
    transport = request.args.get("transport")
    sort = request.args.get("sort")  # 'newest' or 'rating'

    if location:
        query["location"] = location
    if purpose:
        query["purpose"] = purpose
    if budget:
        query["budget"] = budget
    if transport:
        query["transport"] = transport

    sort_order = None
    if sort == "newest":
        sort_order = ("_id", -1)  # Sort by most recent
    elif sort == "rating":
        sort_order = ("rating", -1)  # Sort by highest rated

    reviews_cursor = reviews_collection.find(query)
    if sort_order:
        reviews_cursor = reviews_cursor.sort([sort_order])

    reviews = []
    for review in reviews_cursor:
        review["_id"] = str(review["_id"])  # Convert ObjectId to string
        reviews.append(review)

    return jsonify(reviews), 200

# ADD COMMENT
@app.route("/add_comment", methods=["POST"])
@jwt_required()
def add_comment():
    data = request.json
    review_id, comment = data.get("reviewId"), data.get("comment")
    if not review_id or not comment:
        return jsonify({"error": "Review ID and comment are required."}), 400
    user_email = get_jwt_identity()
    reviews_collection.update_one({"_id": ObjectId(review_id)}, {"$push": {"comments": {"user_email": user_email, "comment": comment}}})
    return jsonify({"message": "Comment added successfully!"}), 200

# UPDATE RATING
@app.route("/update_rating", methods=["POST"])
def update_rating():
    data = request.json
    print(f"Received data: {data}")  # Log the incoming data for debugging
    
    review_id = data.get("reviewId")
    rating = data.get("rating")

    if not review_id or not rating:
        print("Missing reviewId or rating")  # Log if any field is missing
        return jsonify({"error": "Review ID and rating are required."}), 400

    if not (1 <= rating <= 5):
        print(f"Invalid rating: {rating}")  # Log if the rating is out of bounds
        return jsonify({"error": "Rating must be between 1 and 5."}), 400

    # Get the review and update the rating
    review = reviews_collection.find_one({"_id": ObjectId(review_id)})
    if not review:
        print(f"Review with ID {review_id} not found.")  # Log if review doesn't exist
        return jsonify({"error": "Review not found."}), 404

    # Calculate new rating
    total_rating = review["rating"] * review["rating_count"] + rating
    new_rating_count = review["rating_count"] + 1
    new_avg_rating = total_rating / new_rating_count

    reviews_collection.update_one(
        {"_id": ObjectId(review_id)},
        {
            "$set": {
                "rating": new_avg_rating,
                "rating_count": new_rating_count
            }
        }
    )

    return jsonify({"message": "Rating updated successfully!"}), 200

if __name__ == "__main__":
    app.run(debug=True)
