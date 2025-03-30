from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import uuid

app = Flask(__name__)
CORS(app)

# Configure upload folder
UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# In-memory storage for reviews (Use MongoDB in production)
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
