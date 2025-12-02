from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import bcrypt
import os

app = Flask(__name__)
CORS(app)

# --------------------------
# MongoDB Atlas Connection
# --------------------------

# Get connection string from environment variable (Vercel)
MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    raise Exception("❌ MONGO_URI is missing. Add it in Vercel Environment Variables.")

client = MongoClient(MONGO_URI)

# Your database and collection
db = client["loginDB"]
adminUsers = db["adminUsers"]   # ← imong collection name

# --------------------------
# Register Route
# --------------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    fullname = data.get("fullname")
    email = data.get("email")
    password = data.get("password")

    if not fullname or not email or not password:
        return jsonify({"status": "error", "message": "All fields are required"}), 400

    # Check if email already exists
    if adminUsers.find_one({"email": email}):
        return jsonify({"status": "error", "message": "Email already registered"}), 400

    # Hash password
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    # Insert user
    adminUsers.insert_one({
        "fullname": fullname,
        "email": email,
        "password": hashed
    })

    return jsonify({"status": "success", "message": "Registered successfully"}), 201

# --------------------------
# Login Route
# --------------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = adminUsers.find_one({"email": email})

    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    if not bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        return jsonify({"status": "error", "message": "Incorrect password"}), 400

    return jsonify({
        "status": "success",
        "message": "Login successful",
        "fullname": user["fullname"]
    }), 200

# --------------------------
# Run Server
# --------------------------
if __name__ == "__main__":
    app.run(debug=True)
