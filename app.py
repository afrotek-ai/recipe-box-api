"""Recipe Box API — BE104 course project.

A Flask + SQLite CRUD API for recipes with JWT authentication.
- /register and /login create users and issue tokens.
- Write routes (POST, PATCH, DELETE on /recipes) require a valid bearer token.
- PATCH and DELETE also require that the caller owns the recipe or is an admin.
"""

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    # Fail fast: without a secret, every protected route would crash later.
    raise RuntimeError("JWT_SECRET is not set. Add it to your .env file.")

DATABASE = "recipes.db"

# Used so a login for a missing user takes about as long as a wrong password,
# which makes it harder to guess which usernames exist.
DUMMY_HASH = generate_password_hash("not-a-real-password")

app = Flask(__name__)


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # 1) Read the Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "missing or invalid authorization header"}), 401

        token = auth_header[len("Bearer "):].strip()

        # 2) Verify the token
        try:
            payload = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=["HS256"],
                options={"require": ["exp", "sub"]},
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token has expired; please log in again"}), 401
        except jwt.PyJWTError:
            return jsonify({"error": "invalid or unverifiable token"}), 401

        # 3) Store identity for the route to use
        g.current_user = {
            "id": payload.get("sub"),
            "role": payload.get("role"),
            "raw": payload,
        }

        # 4) Continue to the original route
        return f(*args, **kwargs)

    return wrapper


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def recipe_to_dict(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "ingredients": row["ingredients"],
        "instructions": row["instructions"],
        "is_public": bool(row["is_public"]),
        "owner_id": row["owner_id"],
    }


@app.get("/")
def hello():
    return jsonify({"message": "Recipe Box API", "recipes": "/recipes"})


@app.get("/recipes")
def list_recipes():
    rows = get_db().execute("SELECT * FROM recipes ORDER BY id").fetchall()
    return jsonify([recipe_to_dict(r) for r in rows])


@app.get("/recipes/<int:recipe_id>")
def get_recipe(recipe_id):
    row = get_db().execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404
    return jsonify(recipe_to_dict(row))


@app.post("/recipes")
@require_auth
def create_recipe():
    # Identity comes from the verified JWT (set by require_auth)
    user_id = g.current_user["id"]

    data = request.get_json(silent=True)
    if (
        not isinstance(data, dict)
        or not data.get("title")
        or not data.get("ingredients")
    ):
        return jsonify({"error": "title and ingredients are required"}), 400

    instructions = data.get("instructions", "")
    if (
        not isinstance(data["title"], str)
        or not isinstance(data["ingredients"], str)
        or not isinstance(instructions, str)
        or not data["title"].strip()
        or not data["ingredients"].strip()
    ):
        return jsonify(
            {"error": "title, ingredients, and instructions must be text"}
        ), 400

    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO recipes (title, ingredients, instructions, is_public, owner_id)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                data["title"],
                data["ingredients"],
                instructions,
                1 if data.get("is_public", True) else 0,
                user_id,  # from the JWT payload
            ),
        )
        db.commit()
    except sqlite3.IntegrityError as exc:
        if "UNIQUE" in str(exc):
            return jsonify({"error": "a recipe with that title already exists"}), 409
        # Anything else (for example the token's user no longer exists)
        # is not a duplicate title, so don't report it as one.
        return jsonify({"error": "invalid or unverifiable token"}), 401
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (cur.lastrowid,)
    ).fetchone()
    return jsonify(recipe_to_dict(row)), 201


@app.patch("/recipes/<int:recipe_id>")
@require_auth
def update_recipe(recipe_id):
    db = get_db()

    # 1) Load the recipe first
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404

    # 2) Enforce ownership or admin
    user_id = g.current_user["id"]
    role = g.current_user["role"]

    is_owner = str(row["owner_id"]) == str(user_id)
    is_admin = role == "admin"

    if not (is_owner or is_admin):
        return jsonify({"error": "you do not have permission to modify this recipe"}), 403

    # 3) Update logic
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data:
        return jsonify({"error": "a JSON body is required"}), 400

    fields, values = [], []
    for column in ("title", "ingredients", "instructions"):
        if column in data:
            value = data[column]
            if not isinstance(value, str):
                return jsonify({"error": f"{column} must be text"}), 400
            # Same rule as create: title and ingredients can't be blank
            if column != "instructions" and not value.strip():
                return jsonify({"error": f"{column} cannot be empty"}), 400
            fields.append(f"{column} = ?")
            values.append(value)
    if "is_public" in data:
        fields.append("is_public = ?")
        values.append(1 if data["is_public"] else 0)
    if not fields:
        return jsonify({"error": "nothing to update"}), 400

    values.append(recipe_id)

    try:
        db.execute(
            f"UPDATE recipes SET {', '.join(fields)} WHERE id = ?", values
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409

    # Re-fetch updated row
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    return jsonify(recipe_to_dict(row))


@app.delete("/recipes/<int:recipe_id>")
@require_auth
def delete_recipe(recipe_id):
    db = get_db()

    # 1) Load the recipe first
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404

    # 2) Enforce ownership or admin
    user_id = g.current_user["id"]
    role = g.current_user["role"]

    is_owner = str(row["owner_id"]) == str(user_id)
    is_admin = role == "admin"

    if not (is_owner or is_admin):
        return jsonify({"error": "you do not have permission to delete this recipe"}), 403

    # 3) Perform the delete
    db.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
    db.commit()

    return "", 204


@app.post("/register")
def register():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be JSON"}), 400

    if not all(data.get(key) for key in ("username", "email", "password")):
        return jsonify({"error": "username, email, and password are required"}), 400

    # Reject non-text values (for example a number) before calling string methods
    if not all(isinstance(data[key], str) for key in ("username", "email", "password")):
        return jsonify({"error": "username, email, and password must be text"}), 400

    username = data["username"].strip()
    email = data["email"].strip()
    # The password is NOT stripped: login uses it exactly as typed,
    # so register has to hash it exactly as typed too.
    password = data["password"]

    if not username or not email or not password.strip():
        return jsonify({"error": "username, email, and password are required"}), 400

    password_hash = generate_password_hash(password)

    db = get_db()

    # SQLite's UNIQUE is case-sensitive, so check case-insensitively here
    # to stop "Baka" and "baka" from both registering.
    existing = db.execute(
        "SELECT 1 FROM users WHERE lower(username) = lower(?) OR lower(email) = lower(?)",
        (username, email),
    ).fetchone()
    if existing:
        return jsonify({"error": "username or email already exists"}), 409

    try:
        cursor = db.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        # UNIQUE constraint failed (duplicate username or email)
        return jsonify({"error": "username or email already exists"}), 409

    new_id = cursor.lastrowid

    return jsonify(
        {
            "id": new_id,
            "username": username,
            "email": email,
        }
    ), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    username = data.get("username")
    password = data.get("password")

    # Validate required fields
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "username and password must be text"}), 400

    # Same trimming as register for the username; the password is left as typed
    username = username.strip()

    db = get_db()
    user = db.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    if user is None:
        # Do the same amount of hashing work as a real check
        check_password_hash(DUMMY_HASH, password)
        return jsonify({"error": "Invalid username or password"}), 401

    # Same generic failure for a wrong password
    if not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid username or password"}), 401

    # Success: issue JWT with identity + expiration
    payload = {
        "sub": str(user["id"]),             # subject must be a string
        "username": user["username"],
        "role": user["role"],
        "exp": datetime.now(timezone.utc) + timedelta(hours=4),
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],  # optional but handy
        "token": token,
    }), 200

'''
if __name__ == "__main__":
    # Debug mode is off unless you turn it on: FLASK_DEBUG=1 python app.py
    app.run(debug=os.getenv("FLASK_DEBUG") == "1")
'''
if __name__ == "__main__":
    app.run(debug=True)