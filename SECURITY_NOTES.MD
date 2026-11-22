- 2026-11-04: Anonymous `GET /recipes` returns **all** recipes, including `is_public: false` ones like `"Secret family hot sauce"`.
- 2026-11-04: Anonymous `PATCH /recipes/1` successfully changes the recipe title to `"Shakshuka (edited by anonymous)"`.
- 2026-11-04: Anonymous `DELETE /recipes/1` succeeds (204) and subsequent `GET /recipes/1` returns `"error": "recipe not found"`.

- 2026-11-22: Password storage:
`I connected to recipes.db with sqlite3 and ran

    SELECT id, username, email, password_hash FROM users LIMIT 5;.

For all users, the password_hash column contained long scrypt-derived hex strings (e.g. 327...:...:...), not plaintext passwords.

Conclusion: Passwords are stored as secure hashes, not plaintext.
 


 