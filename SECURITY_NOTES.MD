- 2026-11-04: Anonymous `GET /recipes` returns **all** recipes, including `is_public: false` ones like `"Secret family hot sauce"`.
- 2026-11-04: Anonymous `PATCH /recipes/1` successfully changes the recipe title to `"Shakshuka (edited by anonymous)"`.
- 2026-11-04: Anonymous `DELETE /recipes/1` succeeds (204) and subsequent `GET /recipes/1` returns `"error": "recipe not found"`.

- 2026-11-22: Password storage:
`I connected to recipes.db with sqlite3 and ran

    SELECT id, username, email, password_hash FROM users LIMIT 5;.

For all users, the password_hash column contained long scrypt-derived hex strings (e.g. 327...:...:...), not plaintext passwords.

Conclusion: Passwords are stored as secure hashes, not plaintext.
 

- 2026-11-22: Token-required actions (update recipe):

Sent PATCH /recipes/1 without an Authorization header. Got 401 UNAUTHORIZED and error "missing or invalid authorization header".

Repeated the same request with a valid Authorization: Bearer <token> header. Got 200 OK and the recipe’s title updated to "Security Check".

Conclusion: Updating recipes requires a valid Bearer token; anonymous clients cannot modify recipes.

- 2026-11-22: Ownership and admin authorization (PATCH /recipes/1):

    With a non-owner user token, PATCH /recipes/1 returned 403 FORBIDDEN and "you do not have permission to modify this recipe".

    With the owner’s token, the same request returned 200 OK and updated the title to "Correct User test".

    With an admin token, the same request returned 200 OK and updated the title to "Admin PATCH test" even though owner_id remained 1.
    
  Conclusion: The API enforces ownership correctly (403 for cross-user) and allows both owners and admins to modify recipes.








