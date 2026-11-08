from werkzeug.security import generate_password_hash, check_password_hash

sample_password = "MaestroDemo123!"  # fake password just for testing

hash_value = generate_password_hash(sample_password)
print("HASH:", hash_value)

print("correct?", check_password_hash(hash_value, sample_password))
print("wrong?", check_password_hash(hash_value, "wrong-password"))
