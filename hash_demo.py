from werkzeug.security import generate_password_hash, check_password_hash

sample_password = "MaestroDemo123!"

hash1 = generate_password_hash(sample_password)
hash2 = generate_password_hash(sample_password)

print("HASH 1:", hash1)
print("HASH 2:", hash2)
print("same string?", hash1 == hash2)

print("check1 with password:", check_password_hash(hash1, sample_password))
print("check2 with password:", check_password_hash(hash2, sample_password))
