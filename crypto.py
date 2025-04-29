def xor_encrypt_decrypt(data, key):

    if not data or not key:
        return b""
        
    key_len = len(key)
    encrypted = bytearray(len(data))
    
    for i in range(len(data)):
        encrypted[i] = data[i] ^ key[i % key_len]
    
    return bytes(encrypted)


def encrypt_file(file_path, key, chunk_size=1024):

    encrypted_chunks = []
    
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            encrypted_chunk = xor_encrypt_decrypt(chunk, key)
            encrypted_chunks.append(encrypted_chunk)
    
    return encrypted_chunks


def decrypt_chunks(encrypted_chunks, key):

    decrypted_data = bytearray()
    
    for chunk in encrypted_chunks:
        decrypted_chunk = xor_encrypt_decrypt(chunk, key)
        decrypted_data.extend(decrypted_chunk)
    
    return bytes(decrypted_data)


def save_to_file(data, file_path):

    with open(file_path, 'wb') as f:
        f.write(data)