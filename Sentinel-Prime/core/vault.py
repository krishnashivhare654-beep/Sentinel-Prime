import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

# Configuration
SALT_SIZE = 16
KEY_LEN = 32 # 256-bit
BLOCK_SIZE = 16

def generate_key(password, salt):
    # Password se 256-bit key banata hai
    return scrypt(password.encode(), salt, KEY_LEN, N=2**14, r=8, p=1)

def encrypt_file(file_path, password):
    try:
        salt = get_random_bytes(SALT_SIZE)
        key = generate_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM)
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        # Locked file ka extension .sentinel hoga
        with open(file_path + ".sentinel", 'wb') as f:
            [ f.write(x) for x in (salt, cipher.nonce, tag, ciphertext) ]
            
        # Original file delete kar dete hain security ke liye
        os.remove(file_path)
        return True, "File Encrypted Successfully"
    except Exception as e:
        return False, str(e)

def decrypt_file(encrypted_file_path, password):
    try:
        with open(encrypted_file_path, 'rb') as f:
            salt = f.read(SALT_SIZE)
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()
            
        key = generate_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        data = cipher.decrypt_and_verify(ciphertext, tag)
        
        # Wapis original file name (remove .sentinel)
        original_path = encrypted_file_path.replace(".sentinel", "")
        with open(original_path, 'wb') as f:
            f.write(data)
            
        os.remove(encrypted_file_path)
        return True, "File Decrypted Successfully"
    except Exception as e:
        return False, "Invalid Password or Corrupt File"

if __name__ == "__main__":
    # Quick Test
    # test_file = "test.txt"
    # with open(test_file, "w") as f: f.write("Top Secret Data")
    # encrypt_file(test_file, "krishna123")
    # print("Locked!")
    pass