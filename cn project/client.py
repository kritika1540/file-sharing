# client.py
import socket
import os
import pickle
import rsa_utils

class FileClient:
    def __init__(self, server_host='localhost', server_port=9999):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.public_key, self.private_key = rsa_utils.generate_keypair()
        self.server_public_key = None
        
    def connect(self):
        """Connect to the server and perform key exchange"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.connect((self.server_host, self.server_port))
            print(f"Connected to server at {self.server_host}:{self.server_port}")
            
            # Perform key exchange
            self.key_exchange()
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def key_exchange(self):
        """Exchange public keys with server"""
        # Receive server public key
        self.server_public_key = pickle.loads(self.socket.recv(4096))
        print(f"Received server public key: {self.server_public_key}")
        
        # Send client public key
        self.socket.send(pickle.dumps(self.public_key))
        print("Sent client public key to server")
    
    def upload_file(self, filepath):
        """Upload a file to the server"""
        if not os.path.exists(filepath):
            print(f"File {filepath} not found")
            return False
        
        filename = os.path.basename(filepath)
        
        # Send upload command
        command = f"UPLOAD {filename}"
        encrypted_command = rsa_utils.encrypt(self.server_public_key, command)
        self.socket.send(pickle.dumps(encrypted_command))
        
        # Wait for acknowledgment
        encrypted_response = pickle.loads(self.socket.recv(4096))
        response = rsa_utils.decrypt(self.private_key, encrypted_response).decode()
        
        if not response.startswith("READY_FOR_UPLOAD"):
            print(f"Server not ready: {response}")
            return False
        
        # Read file
        with open(filepath, 'rb') as f:
            file_data = f.read()
        
        # Encrypt and send file
        encrypted_file = rsa_utils.encrypt(self.server_public_key, file_data)
        self.socket.send(pickle.dumps(encrypted_file))
        
        # Wait for completion response
        encrypted_completion = pickle.loads(self.socket.recv(4096))
        completion = rsa_utils.decrypt(self.private_key, encrypted_completion).decode()
        
        if completion.startswith("UPLOAD_SUCCESS"):
            print(f"Successfully uploaded {filename}")
            return True
        else:
            print(f"Upload failed: {completion}")
            return False
    
    def download_file(self, filename, save_path=None):
        """Download a file from the server"""
        if save_path is None:
            save_path = filename
        
        # Send download command
        command = f"DOWNLOAD {filename}"
        encrypted_command = rsa_utils.encrypt(self.server_public_key, command)
        self.socket.send(pickle.dumps(encrypted_command))
        
        # Receive file size or error
        encrypted_response = pickle.loads(self.socket.recv(4096))
        response = rsa_utils.decrypt(self.private_key, encrypted_response).decode()
        
        if response.startswith("FILE_NOT_FOUND"):
            print(f"File {filename} not found on server")
            return False
        
        if not response.startswith("FILE_SIZE"):
            print(f"Unexpected response: {response}")
            return False
        
        # Send ready acknowledgment
        ack = "READY_FOR_DOWNLOAD"
        encrypted_ack = rsa_utils.encrypt(self.server_public_key, ack)
        self.socket.send(pickle.dumps(encrypted_ack))
        
        # Receive encrypted file
        encrypted_file = pickle.loads(self.socket.recv(1024*1024*10))  # 10MB max
        
        # Decrypt file
        file_data = rsa_utils.decrypt(self.private_key, encrypted_file)
        
        # Save file
        with open(save_path, 'wb') as f:
            f.write(file_data)
        
        print(f"Successfully downloaded {filename} to {save_path}")
        return True
    
    def list_files(self):
        """List files available on the server"""
        # Send list command
        command = "LIST"
        encrypted_command = rsa_utils.encrypt(self.server_public_key, command)
        self.socket.send(pickle.dumps(encrypted_command))
        
        # Receive file list
        encrypted_list = pickle.loads(self.socket.recv(4096))
        file_list = rsa_utils.decrypt(self.private_key, encrypted_list).decode()
        
        print("Files available on server:")
        print(file_list)
        return file_list
    
    def close(self):
        """Close the connection to the server"""
        if self.socket:
            try:
                # Send exit command
                command = "EXIT"
                encrypted_command = rsa_utils.encrypt(self.server_public_key, command)
                self.socket.send(pickle.dumps(encrypted_command))
            except:
                pass
            finally:
                self.socket.close()
                print("Connection closed")

def main():
    client = FileClient()
    if not client.connect():
        return
    
    try:
        while True:
            print("\nOptions:")
            print("1. Upload file")
            print("2. Download file")
            print("3. List files")
            print("4. Exit")
            choice = input("Enter choice (1-4): ")
            
            if choice == '1':
                filepath = input("Enter file path to upload: ")
                client.upload_file(filepath)
            elif choice == '2':
                filename = input("Enter filename to download: ")
                save_path = input("Enter save path (or press enter to use original filename): ")
                if not save_path:
                    save_path = filename
                client.download_file(filename, save_path)
            elif choice == '3':
                client.list_files()
            elif choice == '4':
                break
            else:
                print("Invalid choice")
    finally:
        client.close()

if __name__ == "__main__":
    main()