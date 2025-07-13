# server.py
import socket
import os
import pickle
import rsa_utils

class FileServer:
    def __init__(self, host='localhost', port=9999):  # creating instance
        self.host = host   # initiallizig instance
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)       #socket.AF_INET -> Address Family - IPv4
                                                                              #socket.SOCK_STREAM -> TCP 
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)     
        self.public_key, self.private_key = rsa_utils.generate_keypair()
        
    def start(self):
        """Start the server and listen for connections"""
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)  # Listen for only one connection
        print(f"Server started on {self.host}:{self.port}")
        print(f"Server public key: {self.public_key}")
        
        try:
            # Accept a single client connection
            client_socket, address = self.socket.accept()
            print(f"Connection from {address}")
            self.handle_client(client_socket)
        except KeyboardInterrupt:
            print("Server shutting down...")
        finally:
            self.socket.close()
    
    def handle_client(self, client_socket):
        """Handle client connection"""
        try:
            # Exchange keys
            client_public_key = self.key_exchange(client_socket)
            
            while True:
                # Receive command
                encrypted_command = pickle.loads(client_socket.recv(4096))
                if not encrypted_command:
                    break
                
                # Decrypt command
                command_bytes = rsa_utils.decrypt(self.private_key, encrypted_command)
                command = command_bytes.decode()
                
                if command.startswith("UPLOAD"):
                    self.handle_upload(client_socket, client_public_key, command)
                elif command.startswith("DOWNLOAD"):
                    self.handle_download(client_socket, client_public_key, command)
                elif command == "LIST":
                    self.handle_list(client_socket, client_public_key)
                elif command == "EXIT":
                    break
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            print(f"Connection closed")
            client_socket.close()
            
    def key_exchange(self, client_socket):
        """Exchange public keys with client"""
        # Send server public key
        client_socket.send(pickle.dumps(self.public_key))
        
        # Receive client public key
        client_public_key = pickle.loads(client_socket.recv(4096))
        print(f"Key exchange completed")
        return client_public_key
        
    def handle_upload(self, client_socket, client_public_key, command):
        """Handle file upload from client"""
        _, filename = command.split(" ", 1)
        
        # Send acknowledgment
        ack = f"READY_FOR_UPLOAD {filename}"
        encrypted_ack = rsa_utils.encrypt(client_public_key, ack)
        client_socket.send(pickle.dumps(encrypted_ack))
        
        # Receive encrypted file content
        encrypted_file_data = pickle.loads(client_socket.recv(1024*1024*10))  # 10MB max
        
        # Decrypt file
        file_data = rsa_utils.decrypt(self.private_key, encrypted_file_data)
        
        # Save file
        upload_dir = "uploads"
        os.makedirs(upload_dir, exist_ok=True)
        filepath = os.path.join(upload_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(file_data)
        
        # Send response
        response = f"UPLOAD_SUCCESS {filename}"
        encrypted_response = rsa_utils.encrypt(client_public_key, response)
        client_socket.send(pickle.dumps(encrypted_response))
        
    def handle_download(self, client_socket, client_public_key, command):
        """Handle file download request from client"""
        _, filename = command.split(" ", 1)
        
        upload_dir = "uploads"
        filepath = os.path.join(upload_dir, filename)
        
        if not os.path.exists(filepath):
            response = f"FILE_NOT_FOUND {filename}"
            encrypted_response = rsa_utils.encrypt(client_public_key, response)
            client_socket.send(pickle.dumps(encrypted_response))
            return
        
        # Read file
        with open(filepath, 'rb') as f:
            file_data = f.read()
        
        # Send file size first
        size_message = f"FILE_SIZE {len(file_data)}"
        encrypted_size = rsa_utils.encrypt(client_public_key, size_message)
        client_socket.send(pickle.dumps(encrypted_size))
        
        # Wait for acknowledgment
        encrypted_ack = pickle.loads(client_socket.recv(4096))
        ack = rsa_utils.decrypt(self.private_key, encrypted_ack).decode()
        
        if ack != "READY_FOR_DOWNLOAD":
            return
        
        # Encrypt and send file
        encrypted_file = rsa_utils.encrypt(client_public_key, file_data)
        client_socket.send(pickle.dumps(encrypted_file))
        
    def handle_list(self, client_socket, client_public_key):
        """Handle file listing request"""
        upload_disr = "uploads"
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
        
        # Get list of files
        files = os.listdir(upload_dir)
        file_list = "\n".join(files) if files else "No files available"
        
        # Encrypt and send the list
        encrypted_list = rsa_utils.encrypt(client_public_key, file_list)
        client_socket.send(pickle.dumps(encrypted_list))

if __name__ == "__main__":
    server = FileServer()
    server.start()