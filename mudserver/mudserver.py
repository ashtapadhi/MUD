import http.server

# Define the port and directory to serve
PORT = 8080  # Use 8080 or another port commonly used for HTTP
DIRECTORY = "."

class MUDRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve the MUD file or any other static file
        if self.path == "/mudfile.json":
            self.path = "mudfile.json"
        return super().do_GET()

def run(server_class=http.server.HTTPServer, handler_class=MUDRequestHandler):
    server_address = ('', PORT)
    httpd = server_class(server_address, handler_class)

    print(f"Starting HTTP server on port {PORT}...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
