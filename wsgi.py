from server import app
from flask_socketio import SocketIO

socketio = SocketIO(app)

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=8000)
