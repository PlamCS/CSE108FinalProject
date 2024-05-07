from flask import Flask, request, redirect, url_for, render_template, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_admin import Admin, BaseView, expose, AdminIndexView
from flask_admin.menu import MenuLink
from flask_admin.contrib.sqla import ModelView
from flask_admin.form import Select2TagsField
from flask_socketio import SocketIO, emit, send, join_room, leave_room
from string import ascii_uppercase
from datetime import datetime
import bcrypt
import secrets
import random
import csv
import os

app = Flask(__name__)
socketio = SocketIO(app)
socketio.init_app(app, cors_allowed_origins="*", logger=True, engineio_logger=True)
CORS(app, supports_credentials=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
secret_key = secrets.token_hex(32)
app.config['SECRET_KEY'] = secret_key
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    @property
    def is_active(self):
        return True
    @property
    def is_authenticated(self):
        return True
    def get_id(self):
        return str(self.id)

class Drawing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(4), unique=True, nullable=False)
    members = db.Column(db.Integer, default=0)
    messages = db.relationship('Message', backref='room', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    sender = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

admin = Admin(app, name='Chat and Draw Admin', template_mode='bootstrap3')
admin._menu = admin._menu[1:]
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Drawing, db.session))
admin.add_view(ModelView(Room, db.session))
admin.add_view(ModelView(Message, db.session))

with app.app_context():
    db.create_all()

def generate_unique_code(length):
    while True:
        code = "".join(random.choices(ascii_uppercase, k=length))
        if not Room.query.filter_by(code=code).first():
            return code


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
        
@app.route('/upload_canvas_url', methods=['POST'])
def upload_canvas_url():
    if 'username' not in session:
        return jsonify({'error': 'User not logged in'}), 401

    data = request.get_json()
    data_url = data.get('data_url')

    if not data_url:
        return jsonify({'error': 'Missing data URL'}), 400

    # Find the user in the database
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Add the new drawing entry with the data URL
    new_drawing = Drawing(user_id=user.id, data_url=data_url)
    db.session.add(new_drawing)
    db.session.commit()

    return jsonify({'success': 'Data URL stored successfully'}), 200
        
@app.route("/", methods=["POST", "GET"])
def index():
    if request.method == "POST":
        name = request.form.get("name")
        code = request.form.get("code")
        join = request.form.get("join", False)
        create = request.form.get("create", False)

        if not name:
            return render_template("lobby.html", error="Please enter a name.", code=code, name=name)

        if join != False and not code:
            return render_template("lobby.html", error="Please enter a room code.", code=code, name=name)
        
        room = code
        if create != False:
            room = generate_unique_code(4)
            new_room = Room(code=room, members=0)
            db.session.add(new_room)
            db.session.commit()
        elif not Room.query.filter_by(code=code).first():
            return render_template("lobby.html", error="Room does not exist.", code=code, name=name)
        
        session["room"] = room
        session["name"] = name
        return redirect(url_for("room"))

    return render_template("lobby.html")

# Handle register form submission
@app.route('/register', methods=['GET','POST'])
def register():
    if (request.method == 'GET'):
        return render_template('register.html')
    # Retrieve username and password from the form
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get("confirm_password")


    if password != confirm_password:
        return render_template("register.html", error="Passwords do not match")
    # Check if the username is already taken
    if User.query.filter_by(username=username).first():
        # Username already exists, redirect back to the register page with a message
        return redirect(url_for('register'))

    # Hash the password before storing it in the database
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create a new user object and add it to the database
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    # Redirect to the login page after successful registration
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', "POST"])
def login():
    if(request.method == 'GET'):
        return render_template('login.html')
    # Retrieve username and password from the form
    username = request.form.get('username')
    password = request.form.get('password')
    

    # Check if the user exists in the database
    user = User.query.filter_by(username=username).first()
    if user:
        # Check if the provided password matches the stored hashed password
        if bcrypt.check_password_hash(user.password, password):
            # Successful login, redirect to homepage or dashboard
            login_user(user)
            return redirect(url_for('index'))

    # If login fails, redirect back to the login page
    return redirect(url_for('login'))



@app.route("/room")
def room():
    room_code = session.get("room")
    if room_code is None or session.get("name") is None:
        return redirect(url_for("index"))

    room = Room.query.filter_by(code=room_code).first()
    if not room:
        return redirect(url_for("index"))

    messages = Message.query.filter_by(room_id=room.id).all()
    return render_template("room.html", code=room_code, messages=messages)

@app.route('/logout')
@login_required
def logout():
    
    logout_user()  
    return redirect(url_for('login'))

@socketio.on("message")
def message(data):
    room_code = session.get("room")
    name = session.get("name")
    if not room_code or not name:
        return
    
    room = Room.query.filter_by(code=room_code).first()
    if not room:
        print("Room not found")
        return

    try:
        new_message = Message(content=data["data"], room_id=room.id, sender=name)
        db.session.add(new_message)
        db.session.commit()
        emit("message", {"name": name, "message": data["data"]}, room=room_code)
        print("Message sent successfully")
    except Exception as e:
        print("Error:", e)

@socketio.on("connect")
def connect(auth):
    room_code = session.get("room")
    name = session.get("name")
    if not room_code or not name:
        return

    room = Room.query.filter_by(code=room_code).first()
    if not room:
        return

    join_room(room.code)
    room.members += 1

    # Add join message to the room's message history
    message_content = f"{name} has entered the room"
    new_message = Message(content=message_content, sender=name, room_id=room.id)
    db.session.add(new_message)
    db.session.commit()

    # Emit join message to all users in the room
    emit("message", {"name": name, "message": message_content}, room=room.code)

    print(f"{name} joined room {room.code}")


@socketio.on("disconnect")
def disconnect():
    room_code = session.get("room")
    name = session.get("name")
    if not room_code or not name:
        return
    
    user = User.query.filter_by(username=name).first()
    if not user:
        return
    
    room = Room.query.filter_by(code=room_code).first()
    if not room:
        return
    
    leave_room(room_code)
    room.members -= 1
    if room.members <= 0:
        db.session.delete(room)
    db.session.commit()
    
    message_content = f"{name} has left the room"
    message = Message(content=message_content, sender=name, room_id=room.id)
    db.session.add(message)
    db.session.commit()
    
    send({"name": name, "message": message_content}, to=room_code)
    print(f"{name} has left the room {room_code}")

@socketio.on("toggle_eraser")
def handle_toggle_eraser(data):
    # Handle eraser toggle event
    is_erasing = data.get("isErasing")
    emit("toggle_eraser", {"isErasing": is_erasing}, broadcast=True)

@socketio.on("change_color")
def handle_change_color(data):
    # Emit color change event to the client who initiated it
    emit("change_color", data)

@socketio.on("change_width")
def handle_change_width(data):
    # Emit line width change event to the client who initiated it
    emit("change_width", data)

# Listen for the start_line event
@socketio.on('start_line')
def handle_start_line():
    emit('start_line', broadcast=True) 

#@socketio.on("draw")
#def handle_draw(data):
    # Broadcast drawing data to all clients
#    emit("draw", data, broadcast=True)

@socketio.on("draw")
def handle_draw(data):
    # Broadcast drawing data to all clients
    room_code = data['room']
    emit("draw", data, room=room_code)

@socketio.on("start_line")
def handle_start_line(data):
    room_code = data['room']
    emit("start_line", room=room_code)

#@socketio.on("change_color")
#def handle_change_color(data):
    # Handle line color change event
#    color = data.get("color")
#    socket_id = request.sid  # Get the socket ID
#    emit("change_color", {"color": color, "socket_id": socket_id})

#@socketio.on("change_width")
#def handle_change_width(data):
    # Handle line width change event
#    width = data.get("width")
#   socket_id = request.sid  # Get the socket ID
#    emit("change_width", {"width": width, "socket_id": socket_id})

@socketio.on("leave_room")
def handle_leave_room(data):
    room_code = data.get("room")
    name = session.get("name")
    
    #debug
    print(f"Attempting to leave room: {room_code}, by user: {name}")

    if not room_code or not name:
        print("Missing room code or name.")
        return

    #user = User.query.filter_by(username=name).first()
    #if not user:
    #    print(f"User {name} not found.")
    #    return

    room = Room.query.filter_by(code=room_code).first()
    if not room:
        print(f"Room with code {room_code} not found.")
        return

    leave_room(room_code)
    room.members -= 1
    if room.members <= 0:
        db.session.delete(room)
    db.session.commit()

    try:
        message_content = f"{name} has left the room"
        message = Message(content=message_content, sender=name, room_id=room.id)
        db.session.add(message)
        db.session.commit()
    except Exception as e:
        print(f"Error creating or saving message: {e}")
        return

    send({"name": name, "message": message_content}, to=room_code)
    print(f"{name} has left the room {room_code}")


if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=5000)