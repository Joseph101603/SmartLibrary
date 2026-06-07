from flask import Flask, request, jsonify, send_from_directory, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid
import os

app = Flask(__name__, static_folder='static')
app.secret_key = 'smartlibrary_capstone_secret_key' 

# --- DATABASE CONFIGURATION ---
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'library.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- LOGIN MANAGER SETUP ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page' 

# --- DATABASE MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

class Booking(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    desk_id = db.Column(db.Integer, nullable=False)
    student_id = db.Column(db.String(50), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- AUTHENTICATION ROUTES ---

@app.route('/login_portal')
def login_page():
    return send_from_directory('static', 'login.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    if User.query.filter_by(student_id=data['student_id']).first() or User.query.filter_by(email=data['email']).first():
        return jsonify({"error": "Student ID or Email already registered."}), 400
    
    hashed_pw = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(student_id=data['student_id'], email=data['email'], password_hash=hashed_pw)
    
    db.session.add(new_user)
    db.session.commit()
    
    login_user(new_user)
    is_admin = (new_user.student_id.upper() == 'ADMIN')
    return jsonify({"message": "Registration successful!", "is_admin": is_admin})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(student_id=data['student_id']).first()
    
    if user and check_password_hash(user.password_hash, data['password']):
        login_user(user)
        # Check if the user is the master admin
        is_admin = (user.student_id.upper() == 'ADMIN')
        return jsonify({"message": "Login successful!", "is_admin": is_admin})
    
    return jsonify({"error": "Invalid Student ID or password."}), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login_portal')

# --- CORE APP ROUTES ---

@app.route('/')
@login_required
def index():
    return send_from_directory('static', 'index.html')

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.student_id.upper() != 'ADMIN':
        return "<h1>Access Denied</h1><p>This page is restricted to Library Staff only.</p><a href='/'>Return to Map</a>", 403
    return send_from_directory('static', 'admin.html')

@app.route('/book', methods=['POST'])
@login_required
def book_desk():
    data = request.json
    desk_id = int(data.get('desk_id'))
    start_str = data.get('start_time')
    end_str = data.get('end_time')

    active_student_id = current_user.student_id 

    start_time = datetime.strptime(start_str, "%Y-%m-%dT%H:%M")
    end_time = datetime.strptime(end_str, "%Y-%m-%dT%H:%M")

    if start_time >= end_time:
        return jsonify({"error": "End time must be after start time."}), 400

    duration_hours = (end_time - start_time).total_seconds() / 3600
    if duration_hours > 3:
        return jsonify({"error": "Booking limit exceeded. Maximum 3 hours."}), 400

    start_of_day = start_time.replace(hour=0, minute=0, second=0)
    end_of_day = start_time.replace(hour=23, minute=59, second=59)
    
    daily_booking = Booking.query.filter(
        Booking.student_id == active_student_id,
        Booking.start_time >= start_of_day,
        Booking.start_time <= end_of_day
    ).first()

    if daily_booking:
        return jsonify({"error": "You can only book once per day. Please choose a different date."}), 400

    existing_bookings = Booking.query.filter_by(desk_id=desk_id).all()
    for b in existing_bookings:
        if max(start_time, b.start_time) < min(end_time, b.end_time):
            return jsonify({"error": "Desk already booked for this time."}), 400

    new_booking = Booking(
        desk_id=desk_id,
        student_id=active_student_id,
        start_time=start_time,
        end_time=end_time
    )
    db.session.add(new_booking)
    db.session.commit()
    
    return jsonify({"message": f"Seat S{desk_id} booked successfully!"})

@app.route('/cancel/<booking_id>', methods=['DELETE'])
@login_required
def cancel_booking(booking_id):
    if current_user.student_id.upper() != 'ADMIN':
        return jsonify({"error": "Unauthorized. Only staff can revoke bookings."}), 403

    booking = Booking.query.get(booking_id)
    if booking:
        db.session.delete(booking)
        db.session.commit()
        return jsonify({"message": "Booking revoked successfully."})
    return jsonify({"error": "Booking not found."}), 404

@app.route('/bookings', methods=['GET'])
def get_bookings():
    all_bookings = Booking.query.all()
    res = []
    for b in all_bookings:
        res.append({
            "id": b.id,
            "desk_id": b.desk_id,
            "student_id": b.student_id,
            "start_time": b.start_time.strftime("%Y-%m-%d %H:%M"),
            "end_time": b.end_time.strftime("%Y-%m-%d %H:%M")
        })
    return jsonify(res)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)