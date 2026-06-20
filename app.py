from flask import Flask, request, jsonify, send_from_directory, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid
import os

app = Flask(__name__, static_folder='static')
app.secret_key = 'smartlibrary_capstone_secret_key' 

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'library.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page' 

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
    is_checked_in = db.Column(db.Boolean, default=False)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---
@app.route('/login_portal')
def login_page(): return send_from_directory('static', 'login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login_portal')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    if User.query.filter_by(student_id=data['student_id']).first(): return jsonify({"error": "Exists"}), 400
    hashed_pw = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(student_id=data['student_id'], email=data['email'], password_hash=hashed_pw)
    db.session.add(new_user); db.session.commit(); login_user(new_user)
    return jsonify({"message": "Success!"})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(student_id=data['student_id']).first()
    if user and check_password_hash(user.password_hash, data['password']):
        login_user(user); return jsonify({"message": "Success!"})
    return jsonify({"error": "Invalid"}), 401

@app.route('/api/me')
@login_required
def current_user_info(): return jsonify({"student_id": current_user.student_id})

@app.route('/api/my_stats')
@login_required
def my_stats():
    user_bookings = Booking.query.filter_by(student_id=current_user.student_id).all()
    total_hours = sum([(b.end_time - b.start_time).total_seconds()/3600 for b in user_bookings])
    return jsonify({"total_hours": round(total_hours, 1), "total_sessions": len(user_bookings)})

@app.route('/api/checkin/<booking_id>', methods=['POST'])
@login_required
def check_in(booking_id):
    booking = Booking.query.get(booking_id)
    # Ensure the booking exists and belongs to the student
    if booking and booking.student_id == current_user.student_id:
        booking.is_checked_in = True
        db.session.commit()
        return jsonify({"message": "Checked in successfully!"})
    return jsonify({"error": "Invalid booking or unauthorized"}), 404

@app.route('/')
@login_required
def index(): return send_from_directory('static', 'index.html')

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.student_id.upper() != 'ADMIN': return jsonify({"error": "Denied"}), 403
    return send_from_directory('static', 'admin.html')

@app.route('/book', methods=['POST'])
@login_required
def book_desk():
    data = request.json
    desk_id = int(data.get('desk_id'))
    start_time = datetime.strptime(data.get('start_time'), "%Y-%m-%dT%H:%M")
    end_time = datetime.strptime(data.get('end_time'), "%Y-%m-%dT%H:%M")

    # --- FIX: Time Validation Logic ---
    if start_time >= end_time:
        return jsonify({"error": "Start time must be before end time."}), 400
    
    duration_hours = (end_time - start_time).total_seconds() / 3600
    if duration_hours > 3:
        return jsonify({"error": "Booking limit exceeded. Maximum 3 hours."}), 400
    # --- END FIX ---

    start_of_day = start_time.replace(hour=0, minute=0, second=0)
    end_of_day = start_time.replace(hour=23, minute=59, second=59)
    
    daily_booking = Booking.query.filter(
        Booking.student_id == current_user.student_id,
        Booking.start_time >= start_of_day,
        Booking.start_time <= end_of_day
    ).first()

    if daily_booking:
        return jsonify({"error": "You can only book once per day."}), 400

    new_booking = Booking(
        desk_id=desk_id, 
        student_id=current_user.student_id, 
        start_time=start_time, 
        end_time=end_time
    )
    db.session.add(new_booking)
    db.session.commit()
    return jsonify({"message": "Booked successfully!"})

@app.route('/cancel/<booking_id>', methods=['DELETE'])
@login_required
def cancel_booking(booking_id):
    booking = Booking.query.get(booking_id)
    if not booking or (current_user.student_id.upper() != 'ADMIN' and current_user.student_id != booking.student_id): return jsonify({"error": "Denied"}), 403
    db.session.delete(booking); db.session.commit(); return jsonify({"message": "Cancelled!"})

@app.route('/bookings', methods=['GET'])
def get_bookings():
    return jsonify([{"id": b.id, "desk_id": b.desk_id, "student_id": b.student_id, "start_time": b.start_time.strftime("%Y-%m-%d %H:%M"), "end_time": b.end_time.strftime("%Y-%m-%d %H:%M")} for b in Booking.query.all()])

if __name__ == '__main__': app.run(host='0.0.0.0', debug=True, port=5000)