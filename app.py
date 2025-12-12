from flask import Flask, request, jsonify, session, redirect
from sqlalchemy import or_
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///civileye.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # Set True if using HTTPS

CORS(app, supports_credentials=True, origins=['http://localhost:*', 'http://127.0.0.1:*'])
db = SQLAlchemy(app)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    complaints = db.relationship('Complaint', backref='user', lazy=True)

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    place = db.Column(db.String(100), nullable=False)
    pincode = db.Column(db.String(6), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone_number = db.Column(db.String(10), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    complaints = db.relationship('Complaint', backref='department', lazy=True)

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.String(20), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    complaint_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')
    priority = db.Column(db.String(20), default='medium')
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    images = db.Column(db.Text)  # Store JSON array of image paths
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updates = db.relationship('ComplaintUpdate', backref='complaint', lazy=True)

class ComplaintUpdate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.Integer, db.ForeignKey('complaint.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Authority(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Helper Functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def generate_complaint_id():
    year = datetime.now().year
    count = Complaint.query.count() + 1
    return f"CE-{year}-{count:04d}"

# User Authentication Routes
@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.get_json(silent=True) or request.form
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    user = User(
        username=data['username'],
        email=data['email'],
        password_hash=generate_password_hash(data['password'])
    )
    
    db.session.add(user)
    db.session.commit()

    session['user_id'] = user.id
    session['user_type'] = 'user'

    # If the client POSTed as JSON (AJAX), return JSON; otherwise redirect to signin page
    if request.content_type and request.content_type.startswith('application/json'):
        return jsonify({
            'message': 'User created successfully',
            'user': {'id': user.id, 'username': user.username, 'email': user.email}
        }), 201
    else:
        # Redirect frontend to signin page (frontend served on port 8000)
        return redirect('http://localhost:8000/signin.html')

@app.route('/api/auth/signin', methods=['POST'])
def signin():
    data = request.get_json(silent=True) or request.form
    identifier = data.get('username')
    # allow signin using username OR email
    user = User.query.filter(or_(User.username == identifier, User.email == identifier)).first()

    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    session['user_id'] = user.id
    session['user_type'] = 'user'
    
    return jsonify({
        'message': 'Login successful',
        'user': {'id': user.id, 'username': user.username, 'email': user.email}
    }), 200

@app.route('/api/auth/signout', methods=['POST'])
def signout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/auth/me', methods=['GET'])
def get_me():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return jsonify({
                'type': 'user',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                }
            }), 200
    elif 'authority_id' in session:
        authority = Authority.query.get(session['authority_id'])
        if authority:
            return jsonify({
                'type': 'authority',
                'authority': {
                    'id': authority.id,
                    'username': authority.username,
                    'email': authority.email
                }
            }), 200
    
    return jsonify({'error': 'Not authenticated'}), 401

# Authority Authentication Routes
@app.route('/api/authority/signin', methods=['POST'])
def authority_signin():
    data = request.get_json(silent=True) or request.form
    authority = Authority.query.filter_by(username=data['username']).first()
    
    if not authority or not check_password_hash(authority.password_hash, data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    session['authority_id'] = authority.id
    session['user_type'] = 'authority'
    
    return jsonify({
        'message': 'Login successful',
        'authority': {'id': authority.id, 'username': authority.username}
    }), 200

# Department Routes
@app.route('/api/departments', methods=['GET'])
def get_departments():
    departments = Department.query.all()
    return jsonify([{
        'id': d.id,
        'name': d.name,
        'place': d.place,
        'pincode': d.pincode,
        'email': d.email,
        'phone_number': d.phone_number,
        'description': d.description
    } for d in departments]), 200

@app.route('/api/departments', methods=['POST'])
def add_department():
    data = request.get_json(silent=True) or request.form

    department = Department(
        name=data.get('dept'),
        place=data.get('place'),
        pincode=data.get('pincode'),
        email=data.get('email'),
        phone_number=data.get('phone_number'),
        description=data.get('description')
    )
    
    db.session.add(department)
    db.session.commit()
    
    return jsonify({
        'message': 'Department added successfully',
        'department': {'id': department.id, 'name': department.name}
    }), 201

@app.route('/api/departments/<int:id>', methods=['DELETE'])
def delete_department(id):
    department = Department.query.get_or_404(id)
    db.session.delete(department)
    db.session.commit()
    return jsonify({'message': 'Department deleted successfully'}), 200

# Complaint Routes
@app.route('/api/complaints', methods=['POST'])
def create_complaint():
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    data = request.form
    complaint_id = generate_complaint_id()
    
    # Handle file uploads
    image_paths = []
    if 'images' in request.files:
        files = request.files.getlist('images')
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                image_paths.append(filename)
    
    complaint = Complaint(
        complaint_id=complaint_id,
        user_id=session['user_id'],
        fullname=data['fullname'],
        email=data['email'],
        location=data['location'],
        complaint_type=data['complaintType'],
        description=data['description'],
        images=','.join(image_paths) if image_paths else None
    )
    
    db.session.add(complaint)
    db.session.commit()
    
    return jsonify({
        'message': 'Complaint submitted successfully',
        'complaint_id': complaint_id
    }), 201

@app.route('/api/complaints', methods=['GET'])
def get_complaints():
    status_filter = request.args.get('status')
    user_id = request.args.get('user_id')
    
    query = Complaint.query
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    if user_id:
        query = query.filter_by(user_id=user_id)
    
    complaints = query.order_by(Complaint.created_at.desc()).all()
    
    return jsonify([{
        'id': c.id,
        'complaint_id': c.complaint_id,
        'fullname': c.fullname,
        'email': c.email,
        'location': c.location,
        'complaint_type': c.complaint_type,
        'description': c.description,
        'status': c.status,
        'priority': c.priority,
        'created_at': c.created_at.isoformat(),
        'images': c.images.split(',') if c.images else []
    } for c in complaints]), 200

@app.route('/api/complaints/latest', methods=['GET'])
def get_latest_complaints():
    complaints = Complaint.query.order_by(Complaint.created_at.desc()).limit(5).all()
    
    return jsonify([{
        'id': c.complaint_id,
        'type': c.complaint_type.replace('_', ' ').title(),
        'location': c.location,
        'priority': c.priority,
        'timeAgo': get_time_ago(c.created_at),
        'status': c.status
    } for c in complaints]), 200

@app.route('/api/complaints/<int:id>', methods=['GET'])
def get_complaint(id):
    complaint = Complaint.query.get_or_404(id)
    
    return jsonify({
        'id': complaint.id,
        'complaint_id': complaint.complaint_id,
        'fullname': complaint.fullname,
        'email': complaint.email,
        'location': complaint.location,
        'complaint_type': complaint.complaint_type,
        'description': complaint.description,
        'status': complaint.status,
        'priority': complaint.priority,
        'created_at': complaint.created_at.isoformat(),
        'images': complaint.images.split(',') if complaint.images else [],
        'updates': [{
            'message': u.message,
            'status': u.status,
            'created_at': u.created_at.isoformat()
        } for u in complaint.updates]
    }), 200

@app.route('/api/complaints/<int:id>/status', methods=['PUT'])
def update_complaint_status(id):
    if 'authority_id' not in session:
        return jsonify({'error': 'Authority authentication required'}), 401
    
    complaint = Complaint.query.get_or_404(id)
    data = request.json
    
    complaint.status = data['status']
    
    update = ComplaintUpdate(
        complaint_id=complaint.id,
        message=data.get('message', f'Status changed to {data["status"]}'),
        status=data['status']
    )
    
    db.session.add(update)
    db.session.commit()
    
    return jsonify({'message': 'Status updated successfully'}), 200

@app.route('/api/stats', methods=['GET'])
def get_stats():
    total = Complaint.query.count()
    pending = Complaint.query.filter_by(status='pending').count()
    inprogress = Complaint.query.filter_by(status='inprogress').count()
    resolved = Complaint.query.filter_by(status='resolved').count()
    
    return jsonify({
        'total': total,
        'pending': pending,
        'inprogress': inprogress,
        'resolved': resolved
    }), 200

def get_time_ago(dt):
    now = datetime.utcnow()
    diff = now - dt
    
    if diff.days > 0:
        return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
    elif diff.seconds >= 3600:
        hours = diff.seconds // 3600
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif diff.seconds >= 60:
        minutes = diff.seconds // 60
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    else:
        return "Just now"

# Initialize database
with app.app_context():
    db.create_all()
    
    # Create default authority account if it doesn't exist
    if not Authority.query.filter_by(username='admin').first():
        admin = Authority(
            username='admin',
            email='admin@civileye.com',
            password_hash=generate_password_hash('admin123')
        )
        db.session.add(admin)
        db.session.commit()
        print("Default admin account created: username='admin', password='admin123'")

if __name__ == '__main__':
    app.run(debug=True, port=5000)