from flask import Flask, render_template, request, redirect, url_for
from flask_socketio import SocketIO, send
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database URI for SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking

# Initialize extensions
db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)
bcrypt = Bcrypt(app)

# Create a User model to represent users in the database
class User(UserMixin, db.Model):
    id = db.Column(db.String(150), primary_key=True)
    password = db.Column(db.String(150))

# Load user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Find the user in the database
    user = User.query.get(username)
    
    if user and bcrypt.check_password_hash(user.password, password):  # Check if password is correct
        login_user(user)
        return redirect(url_for('chat'))
    
    return 'Invalid credentials', 401

@app.route('/create_account')
def create_account():
    return render_template('create_user.html')

@app.route('/create_user', methods=['POST'])
def create_user():
    username = request.form['username']
    password = request.form['password']
    
    # Hash the password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    # Create a new user and add it to the database
    new_user = User(id=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    
    return redirect(url_for('index'))

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', username=current_user.id)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@socketio.on('message')
def handle_message(msg):
    print(f"{current_user.id}: {msg}")
    send({'username': current_user.id, 'msg': msg}, broadcast=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create the database tables (if they don't already exist)
    socketio.run(app, debug=True)

