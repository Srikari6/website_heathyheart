from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import pickle
from prediction import predict_swe
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config['SECRET_KEY'] = '22bce7409'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\kvsud\\OneDrive\\Desktop\\html\\SWE\\heart_helper.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password_hash = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    input_data = db.Column(db.String, nullable=False)
    prediction_result = db.Column(db.String(50), nullable=False)
    prediction_score = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LoginActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)

# Load the machine learning model
with open('SWE.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Registration Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        user = User(username=username, email=email, password_hash=hashed_password)
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()  # Rollback the session to avoid issues with future inserts
            flash('An account with this email already exists. Please use a different email.', 'warning')
            return redirect(url_for('register'))
            
    return render_template('register.html')

# Login Page
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user:
            if bcrypt.check_password_hash(user.password_hash, password):
                login_user(user)
                
                # Log the login activity
                login_activity = LoginActivity(user_id=user.id)
                db.session.add(login_activity)
                db.session.commit()
                
                return redirect(url_for('profile'))
            else:
                flash('Login Unsuccessful. Check email and password.', 'danger')
        else:
            flash('You are not registered. Please register first.', 'warning')
            return redirect(url_for('register'))  # Redirect to registration page if not registered
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Profile Page
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

# BMI Calculator Page
@app.route('/bmi', methods=['GET', 'POST'])
@login_required
def bmi():
    if request.method == 'POST':
        weight = float(request.form['weight'])
        height = float(request.form['height'])
        bmi = weight / ((height / 100) ** 2)
        bmi_message = "Normal" if 18.5 <= bmi <= 24.9 else "Outside the normal range"
        return render_template('result.html', bmi=bmi, bmi_message=bmi_message)
    return render_template('bmi.html')

# Result Page
@app.route('/result')
@login_required
def result():
    return render_template('result.html')

# Health Input Form
@app.route('/health_input', methods=['GET', 'POST'])
@login_required
def health_input():
    if request.method == 'POST':
        # Collect and process inputs
        data = {
            'age': int(request.form['age']),
            'education': int(request.form['education']),
            'sex': int(request.form['sex']),
            'is_smoking': int(request.form.get('is_smoking', 0)),
            'cigsPerDay': int(request.form.get('cigsPerDay', 0)),
            'BPMeds': int(request.form.get('BPMeds', 0)),
            'prevalentStroke': int(request.form.get('prevalentStroke', 0)),
            'prevalentHyp': int(request.form.get('prevalentHyp', 0)),
            'diabetes': int(request.form.get('diabetes', 0)),
            'totChol': int(request.form['totChol']),
            'sysBP': float(request.form['sysBP']),
            'diaBP': float(request.form['diaBP']),
            'BMI': float(request.form['BMI']),
            'heartRate': int(request.form['heartRate']),
            'glucose': int(request.form['glucose']),
        }
        features = [0] + list(data.values())
        prediction = predict_swe([features])
        prediction_result = "High risk" if prediction >= 0.7 else "Average risk" if prediction >= 0.3 else "Low risk"

        # Store prediction in database
        new_prediction = Prediction(
            user_id=current_user.id,
            input_data=str(data),
            prediction_result=prediction_result,
            prediction_score=prediction
        )
        db.session.add(new_prediction)
        db.session.commit()

        return render_template('prediction_result.html', prediction_result=prediction_result, prediction=prediction)
    return render_template('health_input.html')

# Reports Page
@app.route('/reports')
@login_required
def reports():
    # Retrieve all predictions for the current user
    user_reports = Prediction.query.filter_by(user_id=current_user.id).order_by(Prediction.created_at.desc()).all()
    return render_template('reports.html', reports=user_reports)

# Start the Flask server
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensures tables are created
    app.run(debug=True)
