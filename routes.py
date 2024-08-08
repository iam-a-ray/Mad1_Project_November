from flask import render_template, request, redirect, url_for, flash, session
from app import app
from models import db, User, Campaign, AdRequest
from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/')
def index():
    if 'user_id' in session:
        return render_template('index.html')
    else:
        flash('Please login first')
        return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    roles = request.form.get('role')
    username = request.form.get('username')
    password = request.form.get('password')

    if not roles or not username or not password:
        flash('All fields are required')
        return redirect(url_for('login'))

    user = User.query.filter_by(Username=username).first()
    dashboard = None

    if roles == 'influencer' and user and user.isInfluencer:
        dashboard = 'inf_dashboard'
    elif roles == 'sponsor' and user and user.isSponsor:
        dashboard = 'spon_dashboard'
    elif roles == 'admin' and user and user.isAdmin:
        dashboard = 'admin_dashboard'
    else:
        flash('User not found or role mismatch')
        return redirect(url_for('login'))

    if user and check_password_hash(user.Passhash, password):
        session['user_id'] = user.UserID
        flash('Login successful')
        return redirect(url_for(dashboard))
    else:
        flash('Invalid username or password')
        return redirect(url_for('login'))

@app.route('/registerAsInf')
def registerAsInf():
    return render_template('InfluencerRegister.html')

@app.route('/registerAsSponsor')
def registerAsSponsor():
    return render_template('SponsorRegister.html')

@app.route('/registerAsInf', methods=['POST'])
def registerAsInf_post():
    name = request.form.get('name')
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    email = request.form.get('email')
    platform = request.form.get('platform')
    handles = request.form.get('handles')
    category = request.form.get('category')
    follower_count = request.form.get('follower_count')

    if not name or not username or not password or not confirm_password or not email or not platform or not handles or not category or not follower_count:
        flash('All fields are required')
        return redirect(url_for('registerAsInf'))

    if password != confirm_password:
        flash('Passwords do not match')
        return redirect(url_for('registerAsInf'))

    user_inf = User.query.filter_by(Username=username).first()
    if user_inf:
        flash('Username already exists')
        return redirect(url_for('registerAsInf'))

    password_hash = generate_password_hash(password)
    new_user = User(Name=name, Username=username, Passhash=password_hash, Email=email, Platform=platform, Handles=handles, Category=category, Reach=follower_count, isInfluencer=True)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('login'))

@app.route('/registerAsSponsor', methods=['POST'])
def registerAsSponsor_post():
    company_name = request.form.get('name')
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    email = request.form.get('email')
    industry = request.form.get('industry')

    if not company_name or not username or not password or not confirm_password or not email or not industry:
        flash('All fields are required')
        return redirect(url_for('registerAsSponsor'))

    if password != confirm_password:
        flash('Passwords do not match')
        return redirect(url_for('registerAsSponsor'))

    user_spon = User.query.filter_by(Username=username).first()
    if user_spon:
        flash('Username already exists')
        return redirect(url_for('registerAsSponsor'))

    password_hash = generate_password_hash(password)
    new_user = User(Name=company_name, Username=username, Passhash=password_hash, Email=email, Industry=industry, isSponsor=True)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('login'))

@app.route('/inf_dashboard')
def inf_dashboard():
    if 'user_id' not in session:
        flash('Please login first')
        return redirect(url_for('login'))
    user = User.query.filter_by(UserID=session['user_id'], isInfluencer=True).first()
    return render_template('inf_dashboard.html', user=user)

@app.route('/spon_dashboard')
def spon_dashboard():
    if 'user_id' not in session:
        flash('Please login first')
        return redirect(url_for('login'))
    user = User.query.filter_by(UserID=session['user_id'], isSponsor=True).first()
    return render_template('spon_dashboard.html', user=user)

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        flash('Please login first')
        return redirect(url_for('login'))
    user = User.query.filter_by(UserID=session['user_id'], isAdmin=True).first()
    return render_template('admin_dashboard.html', user=user)
