from flask import render_template, request, redirect, url_for, flash, session
from app import app
from models import db, User, Campaign, AdRequest
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps


# Decorator to check if the user is logged in
def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


# Decorator to check if the user is an influencer
def influencer_required(f):
    @wraps(f)
    @auth_required
    def decorated_function(*args, **kwargs):
        user = User.query.filter_by(UserID=session["user_id"]).first()
        if not user or not user.isInfluencer:
            flash("Access denied: Only influencers can access this dashboard")
            return redirect(url_for("login"))
        return f(user=user, *args, **kwargs)

    return decorated_function


# Decorator to check if the user is a sponsor
def sponsor_required(f):
    @wraps(f)
    @auth_required
    def decorated_function(*args, **kwargs):
        user = User.query.filter_by(UserID=session["user_id"]).first()
        if not user or not user.isSponsor:
            flash("Access denied: Only sponsors can access this dashboard")
            return redirect(url_for("login"))
        return f(user=user, *args, **kwargs)

    return decorated_function


# Decorator to check if the user is an admin
def admin_required(f):
    @wraps(f)
    @auth_required
    def decorated_function(*args, **kwargs):
        user = User.query.filter_by(UserID=session["user_id"]).first()
        if not user or not user.isAdmin:
            flash("Access denied: Only admins can access this dashboard")
            return redirect(url_for("login"))
        return f(user=user, *args, **kwargs)

    return decorated_function


@app.route("/")
@auth_required
def index():
    return render_template("index.html")


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_post():
    roles = request.form.get("role")
    username = request.form.get("username")
    password = request.form.get("password")

    if not roles or not username or not password:
        flash("All fields are required")
        return redirect(url_for("login"))

    user = User.query.filter_by(Username=username).first()
    dashboard = None

    if roles == "influencer" and user and user.isInfluencer:
        dashboard = "inf_dashboard"
    elif roles == "sponsor" and user and user.isSponsor:
        dashboard = "spon_dashboard"
    elif roles == "admin" and user and user.isAdmin:
        dashboard = "admin_dashboard"
    else:
        flash("User not found or role mismatch")
        return redirect(url_for("login"))

    if user and check_password_hash(user.Passhash, password):
        session["user_id"] = user.UserID
        flash("Login successful")
        return redirect(url_for(dashboard))
    else:
        flash("Invalid username or password")
        return redirect(url_for("login"))


@app.route("/registerAsInf")
def registerAsInf():
    return render_template("InfluencerRegister.html")


@app.route("/registerAsSponsor")
def registerAsSponsor():
    return render_template("SponsorRegister.html")


@app.route("/registerAsInf", methods=["POST"])
def registerAsInf_post():
    name = request.form.get("name")
    username = request.form.get("username")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")
    email = request.form.get("email")
    platform = request.form.get("platform")
    handles = request.form.get("handles")
    category = request.form.get("category")
    follower_count = request.form.get("follower_count")

    if (
        not name
        or not username
        or not password
        or not confirm_password
        or not email
        or not platform
        or not handles
        or not category
        or not follower_count
    ):
        flash("All fields are required")
        return redirect(url_for("registerAsInf"))

    if password != confirm_password:
        flash("Passwords do not match")
        return redirect(url_for("registerAsInf"))

    user_inf = User.query.filter_by(Username=username).first()
    if user_inf:
        flash("Username already exists")
        return redirect(url_for("registerAsInf"))

    password_hash = generate_password_hash(password)
    new_user = User(
        Name=name,
        Username=username,
        Passhash=password_hash,
        Email=email,
        Platform=platform,
        Handles=handles,
        Category=category,
        Reach=follower_count,
        isInfluencer=True,
    )
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for("login"))


@app.route("/registerAsSponsor", methods=["POST"])
def registerAsSponsor_post():
    company_name = request.form.get("name")
    username = request.form.get("username")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")
    email = request.form.get("email")
    industry = request.form.get("industry")

    if (
        not company_name
        or not username
        or not password
        or not confirm_password
        or not email
        or not industry
    ):
        flash("All fields are required")
        return redirect(url_for("registerAsSponsor"))

    if password != confirm_password:
        flash("Passwords do not match")
        return redirect(url_for("registerAsSponsor"))

    user_spon = User.query.filter_by(Username=username).first()
    if user_spon:
        flash("Username already exists")
        return redirect(url_for("registerAsSponsor"))

    password_hash = generate_password_hash(password)
    new_user = User(
        Name=company_name,
        Username=username,
        Passhash=password_hash,
        Email=email,
        Industry=industry,
        isSponsor=True,
    )
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for("login"))


@app.route("/inf_dashboard")
@influencer_required
def inf_dashboard(user):
    return render_template("inf_dashboard.html", user=user)


@app.route("/spon_dashboard")
@sponsor_required
def spon_dashboard(user):
    return render_template("spon_dashboard.html", user=user)


@app.route("/admin_dashboard")
@admin_required
def admin_dashboard(user):
    return render_template("admin_dashboard.html", user=user)


@app.route("/updateAdminInfo")
@admin_required
def updateAdminInfo(user):
    return render_template("updateAdminInfo.html",user=user)


@app.route("/updateAdminInfo", methods=["POST"])
@admin_required
def updateAdminInfo_post(user):
    name = request.form.get("name")
    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")
    new_password = request.form.get("new_password")

    # Check if all required fields are filled
    if not name or not email or not password or not username:
        flash("Fill all necessary fields")
        return redirect(url_for("updateAdminInfo"))

    # Verify the current password
    if not check_password_hash(user.Passhash, password):
        flash("Incorrect password")
        return redirect(url_for("updateAdminInfo"))

    # If a new password is provided, ensure it matches the confirmation
    if new_password:
        if new_password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for("updateAdminInfo"))
        else:
            user.Passhash = generate_password_hash(new_password)

    # Update the user's information
    user.Name = name
    user.Email = email
    user.Username = username

    # Commit the changes to the database
    db.session.commit()

    flash("Profile updated successfully")
    return redirect(url_for("admin_dashboard"))


@app.route("/updateInfInfo")
@influencer_required
def updateInfInfo(user):
    return render_template("updateInfInfo.html", user=user)

@app.route("/updateInfInfo", methods=["POST"])
@influencer_required
def updateInfInfo_post(user):
    name = request.form.get("name")
    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")
    new_password = request.form.get("new_password")
    confirm_password = request.form.get("confirm_password")
    platform = request.form.get("platform")
    handles = request.form.get("handles")
    category = request.form.get("category")
    reach = request.form.get("reach")
    niche = request.form.get("niche")  # Retrieve niche from the form

    # Check if all required fields are filled
    if not (name and email and password and username and platform and handles and category and reach and niche):
        flash("Please fill all necessary fields")
        return redirect(url_for("updateInfInfo"))

    # Verify the current password
    if not check_password_hash(user.Passhash, password):
        flash("Incorrect password")
        return redirect(url_for("updateInfInfo"))

    # Handle new password
    if new_password:
        if new_password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for("updateInfInfo"))
        else:
            user.Passhash = generate_password_hash(new_password)
    
    # Update the user's information
    user.Name = name
    user.Email = email
    user.Username = username
    user.Platform = platform
    user.Handles = handles
    user.Category = category
    user.Reach = reach
    user.Niche = niche  # Update the niche field

    # Commit the changes to the database
    db.session.commit()

    flash("Profile updated successfully")
    return redirect(url_for("inf_dashboard"))

@app.route("/updateSponInfo")
@sponsor_required
def updateSponInfo(user):
    return render_template("updateSponsorInfo.html", user=user)

@app.route("/updateSponInfo", methods=["POST"])
@sponsor_required
def updateSponInfo_post(user):
    name = request.form.get("name")
    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")
    new_password = request.form.get("new_password")
    confirm_password = request.form.get("confirm_password")
    industry = request.form.get("industry")
    company= request.form.get("company")

    # Check if all required fields are filled
    if not (name and email and password and username and industry and company):
        flash("Please fill all necessary fields")
        return redirect(url_for("updateSponInfo"))

    # Verify the current password
    if not check_password_hash(user.Passhash, password):
        flash("Incorrect password")
        return redirect(url_for("updateSponInfo"))

    # Handle new password
    if new_password:
        if new_password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for("updateSponInfo"))
        else:
            user.Passhash = generate_password_hash(new_password)

    # Update the user's information
    user.Name = name
    user.Email = email
    user.Username = username
    user.Industry = industry
    user.CompanyName = company

    # Commit the changes to the database
    db.session.commit()

    flash("Profile updated successfully")
    return redirect(url_for("spon_dashboard"))




@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("You have been logged out")
    return redirect(url_for("login"))
