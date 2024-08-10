from flask import render_template, request, redirect, url_for, flash, session
from app import app
from models import db, User, Campaign, AdRequest, FlaggedUser
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
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

@app.route("/insco")
def insco():
    return render_template("insco.html")

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
        session["role"] = roles  # Store the role in the session
        print(roles)
        flash("Login successful")
        return redirect(url_for(dashboard))
    else:
        flash("Invalid username or password")
        return redirect(url_for("login"))

@app.route("/registerAsInf")
def registerAsInf():
    return render_template("registration/InfluencerRegister.html")

@app.route("/registerAsSponsor")
def registerAsSponsor():
    return render_template("registration/SponsorRegister.html")

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
    return render_template("influencer/inf_dashboard.html", user=user)

@app.route("/spon_dashboard")
@sponsor_required
def spon_dashboard(user):
    campaigns = Campaign.query.filter_by(SponsorID=user.UserID).all()
    # Calculate the total number of campaigns
    total_campaigns = len(campaigns)
    # Calculate the total budget spent
    total_budget_spent = sum(campaign.Budget for campaign in campaigns)
    # Calculate the total number of active campaigns (assuming an active campaign is one where the current date is within the start and end date)
    from datetime import date
    today = date.today()
    active_campaigns = sum(1 for campaign in campaigns if campaign.StartDate <= today <= campaign.EndDate)

    return render_template(
        "sponsor/spon_dashboard.html",
        user=user,
        campaigns=campaigns,
        total_campaigns=total_campaigns,
        total_budget_spent=total_budget_spent,
        active_campaigns=active_campaigns,
        today=today,
    )


@app.route("/admin_dashboard")
@admin_required
def admin_dashboard(user):
    return render_template("admin/admin_dashboard.html", user=user)

@app.route("/")
@auth_required
def index():
    user=User.query.filter_by(UserID=session["user_id"]).first()
    if user:
        if user.isInfluencer:
            return redirect(url_for("inf_dashboard"))
        elif user.isSponsor:
            return redirect(url_for("spon_dashboard"))
        elif user.isAdmin:
            return redirect(url_for("admin_dashboard"))
    return render_template("index.html")


@app.route("/updateAdminInfo")
@admin_required
def updateAdminInfo(user):
    return render_template("admin/updateAdminInfo.html",user=user)

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
    if username:
        existing_user = User.query.filter(User.Username == username).first()
        if existing_user and existing_user.UserID != user.UserID:
            flash("Username already exists")
            return redirect(url_for("updateAdminInfo"))
        user.Username = username
    # Check if the username already exists
    if name:
        user.Name = name
    if email:
        user.Email = email
    # Commit the changes to the database
    db.session.commit()
    flash("Profile updated successfully")
    return redirect(url_for("admin_dashboard"))


@app.route("/updateInfInfo")
@influencer_required
def updateInfInfo(user):
    return render_template("influencer/updateInfInfo.html", user=user)

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
    niche = request.form.get("niche")

    # Verify the current password
    if not check_password_hash(user.Passhash, password):
        flash("Incorrect password")
        return redirect(url_for("updateInfInfo"))

    # Update only the fields that have been filled in
    if name:
        user.Name = name
    if username:
        existing_user = User.query.filter(User.Username == username).first()
        if existing_user and existing_user.UserID != user.UserID:
            flash("Username already exists")
            return redirect(url_for("updateInfInfo"))
        user.Username = username
    if email:
        user.Email = email
    if platform:
        user.Platform = platform
    if handles:
        user.Handles = handles
    if category:
        user.Category = category
    if reach:
        user.Reach = reach
    if niche:
        user.Niche = niche
    if new_password:
        if new_password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for("updateInfInfo"))
        else:
            user.Passhash = generate_password_hash(new_password)

    # Commit the changes to the database
    db.session.commit()

    flash("Profile updated successfully")
    return redirect(url_for("inf_dashboard"))


@app.route("/updateSponsorInfo")
@sponsor_required
def updateSponsorInfo(user):
    return render_template("sponsor/updateSponsorInfo.html", user=user)

@app.route("/updateSponsorInfo", methods=["POST"])
@sponsor_required
def updateSponsorInfo_post(user):
    name = request.form.get("name")
    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")
    new_password = request.form.get("new_password")
    confirm_password = request.form.get("confirm_password")
    industry = request.form.get("industry")

    # Verify the current password
    if not check_password_hash(user.Passhash, password):
        flash("Incorrect password")
        return redirect(url_for("updateSponsorInfo"))

    # Update only the fields that have been filled in
    if name:
        user.Name = name
    if username:
        existing_user = User.query.filter(User.Username == username).first()
        if existing_user and existing_user.UserID != user.UserID:
            flash("Username already exists")
            return redirect(url_for("updateSponsorInfo"))
        user.Username = username
    if email:
        user.Email = email
    if industry:
        user.Industry = industry
    if new_password:
        if new_password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for("updateSponsorInfo"))
        else:
            user.Passhash = generate_password_hash(new_password)

    # Commit the changes to the database
    db.session.commit()
    flash("Profile updated successfully")
    return redirect(url_for("spon_dashboard"))


@app.route("/flag_user")
@admin_required
def flag_user(user):
    flagged_users = FlaggedUser.query.all()
    return render_template("admin/flag_user.html", user=user, flagged_users=flagged_users)

@app.route("/flag_user", methods=["POST"])
@admin_required
def flag_user_post(user):
    username = request.form.get("username")
    reason = request.form.get("reason")

    if not username or not reason:
        flash("Please fill all fields")
        return redirect(url_for("flag_user"))

    user = User.query.filter_by(Username=username).first()
    if not user:
        flash("User not found")
        return redirect(url_for("flag_user"))

    flagged_user = FlaggedUser(UserID=user.UserID, Reason=reason)
    db.session.add(flagged_user)
    db.session.commit()

    flash("User flagged successfully")
    return redirect(url_for("flag_user"))

@app.route("/create_campaign")
@sponsor_required
def create_campaign(user):
    return render_template("campaign/add.html", user=user)

@app.route("/create_campaign", methods=["POST"])
@sponsor_required
def create_campaign_post(user):
    name = request.form.get("name")
    description = request.form.get("description")
    start_date_str = request.form.get("start_date")
    end_date_str = request.form.get("end_date")
    budget = request.form.get("budget")
    visibility = request.form.get("visibility")

    if not (name and description and start_date_str and end_date_str and budget and visibility):
        flash("Please fill all fields")
        return redirect(url_for("create_campaign"))

    try:
        # Convert date strings to date objects
        start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
        end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
    except ValueError:
        flash("Invalid date format")
        return redirect(url_for("create_campaign"))

    campaign = Campaign(
        Name=name,
        Description=description,
        StartDate=start_date,
        EndDate=end_date,
        Budget=budget,
        Visibility=visibility,
        SponsorID=user.UserID,
    )

    db.session.add(campaign)
    db.session.commit()

    flash("Campaign created successfully")
    return redirect(url_for("spon_dashboard"))

@app.route("/edit_campaign/<int:campaign_id>")
@sponsor_required
def edit_campaign(user, campaign_id):
    campaign = Campaign.query.filter_by(CampaignID=campaign_id).first()
    return render_template("campaign/edit.html", user=user, campaign=campaign)

@app.route("/edit_campaign/<int:campaign_id>", methods=["POST"])
@sponsor_required
def edit_campaign_post(user, campaign_id):
    # Get the form data
    name = request.form.get("name")
    description = request.form.get("description")
    start_date_str = request.form.get("start_date")
    end_date_str = request.form.get("end_date")
    budget = request.form.get("budget")
    visibility = request.form.get("visibility")
    goals = request.form.get("goals")
    status_str = request.form.get("status")

    # Convert date strings to date objects
    start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
    end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
    from datetime import date
    # Determine status
    if status_str == 'auto':  # If 'Auto' is selected
        today = date.today()
        if start_date > today:
            status = False  # Upcoming (not active)
        elif start_date <= today <= end_date:
            status = True  # Active
        else:
            status = False  # Completed
    else:  # If a specific status is selected
        status = status_str == '1'

    # Fetch the campaign from the database
    campaign = Campaign.query.get(campaign_id)
    if campaign is None or campaign.SponsorID != user.UserID:
        flash("Campaign not found or unauthorized access")
        return redirect(url_for("spon_dashboard"))

    # Update the campaign details
    campaign.Name = name
    campaign.Description = description
    campaign.StartDate = start_date
    campaign.EndDate = end_date
    campaign.Budget = budget
    campaign.Visibility = visibility
    campaign.Goals = goals
    campaign.Status = status

    # Commit the changes to the database
    db.session.commit()

    flash("Campaign updated successfully")
    return redirect(url_for("spon_dashboard"))



@app.route("/view_campaigns")
@sponsor_required
def view_campaigns(user):
    campaigns = Campaign.query.filter_by(SponsorID=user.UserID).all()
    return render_template("campaign/view.html", user=user, campaigns=campaigns)

@app.route("/delete_campaign/<int:campaign_id>")
@sponsor_required
def delete_campaign(user, campaign_id):
    campaign = Campaign.query.filter_by(CampaignID=campaign_id).first()
    db.session.delete(campaign)
    db.session.commit()

    flash("Campaign deleted successfully")
    return redirect(url_for("view_campaigns"))

@app.route("/ad_requests")
@influencer_required
def ad_requests(user):
    ad_requests = AdRequest.query.filter_by(InfluencerID=user.UserID).all()
    return render_template("ad_requests.html", user=user, ad_requests=ad_requests)

@app.route("/profile")
@auth_required
def profile():
    user = User.query.filter_by(UserID=session["user_id"]).first()
    return render_template("profile.html", user=user)

@app.route("/logout")
@auth_required
def logout():
    # Clear the session
    session.clear()
    flash("You have been logged out")
    return redirect(url_for("login"))
