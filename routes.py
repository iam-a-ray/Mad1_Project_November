from flask import render_template, request, redirect, url_for, flash, session, abort
from app import app
from models import db, User, Service, ServiceRequest, FlaggedUser, ServiceCategory,Order,Transaction  
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

# Decorator to check if the user is an professional
def professional_required(f):
    @wraps(f)
    @auth_required
    def decorated_function(*args, **kwargs):
        user = User.query.filter_by(UserID=session["user_id"]).first()
        if not user or not user.isProfessional:
            flash("Access denied: Only Professional can access this dashboard")
            return redirect(url_for("login"))
        return f(user=user, *args, **kwargs)

    return decorated_function

# Decorator to check if the user is a customer
def customer_required(f):
    @wraps(f)
    @auth_required
    def decorated_function(*args, **kwargs):
        user = User.query.filter_by(UserID=session["user_id"]).first()
        if not user or not user.isCustomer:
            flash("Access denied: Only Customers can access this dashboard")
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

@app.route("/househelp")
def househelp():
    return render_template("househelp.html")

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

    if roles == "professional" and user and user.isProfessional:
        dashboard = "professional_dashboard"
    elif roles == "customer" and user and user.isCustomer:
        dashboard = "customer_dashboard"
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


@app.route("/registerAsProfessional")
def registerAsInf():
    return render_template("registration/ProfessionalRegister.html")


@app.route("/registerAsCustomer")
def registerAsCustomer():
    return render_template("registration/CustomerRegister.html")


@app.route("/registerAsProfessional", methods=["POST"])
def registerAsProfessional():
    name = request.form.get("name")
    username = request.form.get("username")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")
    email = request.form.get("email")
    phone = request.form.get("phone")
    address = request.form.get("address")
    profession = request.form.get("profession")
    experience = request.form.get("experience")
    pincode = request.form.get("pincode")

    if (
        not name
        or not username
        or not password
        or not confirm_password
        or not email
        or not phone
        or not address
        or not profession
        or not experience
        or not pincode
    ):
        flash("All fields are required")
        return redirect(url_for("registerAsProfessional"))

    if password != confirm_password:
        flash("Passwords do not match")
        return redirect(url_for("registerAsProfessional"))

    user_pro = User.query.filter_by(Username=username).first()
    if user_pro:
        flash("Username already exists")
        return redirect(url_for("registerAsProfessional"))

    password_hash = generate_password_hash(password)
    new_user = User(
        Name=name,
        Username=username,
        Passhash=password_hash,
        Email=email,
        Phone=phone,
        Address=address,
        Profession=profession,
        Experience=experience,
        isProfessional=True,
        Pincode=pincode,
    )
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for("login"))


@app.route("/registerAsCustomer", methods=["POST"])
def registerAsCustomer_post():
    name = request.form.get("name")
    username = request.form.get("username")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")
    email = request.form.get("email")
    phone = request.form.get("phone")
    address = request.form.get("address")
    pincode = request.form.get("pincode")

    if (
        not name
        or not username
        or not password
        or not confirm_password
        or not email
        or not phone
        or not address
        or not pincode
    ):
        flash("All fields are required")
        return redirect(url_for("registerAsCustomer"))

    if password != confirm_password:
        flash("Passwords do not match")
        return redirect(url_for("registerAsCustomer"))

    user_customer = User.query.filter_by(Username=username).first()
    if user_customer:
        flash("Username already exists")
        return redirect(url_for("registerAsCustomer"))

    password_hash = generate_password_hash(password)
    new_user = User(
        Name=name,
        Username=username,
        Passhash=password_hash,
        Email=email,
        Address=address,
        Phone=phone,
        Pincode=pincode,
        isCustomer=True,
    )
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for("login"))

@app.route("/customer_dashboard")
@customer_required
def customer_dashboard(user):
    from datetime import date, timedelta

    today = date.today()

    # Fetch all service requests made by the customer
    service_requests = ServiceRequest.query.filter_by(CustomerID=user.UserID).all()

    # Calculate total services, active services, and total budget
    total_services = len(service_requests)
    total_budget_spent = sum(
        request.service.BasePrice for request in service_requests if request.service
    )
    active_services = sum(
        1 for request in service_requests if request.Status == 'assigned'
    )

    # Calculate customer rating from completed requests
    completed_requests = [
        request for request in service_requests if request.Status == 'closed'
    ]
    valid_ratings = [
        request.Rating for request in completed_requests if request.Rating is not None
    ]
    customer_rating = sum(valid_ratings) / len(valid_ratings) if valid_ratings else 0

    # Fetch associated professional details
    service_professionals = {}
    for request in service_requests:
        professional = (
            User.query.get(request.ProfessionalID) if request.ProfessionalID else None
        )
        service_professionals[request.RequestID] = professional.Name if professional else "Not Assigned"

    return render_template(
        "customer/customer_dashboard.html",
        user=user,
        service_requests=service_requests,
        total_services=total_services,
        total_budget_spent=total_budget_spent,
        active_services=active_services,
        customer_rating=round(customer_rating, 2),
        today=today,
        service_professionals=service_professionals,
    )


@app.route("/admin_dashboard")
@admin_required
def admin_dashboard(user):
    return render_template("admin/admin_dashboard.html", user=user)


@app.route("/professional_dashboard")
@professional_required
def professional_dashboard(user):
    service_requests = ServiceRequest.query.filter_by(ProfessionalID=user.UserID).all()
    services = {service_request.service for service_request in service_requests}
    return render_template(
        "professional/professional_dashboard.html",
        user=user,
        service_requests=service_requests,
        services=services,
    )


@app.route("/")
@auth_required
def index():
    user = User.query.filter_by(UserID=session["user_id"]).first()
    if user:
        if user.isProfessional:
            return redirect(url_for("professional_dashboard"))
        elif user.isCustomer:
            return redirect(url_for("customer_dashboard"))
        elif user.isAdmin:
            return redirect(url_for("admin_dashboard"))
    return render_template("index.html")


@app.route("/updateAdminInfo")
@admin_required
def updateAdminInfo(user):
    return render_template("admin/updateAdminInfo.html", user=user)


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


@app.route("/updateProfessionalInfo")
@professional_required
def updateProfessionalInfo(user):
    return render_template("professional/updateProfessionalInfo.html", user=user)


@app.route("/updateProfessionalInfo", methods=["POST"])
@professional_required
def updateProfessionalInfo_post(user):
    name = request.form.get("name")
    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")
    new_password = request.form.get("new_password")
    confirm_password = request.form.get("confirm_password")
    phone = request.form.get("phone")
    address = request.form.get("address")
    experience = request.form.get("experience")
    profession = request.form.get("profession")
    pincode= request.form.get("pincode")

    # Verify the current password
    if not check_password_hash(user.Passhash, password):
        flash("Incorrect password")
        return redirect(url_for("updateProfessionalInfo"))

    # Update only the fields that have been filled in
    if name:
        user.Name = name
    if username:
        existing_user = User.query.filter(User.Username == username).first()
        if existing_user and existing_user.UserID != user.UserID:
            flash("Username already exists")
            return redirect(url_for("updateProfessionalInfo"))
        user.Username = username
    if email:
        user.Email = email
    if phone:
        user.Phone = phone
    if address:
        user.Address = address
    if experience:
        user.Experience = experience
    if profession:
        user.Profession = profession
    if pincode:
        user.Pincode = pincode
    if new_password:
        if new_password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for("updateProfessionalInfo"))
        else:
            user.Passhash = generate_password_hash(new_password)

    # Commit the changes to the database
    db.session.commit()

    flash("Profile updated successfully")
    return redirect(url_for("professional_dashboard"))


@app.route("/updateCustomerInfo")
@customer_required
def updateCustomerInfo(user):
    return render_template("customer/updateCustomerInfo.html", user=user)


@app.route("/updateCustomerInfo", methods=["POST"])
@customer_required
def updateCustomerInfo_post(user):
    name = request.form.get("name")
    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")
    new_password = request.form.get("new_password")
    confirm_password = request.form.get("confirm_password")
    address = request.form.get("address")
    phone = request.form.get("phone")
    pincode = request.form.get("pincode")

    # Verify the current password
    if not check_password_hash(user.Passhash, password):
        flash("Incorrect password")
        return redirect(url_for("updateCustomerInfo"))

    # Update only the fields that have been filled in
    if name:
        user.Name = name
    if username:
        existing_user = User.query.filter(User.Username == username).first()
        if existing_user and existing_user.UserID != user.UserID:
            flash("Username already exists")
            return redirect(url_for("updateCustomerInfo"))
        user.Username = username
    if email:
        user.Email = email
    if address:
        user.Address = address
    if phone:
        user.Phone = phone
    if pincode:
        user.Pincode = pincode
    if new_password:
        if new_password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for("updateCustomerInfo"))
        else:
            user.Passhash = generate_password_hash(new_password)

    # Commit the changes to the database
    db.session.commit()
    flash("Profile updated successfully")
    return redirect(url_for("customer_dashboard"))

@app.route("/flag_user")
@admin_required
def flag_user(user):
    flagged_users = FlaggedUser.query.all()
    return render_template(
        "admin/flag_user.html", user=user, flagged_users=flagged_users
    )

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

@app.route("/admin/service/add", methods=["GET", "POST"])
@admin_required
def add_service():
    if request.method == "POST":
        service_name = request.form.get("service_name")
        description = request.form.get("description")
        base_price = request.form.get("base_price")
        time_required = request.form.get("time_required")
        category_id = request.form.get("category_id")
        pincode = request.form.get("pincode")

        service = Service(ServiceName=service_name, Description=description, BasePrice=base_price, TimeRequired=time_required, CategoryID=category_id, Pincode=pincode)
        db.session.add(service)
        db.session.commit()

        flash("Service added successfully")
        return redirect(url_for("view_services"))

    categories = ServiceCategory.query.all()
    return render_template("service/add.html", categories=categories)

@app.route("/admin/service/edit/<int:service_id>", methods=["GET", "POST"])
@admin_required
def edit_service(service_id):
    service = Service.query.get_or_404(service_id)
    if request.method == "POST":
        service.ServiceName = request.form.get("service_name")
        service.Description = request.form.get("description")
        service.BasePrice = request.form.get("base_price")
        service.TimeRequired = request.form.get("time_required")
        service.CategoryID = request.form.get("category_id")
        service.Pincode = request.form.get("pincode")
        db.session.commit()

        flash("Service updated successfully")
        return redirect(url_for("view_services"))

    categories = ServiceCategory.query.all()
    return render_template("service/edit.html", service=service, categories=categories)

@app.route("/admin/services")
@admin_required
def view_services():
    services = Service.query.all()
    return render_template("service/view.html", services=services)

@app.route("/admin/service/delete/<int:service_id>", methods=["POST"])
@admin_required
def delete_service(service_id):
    service = Service.query.get_or_404(service_id)
    db.session.delete(service)
    db.session.commit()

    flash("Service deleted successfully")
    return redirect(url_for("view_services"))

@app.route("/service_request/add", methods=["GET", "POST"])
@auth_required
def add_service_request():
    if request.method == "POST":
        service_id = request.form.get("service_id")
        category_id = request.form.get("category_id")
        problem_description = request.form.get("problem_description")
        additional_info = request.form.get("additional_info")
        user_id = session["user_id"]

        # Check if the category exists, if not create it
        category = ServiceCategory.query.get(category_id)
        if not category:
            flash("Selected category does not exist.")
            return redirect(url_for("add_service_request"))

        service_request = ServiceRequest(
            ServiceID=service_id,
            CategoryID=category_id,
            ProblemDescription=problem_description,
            AdditionalInfo=additional_info,
            CustomerID=user_id,
            DateOfRequest=datetime.utcnow()
        )
        db.session.add(service_request)
        db.session.commit()

        flash("Service request added successfully")
        return redirect(url_for("view_service_requests"))

    services = Service.query.all()
    categories = ServiceCategory.query.all()
    return render_template("service_request/add.html", services=services, categories=categories)

@app.route("/service_request/edit/<int:request_id>", methods=["GET", "POST"])
@auth_required
def edit_service_request(request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)
    if service_request.CustomerID != session["user_id"]:
        flash("You do not have permission to edit this service request")
        return redirect(url_for("view_service_requests"))

    if request.method == "POST":
        service_request.ServiceID = request.form.get("service_id")
        service_request.AdditionalInfo = request.form.get("additional_info")
        db.session.commit()

        flash("Service request updated successfully")
        return redirect(url_for("view_service_requests"))

    services = Service.query.all()
    return render_template("service_request/edit.html", service_request=service_request, services=services)

@app.route("/service_requests")
@auth_required
def view_service_requests():
    if session.get("role") == "admin":
        service_requests = ServiceRequest.query.all()
    else:
        service_requests = ServiceRequest.query.filter_by(CustomerID=session["user_id"]).all()
    return render_template("service_request/view.html", service_requests=service_requests)

@app.route("/service_request/delete/<int:request_id>", methods=["POST"])
@auth_required
def delete_service_request(request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)
    if service_request.CustomerID != session["user_id"] and session.get("role") != "admin":
        flash("You do not have permission to delete this service request")
        return redirect(url_for("view_service_requests"))

    db.session.delete(service_request)
    db.session.commit()

    flash("Service request deleted successfully")
    return redirect(url_for("view_service_requests"))