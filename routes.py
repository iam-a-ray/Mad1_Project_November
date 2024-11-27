from flask import render_template, request, redirect, url_for, flash, session, abort
from app import app
from models import db, User, Service, ServiceRequest, FlaggedUser
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
def registerAsProfessional_post():
    name = request.form.get("name")
    username = request.form.get("username")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")
    email = request.form.get("email")
    phone = request.form.get("phone")
    address = request.form.get("address")
    servicetype = request.form.get("servicetype")
    experience = request.form.get("experience")

    if (
        not name
        or not username
        or not password
        or not confirm_password
        or not email
        or not phone
        or not address
        or not servicetype
        or not experience
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
        Servicetype=servicetype,
        Experience=experience,
        isProfessional=True,
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

    if (
        not name
        or not username
        or not password
        or not confirm_password
        or not email
        or not phone
        or not address
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

    # Fetch all services for this sponsor
    services = Service.query.filter_by(CustomerID=user.UserID).all()

    # Calculate the total number of services
    total_services = len(services)

    # Calculate the total budget spent
    total_budget_spent = sum(service.Budget for service in services)

    # Calculate the total number of active services
    active_services = sum(
        1 for service in services if service.StartDate <= today <= service.EndDate
    )

    ad_requests = (
        ServiceRequest.query.join(Service).filter(Service.CustomerID == user.UserID).all()
    )
    valid_ratings = [
        service_request.Rating for service_request in ad_requests if service_request.Rating is not None
    ]
    total_rating = sum(valid_ratings)
    sponsor_rating = total_rating / len(valid_ratings) if valid_ratings else 0

    # Update service ratings based on end date
    for service_request in ad_requests:
        days_after_end = (today - service_request.service.EndDate).days
        if days_after_end > 0:
            new_rating = max(0, service_request.Rating - days_after_end)
            service_request.Rating = new_rating
            db.session.commit()

    # Get professional names associated with each service
    service_professionals = {}
    for service in services:
        service_request = ServiceRequest.query.filter_by(
            ServiceID=service.ServiceID, Status="accepted"
        ).first()
        if service_request:
            professional = User.query.get(service_request.ProfessionalID)
            service_professionals[service.ServiceID] = professional.Name
        else:
            service_professionals[service.ServiceID] = None

    # Automatically determine the status of each service
    for service in services:
        if service.StartDate > today:
            service.Status = False  # Upcoming (not active)
        elif service.StartDate <= today <= service.EndDate:
            service.Status = True  # Active
        else:
            service.Status = False  # Completed
        db.session.commit()

    return render_template(
        "sponsor/customer_dashboard.html",
        user=user,
        services=services,
        total_services=total_services,
        total_budget_spent=total_budget_spent,
        active_services=active_services,
        sponsor_rating=sponsor_rating,
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
    ad_requests = ServiceRequest.query.filter_by(ProfessionalID=user.UserID).all()
    services = {service_request.service for service_request in ad_requests}
    return render_template(
        "professional/professional_dashboard.html",
        user=user,
        ad_requests=ad_requests,
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
def updateInfInfo(user):
    return render_template("professional/updateProfessionalInfo.html", user=user)


@app.route("/updateProfessionalInfo", methods=["POST"])
@professional_required
def updateInfInfo_post(user):
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
    if phone:
        user.Phone = phone
    if address:
        user.Address = address
    if experience:
        user.Experience = experience
    if profession:
        user.Profession = profession
    if new_password:
        if new_password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for("updateInfInfo"))
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


@app.route("/create_service")
@customer_required
def create_service(user):
    return render_template("service/add.html", user=user)


@app.route("/create_service_requests", methods=["POST"])
@customer_required
def create_service_post(user):
    name = request.form.get("name")
    description = request.form.get("description")
    start_date_str = request.form.get("start_date")
    end_date_str = request.form.get("end_date")
    budget = request.form.get("budget")
    visibility = request.form.get("visibility")

    # Convert date strings to date objects
    start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
    end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()

    # Create a new service
    service = Service(
        Name=name,
        Description=description,
        StartDate=start_date,
        EndDate=end_date,
        Budget=budget,
        Visibility=visibility,
        CustomerID=user.UserID,  # Assuming the sponsor's ID is the user ID
    )

    db.session.add(service)
    db.session.commit()

    if visibility == "private":
        professional_id = request.form.get("professional_id")
        if not professional_id:
            flash("Please provide the professional ID")
            return redirect(url_for("create_service"))

        # Check if the professional ID exists in the database
        professional = User.query.filter_by(UserID=professional_id).first()
        if not professional:
            flash("Influencer not found")
            return redirect(url_for("create_service"))

        # Create a service request for the targeted professional
        service_request = ServiceRequest(
            ServiceID=service.ServiceID,  # Now you can use service.ServiceID
            ProfessionalID=professional.UserID,
            Status="pending",
        )

        db.session.add(service_request)
        db.session.commit()

        flash("Service request sent to the targeted professional")
        return redirect(url_for("customer_dashboard"))

    # Flash a success message and redirect to the sponsor dashboard
    flash("Service created successfully")
    return redirect(url_for("customer_dashboard"))

    if not (
        name
        and description
        and start_date_str
        and end_date_str
        and budget
        and visibility
    ):
        flash("Please fill all fields")
        return redirect(url_for("create_service"))

    try:
        # Convert date strings to date objects
        start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
        end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
    except ValueError:
        flash("Invalid date format")
        return redirect(url_for("create_service"))

    service = Service(
        Name=name,
        Description=description,
        StartDate=start_date,
        EndDate=end_date,
        Budget=budget,
        Visibility=visibility,
        CustomerID=user.UserID,
    )

    db.session.add(service)
    db.session.commit()

    flash("Service created successfully")
    return redirect(url_for("customer_dashboard"))


@app.route("/edit_service_requests/<int:service_id>")
@customer_required
def edit_service_requests(user, service_id):
    service = Service.query.filter_by(ServiceID=service_id).first()
    return render_template("service/edit.html", user=user, service=service)


@app.route("/edit_service/<int:service_id>", methods=["POST"])
@customer_required
def edit_service_post(user, service_id):
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
    if status_str == "auto":  # If 'Auto' is selected
        today = date.today()
        if start_date > today:
            status = False  # Upcoming (not active)
        elif start_date <= today <= end_date:
            status = True  # Active
        else:
            status = False  # Completed
    else:  # If a specific status is selected
        status = status_str == "1"

    # Fetch the service from the database
    service = Service.query.get(service_id)
    if service is None or service.CustomerID != user.UserID:
        flash("Service not found or unauthorized access")
        return redirect(url_for("customer_dashboard"))

    # Update the service details
    service.Name = name
    service.Description = description
    service.StartDate = start_date
    service.EndDate = end_date
    service.Budget = budget
    service.Visibility = visibility
    service.Goals = goals
    service.Status = status

    # Commit the changes to the database
    db.session.commit()

    flash("Service updated successfully")
    return redirect(url_for("customer_dashboard"))


@app.route("/view_services")
@customer_required
def view_services(user):
    services = Service.query.filter_by(CustomerID=user.UserID).all()

    # Fetch service professionals
    service_professionals = {}
    for service in services:
        service_request = ServiceRequest.query.filter_by(
            ServiceID=service.ServiceID, Status="accepted"
        ).first()
        if service_request:
            professional = User.query.get(service_request.ProfessionalID)
            service_professionals[service.ServiceID] = professional.Name
        else:
            service_professionals[service.ServiceID] = None

    return render_template(
        "service/view.html",
        user=user,
        services=services,
        service_professionals=service_professionals,  # Pass to the template
    )


@app.route("/delete_service/<int:service_id>")
@customer_required
def delete_service(user, service_id):
    service = Service.query.filter_by(ServiceID=service_id).first()
    db.session.delete(service)
    db.session.commit()

    flash("Service deleted successfully")
    return redirect(url_for("view_services"))


@app.route("/view_service")
@professional_required
def view_ad_requests(user):
    service_requests = ServiceRequest.query.filter_by(ProfessionalID=user.UserID).all()
    return render_template(
        "negotiation/adRequest.html", user=user, service_requests=service_requests
    )


@app.route("/view_service/<int:request_id>")
@professional_required
def view_service_request(user, request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)
    if service_request.ProfessionalID != user.UserID:
        abort(403)
    return render_template(
        "negotiation/view_adRequest.html", user=user, service_request_request=service_request
    )


@app.route("/working_service_requests")
@professional_required
def working_requests(user):
    service_requests = ServiceRequest.query.filter_by(
        ProfessionalID=user.UserID, Status="accepted"
    ).all()
    return render_template(
        "professional/working_service_requests.html", user=user, service_requests=service_requests
    )


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

@app.route("/accept_request/<int:request_id>", methods=["POST"])
@professional_required
def accept_request(user, request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)
    
    if service_request.ProfessionalID != user.UserID:
        abort(403)
    
    # Update ad request status
    service_request.Status = "accepted"
    
    # Find the associated service
    service = Service.query.get(service_request.ServiceID)
    if service:
        service.ProfessionalID = user.UserID  # Assign professional to the service
        service.Status = True  # Mark service as active
    
    db.session.commit()
    flash("Request accepted")
    return redirect(url_for("professional_dashboard"))

@app.route("/decline_request/<int:request_id>", methods=["POST"])
@professional_required
def decline_request(user, request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)
    
    if service_request.ProfessionalID != user.UserID:
        abort(403)
    
    # Update ad request status
    service_request.Status = "declined"
    
    # Remove professional assignment from the service
    service = Service.query.get(service_request.ServiceID)
    if service:
        # Optionally, set the ProfessionalID to None or handle it according to your logic
        service.ProfessionalID = None
    
    db.session.commit()
    flash("Request declined")
    return redirect(url_for("professional_dashboard"))
