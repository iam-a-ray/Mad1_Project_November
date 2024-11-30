from flask import render_template, request, redirect, url_for, flash, session, abort,make_response
from app import app
from models import db, User, Service, ServiceRequest, FlaggedUser, ServiceCategory,Order,Transaction  
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import csv
import io


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

# @app.route("/professional_dashboard")
# @auth_required
# def professional_dashboard():
#     user_id = session["user_id"]
#     user = User.query.get(user_id)
#     if not user.isProfessional or not user.isApproved:
#         flash("You do not have permission to access this page")
#         return redirect(url_for("index"))

#     services = Service.query.filter_by(Profession=user.Profession).all()
#     services = Service.query.join(ServiceCategory, Service.CategoryID == ServiceCategory.CategoryID).filter(ServiceCategory.Name == user.Profession).all()
#     categories = ServiceCategory.query.all()
#     return render_template("professional_dashboard.html", user=user, services=services, categories=categories)

# @app.route("/search_services", methods=["GET"])
# @auth_required
# def search_services():
#     user_id = session["user_id"]
#     user = User.query.get(user_id)
#     if not user.isProfessional or not user.isApproved:
#         flash("You do not have permission to access this page")
#         return redirect(url_for("index"))

#     search_query = request.args.get("search_query")
#     services = Service.query.filter(Service.ServiceName.ilike(f"%{search_query}%")).all()
#     categories = ServiceCategory.query.all()
#     return render_template("professional_dashboard.html", user=user, services=services, categories=categories)

@app.route("/professional_dashboard")
@auth_required
def professional_dashboard():
    user_id = session["user_id"]
    user = User.query.get(user_id)
    if not user.isProfessional or not user.isApproved:
        flash("You do not have permission to access this page")
        return redirect(url_for("index"))

    services = Service.query.all()
    categories = ServiceCategory.query.all()
    return render_template("professional/professional_dashboard.html", user=user, services=services, categories=categories)

@app.route("/search_services", methods=["GET"])
@auth_required
def search_services():
    user_id = session["user_id"]
    user = User.query.get(user_id)
    if not user.isProfessional or not user.isApproved:
        flash("You do not have permission to access this page")
        return redirect(url_for("index"))
    category_id = request.args.get("category_id", "")
    pincode = request.args.get("pincode", "")

    query = Service.query
    if category_id:
        query = query.filter_by(CategoryID=category_id)
    if pincode:
        query = query.filter_by(Pincode=pincode)

    services = query.all()
    categories = ServiceCategory.query.all()
    return render_template("professional/search_services.html", user=user, services=services, categories=categories)

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

@app.route("/orders")
@auth_required
def view_orders():
    user_id = session["user_id"]
    user = User.query.get(user_id)

    if user.isCustomer:
        orders = Order.query.join(Transaction).filter(Transaction.UserID == user_id).all()
    elif user.isProfessional:
        orders = Order.query.join(Service).filter(Service.ProfessionalID == user_id).all()
    else:
        flash("You do not have permission to access this page")
        return redirect(url_for("index"))

    return render_template("orders.html", user=user, orders=orders)

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

@app.route("/admin_dashboard")
@admin_required
def admin_dashboard(user):
    return render_template("admin/admin_dashboard.html", user=user)

@app.route("/view_users")
@admin_required
def view_users(user):
    users = User.query.all()
    return render_template("admin/view_users.html", users=users, user=user)

@app.route("/approve_professionals")
@admin_required
def approve_professionals(user):
    professionals = User.query.filter_by(isProfessional=True, isApproved=False).all()
    return render_template("admin/approve_professionals.html", professionals=professionals, user=user)

@app.route("/block_users")
@admin_required
def block_users(current_user):
    users = User.query.all()
    return render_template("admin/block_users.html", users=users, current_user=current_user)

@app.route("/admin/service/add", methods=["GET", "POST"])
@admin_required
def add_service(user):
    if request.method == "POST":
        service_name = request.form.get("service_name")
        description = request.form.get("description")
        base_price = request.form.get("base_price")
        time_required = request.form.get("time_required")
        category_id = request.form.get("category_id")
        pincode = request.form.get("pincode")

        service = Service(
            ServiceName=service_name,
            Description=description,
            BasePrice=base_price,
            TimeRequired=time_required,
            CategoryID=category_id,
            Pincode=pincode
        )
        db.session.add(service)
        db.session.commit()

        flash("Service added successfully")
        return redirect(url_for("view_services"))

    categories = ServiceCategory.query.all()
    return render_template("admin/add_service.html", categories=categories, user=user)

@app.route("/admin/service/edit/<int:service_id>", methods=["GET", "POST"])
@admin_required
def edit_service(user, service_id):
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
    return render_template("admin/edit_service.html", service=service, categories=categories, user=user)

@app.route("/admin/service/delete/<int:service_id>", methods=["POST"])
@admin_required
def delete_service(user, service_id):
    service = Service.query.get_or_404(service_id)
    db.session.delete(service)
    db.session.commit()

    flash("Service deleted successfully")
    return redirect(url_for("view_services"))

@app.route("/admin/services")
@admin_required
def view_services(user):
    services = Service.query.all()
    return render_template("admin/view_services.html", services=services, user=user)

@app.route("/service_request/add", methods=["GET", "POST"])
@auth_required
def add_service_request():
    user_id = session["user_id"]
    user = User.query.get(user_id)

    if request.method == "POST":
        service_id = request.form.get("service_id")
        category_id = request.form.get("category_id")
        new_category = request.form.get("new_category")
        new_service = request.form.get("new_service")
        base_price = request.form.get("base_price")
        time_required = request.form.get("time_required")
        pincode = request.form.get("pincode")
        problem_description = request.form.get("problem_description")


        # Handle new category
        if new_category:
            existing_category = ServiceCategory.query.filter_by(Name=new_category).first()
            if existing_category:
                category_id = existing_category.CategoryID
            else:
                category = ServiceCategory(Name=new_category)
                db.session.add(category)
                db.session.commit()
                category_id = category.CategoryID

        # Handle new service
        if new_service:
            existing_service = Service.query.filter_by(ServiceName=new_service).first()
            if existing_service:
                service_id = existing_service.ServiceID
            else:
                service = Service(
                    ServiceName=new_service,
                    BasePrice=base_price,
                    TimeRequired=time_required,
                    CategoryID=category_id,
                    Pincode=pincode
                )
                db.session.add(service)
                db.session.commit()
                service_id = service.ServiceID

        service_request = ServiceRequest(
            ServiceID=service_id,
            CategoryID=category_id,
            ProblemDescription=problem_description,
            CustomerID=user_id,
            DateOfRequest=datetime.utcnow()
        )
        db.session.add(service_request)
        db.session.commit()

        flash("Service request added successfully")
        return redirect(url_for("view_service_requests"))

    services = Service.query.all()
    categories = ServiceCategory.query.all()
    return render_template("service_request/add.html", services=services, categories=categories, user=user)

@app.route("/service_request/edit/<int:request_id>", methods=["GET", "POST"])
@auth_required
def edit_service_request(request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)
    if service_request.CustomerID != session["user_id"]:
        flash("You do not have permission to edit this service request")
        return redirect(url_for("view_service_requests"))

    if request.method == "POST":
        service_request.ServiceID = request.form.get("service_id")
        service_request.service.BasePrice = request.form.get("base_price")
        service_request.service.TimeRequired = request.form.get("time_required")
        service_request.service.Pincode = request.form.get("pincode")
        service_request.ProblemDescription = request.form.get("problem_description")
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
    elif session.get("role") == "professional":
        service_requests = ServiceRequest.query.filter_by(ProfessionalID=session["user_id"]).all()
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

@app.route("/approve_professional/<int:user_id>", methods=["POST"])
@admin_required
def approve_professional(user, user_id):
    professional = User.query.get_or_404(user_id)
    if professional.isProfessional and not professional.isApproved:
        professional.isApproved = True
        db.session.commit()
        flash("Professional approved successfully", "success")
    else:
        flash("Invalid operation", "danger")
    return redirect(url_for("approve_professionals"))

@app.route("/edit_user/<int:user_id>", methods=["GET", "POST"])
@admin_required
def edit_user(user, user_id):
    user_to_edit = User.query.get_or_404(user_id)
    if request.method == "POST":
        user_to_edit.Username = request.form.get("username")
        user_to_edit.Name = request.form.get("name")
        user_to_edit.Email = request.form.get("email")
        role = request.form.get("role")
        user_to_edit.isAdmin = role == "admin"
        user_to_edit.isProfessional = role == "professional"
        user_to_edit.isCustomer = role == "customer"
        user_to_edit.isApproved = request.form.get("isApproved") == "true"
        db.session.commit()

        flash("User updated successfully")
        return redirect(url_for("view_users"))

    return render_template("admin/edit_users.html", user_to_edit=user_to_edit, user=user)


@app.route("/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user,user_id):
    user_to_delete = User.query.get_or_404(user_id)
    db.session.delete(user_to_delete)
    db.session.commit()

    flash("User deleted successfully")
    return redirect(url_for("view_users"))

@app.route("/export_csv")
@auth_required
def export_csv():
    user_id = session["user_id"]
    user = User.query.get(user_id)

    if user.isCustomer:
        transactions = Transaction.query.filter_by(UserID=user_id).all()
    elif user.isProfessional:
        transactions = Transaction.query.join(Order).join(Service).filter(Service.ProfessionalID == user_id).all()
    else:
        flash("You do not have permission to access this page")
        return redirect(url_for("index"))

    output = []
    output.append(['Transaction ID', 'Service Name', 'Quantity', 'Unit Price', 'Total Price', 'Timestamp'])

    for transaction in transactions:
        for order in transaction.orders:
            output.append([
                transaction.TransactionID,
                order.service.ServiceName,
                order.Quantity,
                order.UnitPrice,
                order.TotalPrice,
                transaction.Timestamp.strftime('%d %b %Y, %I:%M %p')
            ])

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerows(output)
    response = make_response(si.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=orders.csv'
    response.headers["Content-type"] = "text/csv"
    return response

@app.route("/accept_service_request/<int:request_id>", methods=["POST"])
@auth_required
def accept_service_request(request_id):
    user_id = session["user_id"]
    user = User.query.get(user_id)
    if not user.isProfessional or not user.isApproved:
        flash("You do not have permission to accept this service request")
        return redirect(url_for("search_services"))

    service_request = ServiceRequest.query.get_or_404(request_id)
    if service_request.Status == 'requested':
        service_request.ProfessionalID = user_id
        service_request.Status = 'assigned'
        db.session.commit()
        flash("Service request accepted successfully")
    else:
        flash("Service request not found or already assigned")
    return redirect(url_for("search_services"))

@app.route("/complete_service_request/<int:request_id>", methods=["POST"])
@auth_required
def complete_service_request(request_id):
    user_id = session["user_id"]
    user = User.query.get(user_id)
    if not user.isProfessional or not user.isApproved:
        flash("You do not have permission to complete this service request")
        return redirect(url_for("view_service_requests"))

    service_request = ServiceRequest.query.get_or_404(request_id)
    if service_request.ProfessionalID == user_id and service_request.Status == 'assigned':
        service_request.Status = 'closed'
        service_request.DateOfCompletion = datetime.utcnow()
        db.session.commit()
        flash("Service request marked as completed")
    else:
        flash("You do not have permission to complete this service request")
    return redirect(url_for("view_service_requests"))

@app.route("/orders")
@auth_required
def orders():
    user_id = session["user_id"]
    transactions = Transaction.query.filter_by(UserID=user_id).order_by(Transaction.Timestamp.desc()).all()
    return render_template('orders.html', transactions=transactions)

@app.route("/rate_professional/<int:request_id>", methods=["POST"])
@auth_required
def rate_professional(request_id):
    rating = request.form.get("rating")
    service_request = ServiceRequest.query.get_or_404(request_id)
    if service_request.Status == 'closed':
        professional = User.query.get(service_request.ProfessionalID)
        if professional:
            professional.Rating = (professional.Rating + float(rating)) / 2
            db.session.commit()
            flash("Professional rated successfully")
        else:
            flash("Professional not found")
    else:
        flash("Service request is not closed")
    return redirect(url_for("orders"))
