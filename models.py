from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from app import app

db = SQLAlchemy(app)

# User model for all types of users (admin, customer, professional)
class User(db.Model):
    """
    Represents a user in the system (admin, customer, or service professional).
    """
    __tablename__ = 'user'
    UserID = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(50), unique=True, index=True, nullable=False)
    Passhash = db.Column(db.String(256), nullable=False)
    Name = db.Column(db.String(100), nullable=False)
    Email = db.Column(db.String(100), unique=True, index=True, nullable=False)
    Phone = db.Column(db.String(15), nullable=True)
    isAdmin = db.Column(db.Boolean, nullable=False, default=False)
    isCustomer = db.Column(db.Boolean, nullable=False, default=False)
    isProfessional = db.Column(db.Boolean, nullable=False, default=False)
    Address = db.Column(db.String(200), nullable=True)
    Pincode = db.Column(db.String(6), nullable=True, index=True)
    Experience = db.Column(db.String(100), nullable=True)
    Profession = db.Column(db.String(100), nullable=True)
    Reviews = db.Column(db.Text, nullable=True)
    Rating = db.Column(db.Float)

    def set_password(self, password):
        """Hash and set the user's password."""
        self.Passhash = generate_password_hash(password)

    def check_password(self, password):
        """Check the user's password."""
        return check_password_hash(self.Passhash, password)

    def __repr__(self):
        return f'<User {self.Username}>'

class ServiceCategory(db.Model):
    """
    Represents categories for grouping services.
    """
    __tablename__ = 'service_category'
    CategoryID = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(100), unique=True, nullable=False)
    Description = db.Column(db.Text, nullable=True)
    services = db.relationship('Service', backref='category', lazy=True)

    def __repr__(self):
        return f'<ServiceCategory {self.Name}>'


# Service model for available household services
class Service(db.Model):
    """
    Represents a household service provided on the platform.
    """
    __tablename__ = 'service'
    ServiceID = db.Column(db.Integer, primary_key=True)
    ServiceName = db.Column(db.String(100), nullable=False, unique=True)
    Description = db.Column(db.Text, nullable=True)
    BasePrice = db.Column(db.Float, nullable=False)
    TimeRequired = db.Column(db.Integer, nullable=False)
    CategoryID = db.Column(db.Integer, db.ForeignKey('service_category.CategoryID'), nullable=True)
    Pincode = db.Column(db.String(6), nullable=False, index=True)

    def __repr__(self):
        return f'<Service {self.ServiceName}>'


# ServiceRequest model for tracking customer service requests
class ServiceRequest(db.Model):
    """
    Represents a service request made by a customer and assigned to a professional.
    """
    __tablename__ = 'service_request'
    RequestID = db.Column(db.Integer, primary_key=True)
    ServiceID = db.Column(db.Integer, db.ForeignKey('service.ServiceID'), nullable=False)
    CategoryID = db.Column(db.Integer, db.ForeignKey('service_category.CategoryID'), nullable=False)
    CustomerID = db.Column(db.Integer, db.ForeignKey('user.UserID'), nullable=False)
    ProfessionalID = db.Column(db.Integer, db.ForeignKey('user.UserID'), nullable=True)  # Assigned professional
    DateOfRequest = db.Column(db.Date, nullable=False)
    DateOfCompletion = db.Column(db.Date, nullable=True)
    CreatedAt = db.Column(db.DateTime, default=db.func.now())
    UpdatedAt = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())
    Status = db.Column(
        db.Enum('requested', 'assigned', 'closed', name='request_status'),
        default='requested',
        nullable=False
    )
    ProblemDescription = db.Column(db.Text, nullable=True)
    Remarks = db.Column(db.Text, nullable=True)

    # Relationships
    service = db.relationship('Service', backref=db.backref('service_requests', cascade='all, delete', lazy=True))
    category = db.relationship('ServiceCategory', backref=db.backref('service_requests', lazy=True))
    customer = db.relationship('User', foreign_keys=[CustomerID], backref=db.backref('customer_requests', lazy=True))
    professional = db.relationship('User', foreign_keys=[ProfessionalID], backref=db.backref('assigned_requests', lazy=True))

    def __repr__(self):
        return f'<ServiceRequest {self.RequestID}>'


# Transaction model for storing transaction details
class Transaction(db.Model):
    """
    Represents a transaction for a customer.
    """
    __tablename__ = 'transaction'
    TransactionID = db.Column(db.Integer, primary_key=True)
    UserID = db.Column(db.Integer, db.ForeignKey('user.UserID'), nullable=False)
    Timestamp = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    TotalAmount = db.Column(db.Float, nullable=False)

    # Relationships
    user = db.relationship('User', backref=db.backref('transactions', lazy=True))

    def __repr__(self):
        return f'<Transaction {self.TransactionID}>'


# Order model for storing order details
class Order(db.Model):
    """
    Represents an individual order linked to a transaction and a service.
    """
    __tablename__ = 'order'
    OrderID = db.Column(db.Integer, primary_key=True)
    TransactionID = db.Column(db.Integer, db.ForeignKey('transaction.TransactionID'), nullable=False)
    ServiceID = db.Column(db.Integer, db.ForeignKey('service.ServiceID'), nullable=False)
    Quantity = db.Column(db.Integer, nullable=False)
    UnitPrice = db.Column(db.Float, nullable=False)
    TotalPrice = db.Column(db.Float, nullable=False)

    # Relationships
    transaction = db.relationship('Transaction', backref=db.backref('orders', lazy=True, cascade='all, delete-orphan'))
    service = db.relationship('Service', backref=db.backref('orders', lazy=True))

    def __repr__(self):
        return f'<Order {self.OrderID}>'


# FlaggedUser model for tracking flagged users
class FlaggedUser(db.Model):
    """
    Represents a flagged user for fraudulent activity or poor reviews.
    """
    __tablename__ = 'flagged_user'
    FlaggedUserID = db.Column(db.Integer, primary_key=True)
    UserID = db.Column(db.Integer, db.ForeignKey('user.UserID'), nullable=False)
    Reason = db.Column(db.Text, nullable=False)

    # Relationships
    user = db.relationship('User', backref=db.backref('flagged_entries', lazy=True))

    def __repr__(self):
        return f'<FlaggedUser {self.FlaggedUserID}>'


# Initialize database and add admin user if not already present
with app.app_context():
    db.create_all()

    # Ensure an admin user exists
    if not User.query.filter_by(Username='admin', isAdmin=True).first():
        admin = User(
            Username='admin',
            Name='Administrator',
            Email='admin@example.com',
            isAdmin=True
        )
        admin.set_password('admin')  # Set default admin password
        db.session.add(admin)
        db.session.commit()
