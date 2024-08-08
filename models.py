from flask_sqlalchemy import SQLAlchemy
from app import app
from werkzeug.security import generate_password_hash,check_password_hash
db=SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'user'
    UserID = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(80), unique=True, nullable=False)
    Passhash = db.Column(db.String(256), nullable=False)
    Name = db.Column(db.String(100), nullable=False)
    Email = db.Column(db.String(120), unique=True, nullable=False)
    isAdmin = db.Column(db.Boolean, nullable=False, default=False)
    isSponsor = db.Column(db.Boolean, nullable=False, default=False)
    isInfluencer = db.Column(db.Boolean, nullable=False, default=False)
    CompanyName = db.Column(db.String(100))
    Industry = db.Column(db.String(100))
    Budget = db.Column(db.Float)
    Platform = db.Column(db.String(100))
    Handles = db.Column(db.String(100))
    Category = db.Column(db.String(100))
    Niche = db.Column(db.String(100))
    Reach = db.Column(db.Integer)

    def check_password(self, password):
        return check_password_hash(self.Passhash, password)

    def __repr__(self):
        return f'<User {self.Username}>'
    
class Campaign(db.Model):
    __tablename__ = 'campaign'
    CampaignID = db.Column(db.Integer, primary_key=True)
    SponsorID = db.Column(db.Integer, db.ForeignKey('user.UserID'), nullable=False)
    Name = db.Column(db.String(100), nullable=False)
    Description = db.Column(db.Text)
    StartDate = db.Column(db.Date)
    EndDate = db.Column(db.Date)
    Budget = db.Column(db.Float)
    Visibility = db.Column(db.String(10))  # 'public' or 'private'
    Goals = db.Column(db.Text)

    sponsor = db.relationship('User', backref=db.backref('campaigns', lazy=True), foreign_keys=[SponsorID])

    def __repr__(self):
        return f'<Campaign {self.Name}>'
    
class AdRequest(db.Model):
    __tablename__ = 'ad_request'
    AdRequestID = db.Column(db.Integer, primary_key=True)
    CampaignID = db.Column(db.Integer, db.ForeignKey('campaign.CampaignID'), nullable=False)
    InfluencerID = db.Column(db.Integer, db.ForeignKey('user.UserID'), nullable=False)
    Messages = db.Column(db.Text)
    Requirements = db.Column(db.Text)
    PaymentAmount = db.Column(db.Float)
    Status = db.Column(db.String(20))  # pending, accepted or rejected request

    campaign = db.relationship('Campaign', backref=db.backref('ad_requests', lazy=True))
    influencer = db.relationship('User', backref=db.backref('ad_requests', lazy=True), foreign_keys=[InfluencerID])

    def __repr__(self):
        return f'<AdRequest {self.AdRequestID}>'
    
class FlaggedUser(db.Model):
    __tablename__ = 'flagged_user'
    FlaggedUserID = db.Column(db.Integer, primary_key=True)
    UserID = db.Column(db.Integer, db.ForeignKey('user.UserID'), nullable=False)
    Reason = db.Column(db.Text)

    user = db.relationship('User', backref=db.backref('flagged_entries', lazy=True))

    def __repr__(self):
        return f'<FlaggedUser {self.FlaggedUserID}>'
    
with app.app_context():
    db.create_all()

    admin = User.query.filter_by(isAdmin=True).first()
    if not admin:
        password_hash = generate_password_hash('admin')
        new_admin = User(Username='admin', Passhash=password_hash, Name='admin', Email='admin@example.com', isAdmin=True)
        db.session.add(new_admin)
        db.session.commit()
    # Check if admin is already present in the database or not, if not, then add it to the database
