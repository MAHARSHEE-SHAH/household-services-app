from sqlite3 import IntegrityError
from flask import Flask, render_template, request, redirect, url_for, abort,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps
from datetime import datetime
from flask_migrate import Migrate
import os
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'any_key'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True)
    phone_number = db.Column(db.String(15))
    address = db.Column(db.String(200))
    full_name = db.Column(db.String(100))
    pin_code = db.Column(db.String(10))
    service_name = db.Column(db.String(100))  
    experience = db.Column(db.Integer)  

    def __repr__(self):
        return f'<User {self.username}>'

class Service(db.Model):
    __tablename__ = 'services'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    category = db.Column(db.String(50)) 

    def __repr__(self):
        return f'<Service {self.name}>'
class ServiceRequest(db.Model):
    __tablename__ = 'service_requests'

    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id', ondelete='SET NULL'), nullable=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    date_of_request = db.Column(db.DateTime, default=datetime.utcnow)
    completion_date = db.Column(db.DateTime)
    status = db.Column(db.String(20), default="requested")
    remarks = db.Column(db.String(200))
    rating = db.Column(db.Integer)
    review = db.Column(db.String(500))
    service = db.relationship('Service', backref='requests', passive_deletes=True)
    customer = db.relationship('User', foreign_keys=[customer_id], backref='customer_requests')
    professional = db.relationship('User', foreign_keys=[professional_id], backref='professional_requests')

    def __repr__(self):
        return f'<ServiceRequest {self.id} - Status: {self.status}>'
@app.before_first_request
def create_default_admin():
    if not User.query.filter_by(role="Admin").first():
        admin_user = User(username="admin", password="1234", role="Admin")
        db.session.add(admin_user)
        db.session.commit()
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'Admin':
            abort(403) 
        return f(*args, **kwargs)
    return decorated_function

def professional_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'Professional':
            abort(403) 
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

        if User.query.filter_by(username=username).first():
            return "Username already exists!"
        
        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username, password=password).first()

        if user:
            login_user(user)
            if user.role == "Admin":
                return redirect(url_for('admin_dashboard'))
            elif user.role == "Professional":
                return redirect(url_for('professional_dashboard'))
            elif user.role == "Customer":
                return redirect(url_for('customer_dashboard'))
        else:
            return "Invalid login credentials", 401 

    return render_template('login.html')


@app.route('/customer_signup', methods=['GET', 'POST'])
def customer_signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        address = request.form.get('address')
        pin_code = request.form.get('pin_code')

        if User.query.filter_by(username=username).first():
            return "Username already exists!", 400
        if User.query.filter_by(email=email).first():
            return "Email already exists!", 400
        new_user = User(
            username=username, password=password, role="Customer", 
            full_name=full_name, email=email, phone_number=phone_number,
            address=address, pin_code=pin_code
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('customer_signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'Admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'Professional':
        return redirect(url_for('professional_dashboard'))
    elif current_user.role == 'Customer':
        return redirect(url_for('customer_dashboard'))
    return redirect(url_for('home'))

@login_required
def list_services():
    services = Service.query.all()
    return render_template('admin_dashboard.html', services=services)

@app.route('/add_service', methods=['GET', 'POST'])
@login_required
def add_service():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')

        new_service = Service(name=name, description=description, price=price)
        db.session.add(new_service)

        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return render_template('add_service.html')


@app.route('/edit_service/<int:service_id>', methods=['GET', 'POST'])
@admin_required
def edit_service(service_id):
    service = Service.query.get_or_404(service_id)
    if request.method == 'POST':
        service.name = request.form.get('name')
        service.price = request.form.get('price')
        service.description = request.form.get('description')
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    
    return render_template('edit_service.html', service=service)
@app.route('/delete_service/<int:service_id>', methods=['POST'])
@admin_required
def delete_service(service_id):
    service = Service.query.get_or_404(service_id)

    
    ServiceRequest.query.filter_by(service_id=service_id).update({'service_id': None})
    db.session.commit()  
    db.session.delete(service)
    db.session.commit()
    
    flash("Service and associated requests updated successfully.", "success")
    return redirect(url_for('list_services'))


@app.route('/create_request', methods=['GET', 'POST'])
@login_required
def create_request():
    if current_user.role != 'Customer':
        abort(403) 

    if request.method == 'POST':
        service_id = request.form.get('service_id')
        remarks = request.form.get('remarks')

       
        new_request = ServiceRequest(service_id=service_id, customer_id=current_user.id, remarks=remarks)
        db.session.add(new_request)
        db.session.commit()
        return redirect(url_for('dashboard'))
    
    services = Service.query.all()
    return render_template('create_request.html', services=services)
@app.route('/view_requests')
@login_required
@professional_required
def view_requests():
    
    available_requests = (
        ServiceRequest.query
        .join(Service, ServiceRequest.service_id == Service.id)
        .filter(
            Service.name == current_user.service_name,
            ServiceRequest.status == "requested"
        )
        .all()
    )
    return render_template('view_requests.html', requests=available_requests)


@app.route('/admin_view_requests')
@login_required
@admin_required
def admin_view_requests():
   
    all_requests = ServiceRequest.query.all()
    return render_template('admin_view_requests.html', requests=all_requests)

@app.route('/accept_request/<int:request_id>', methods=['POST'])
@login_required
@professional_required
def accept_request(request_id):
    
    service_request = ServiceRequest.query.get_or_404(request_id)

    
    if service_request.status == 'requested':
        service_request.status = 'accepted'
        service_request.professional_id = current_user.id  
        db.session.commit()
        flash("Service request accepted successfully.", "success")

    return redirect(url_for('professional_dashboard'))

@app.route('/reject_request/<int:request_id>', methods=['POST'])
@login_required
@professional_required
def reject_request(request_id):

    service_request = ServiceRequest.query.get_or_404(request_id)

    
    if service_request.status == 'requested':
        service_request.status = 'rejected'
        db.session.commit()
        flash("Service request rejected successfully.", "danger")

    return redirect(url_for('professional_dashboard'))
        

@app.route('/view_customer_requests')
@login_required
def view_customer_requests():
    if current_user.role != 'Customer':
        abort(403)  
    
    requests = ServiceRequest.query.filter_by(customer_id=current_user.id).all()
    return render_template('view_customer_requests.html', requests=requests)
@app.route('/my_requests')
@login_required
@professional_required
def my_requests():
    
    requests = ServiceRequest.query.filter_by(professional_id=current_user.id).all()
    return render_template('my_requests.html', requests=requests)
@app.route('/complete_request/<int:request_id>', methods=['POST'])
@login_required
@professional_required
def complete_request(request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)


    if service_request.status != 'completed':
        service_request.status = 'completed'
        service_request.completion_date = datetime.utcnow()
        db.session.commit()
    return redirect(url_for('my_requests'))
@app.route('/add_review/<int:request_id>', methods=['GET', 'POST'])
@login_required
def add_review(request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)
    if service_request.status == 'completed' and service_request.customer_id == current_user.id and not service_request.rating:
        if request.method == 'POST':
            service_request.rating = request.form.get('rating')
            service_request.review = request.form.get('review')
            db.session.commit()
            return redirect(url_for('view_customer_requests'))
        return render_template('add_review.html', request=service_request)
    return redirect(url_for('view_customer_requests'))

@app.route('/search_services', methods=['GET', 'POST'])
@login_required
def search_services():
    if current_user.role != 'Customer':
        abort(403)
    
    services = []
    if request.method == 'POST':
        query = request.form.get('query')
     
        services = Service.query.filter(
            (Service.name.ilike(f'%{query}%')) |
            (Service.description.ilike(f'%{query}%'))
        ).all()
    else:
        services=Service.query.all()
    
    return render_template('search_services.html', services=services)
@app.route('/admin_summary')
@login_required
@admin_required
def admin_summary():
    professionals = User.query.filter_by(role="Professional").all()
    summary_data = []

    for professional in professionals:
        completed_requests = ServiceRequest.query.filter_by(professional_id=professional.id, status="completed").all()
        total_services = len(completed_requests)
        average_rating = sum([req.rating for req in completed_requests if req.rating]) / total_services if total_services else 0

        summary_data.append({
            "name": professional.username,
            "total_services": total_services,
            "average_rating": round(average_rating, 2) if average_rating else "No Ratings"
        })

    return render_template('admin_summary.html', summary_data=summary_data)

@app.route('/professional_summary')
@login_required
@professional_required
def professional_summary():
    professional_id = current_user.id
    completed_requests = ServiceRequest.query.filter_by(professional_id=professional_id, status="completed").all()
    total_services = len(completed_requests)
    average_rating = sum(req.rating for req in completed_requests if req.rating) / total_services if total_services else 0
    summary_data = {"total_services": total_services, "average_rating": round(average_rating, 2) if average_rating else "No Ratings"}

    return render_template('professional_summary.html', summary_data=summary_data)
@app.route('/customer_summary')
@login_required
def customer_summary():
    if current_user.role != 'Customer':
        abort(403)  
   
    customer_requests = ServiceRequest.query.filter_by(customer_id=current_user.id).all()
    total_requests = len(customer_requests)
    completed_requests = [req for req in customer_requests if req.status == 'completed']
    average_rating = sum(req.rating for req in completed_requests if req.rating) / len(completed_requests) if completed_requests else 0

    summary_data = {
        "total_requests": total_requests,
        "completed_requests": len(completed_requests),
        "average_rating": round(average_rating, 2) if average_rating else "No Ratings"
    }

    return render_template('customer_summary.html', summary_data=summary_data)
@app.route('/professional_search', methods=['GET', 'POST'])
@login_required
@professional_required
def professional_search():
    search_results = []
    if request.method == 'POST':
        query = request.form.get('query')
       
        search_results = ServiceRequest.query.filter(
            ServiceRequest.professional_id == current_user.id,
            ServiceRequest.remarks.ilike(f"%{query}%")
        ).all()

    return render_template('professional_search.html', results=search_results)

@app.route('/professional_signup', methods=['GET', 'POST'])
def professional_signup():
   
    available_services = Service.query.all()
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        full_name = request.form.get('full_name')
        service_name = request.form.get('service_name')
        experience = request.form.get('experience')
        document = request.files.get('document')
        address = request.form.get('address')
        pin_code = request.form.get('pin_code')

        
        upload_folder = 'uploads'
        os.makedirs(upload_folder, exist_ok=True)
        
        
        if document:
            document_filename = f"{username}_document.pdf" 
            document_path = os.path.join(upload_folder, document_filename)
            document.save(document_path)


        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Username already exists. Please choose a different one."

        
        new_professional = User(
            username=username,
            password=password,
            role="Professional",
            full_name=full_name,
            service_name=service_name,
            experience=int(experience) if experience else None,
            address=address,
            pin_code=pin_code
        )

        
        try:
            db.session.add(new_professional)
            db.session.commit()
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            return "An error occurred. Please try again with a different username."

    return render_template('professional_signup.html', available_services=available_services)


@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    services = Service.query.all()
    professionals = User.query.filter_by(role="Professional").all()
    service_requests = ServiceRequest.query.all()
    return render_template('admin_dashboard.html', services=services, professionals=professionals, service_requests=service_requests)

@app.route('/customer_dashboard')
@login_required
def customer_dashboard():
    if current_user.role != "Customer":
        abort(403)
    return render_template('customer_dashboard.html')

@app.route('/professional_dashboard')
@login_required
@professional_required
def professional_dashboard():
    
    assigned_requests = ServiceRequest.query.filter_by(
        service_id=current_user.service_name,
        status="requested"
    ).all()
    return render_template('professional_dashboard.html', assigned_requests=assigned_requests)



@app.route('/admin_search', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_search():
    results = []
    search_term = None
    category = None
    
    if request.method == 'POST':
        search_term = request.form.get('search_term')
        category = request.form.get('category')

        if category == 'services':
            results = Service.query.filter(
                (Service.name.ilike(f'%{search_term}%')) |
                (Service.description.ilike(f'%{search_term}%'))
            ).all()
        elif category == 'users':
            results = User.query.filter(
                (User.username.ilike(f'%{search_term}%')) |
                (User.full_name.ilike(f'%{search_term}%')) |
                (User.email.ilike(f'%{search_term}%'))
            ).all()
        elif category == 'requests':
            results = ServiceRequest.query.filter(
                (ServiceRequest.remarks.ilike(f'%{search_term}%')) |
                (ServiceRequest.status.ilike(f'%{search_term}%'))
            ).all()
        else:
                results = ServiceRequest.query.all()
    return render_template(
        'admin_search.html',
        results=results,
        search_term=search_term,
        category=category
    )

@app.route('/approve_professional/<int:professional_id>', methods=['POST'])
@login_required
@admin_required
def approve_professional(professional_id):
    professional = User.query.get_or_404(professional_id)
    professional.status = "approved" 
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/reject_professional/<int:professional_id>', methods=['POST'])
@login_required
@admin_required
def reject_professional(professional_id):
    professional = User.query.get_or_404(professional_id)
    professional.status = "rejected" 
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/delete_item/<string:item_type>/<int:item_id>', methods=['POST'])
@login_required
@admin_required
def delete_item(item_type, item_id):
    if item_type == 'professional':
        item = User.query.get_or_404(item_id)
    elif item_type == 'service':
        item = Service.query.get_or_404(item_id)
    else:
        abort(404)
    
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    if request.method == 'POST':
        password = request.form.get('password')
        
        if password == current_user.password: 
            db.session.delete(current_user)
            db.session.commit()
            logout_user()
            flash("Your account has been deleted successfully.", "success")
            return redirect(url_for('home'))
        else:
            flash("Incorrect password. Account not deleted.", "danger")
            return redirect(url_for('delete_account'))
    

    return render_template('confirm_delete.html')
@app.route('/confirm_delete_account', methods=['GET', 'POST'])
@login_required
def confirm_delete_account():
    if request.method == 'POST':
        password = request.form.get('password')
        if password != current_user.password:  
            flash("Incorrect password. Please try again.", "danger")  
            return redirect(url_for('confirm_delete_account'))
            
       
        db.session.delete(current_user)
        db.session.commit()
        logout_user()
        flash("Account successfully deleted.", "success")
        return redirect(url_for('home'))        
    return render_template('confirm_delete.html')
@app.route('/confirm_delete_professional/<int:professional_id>', methods=['GET', 'POST'])
@admin_required
def confirm_delete_professional(professional_id):
    professional = User.query.get_or_404(professional_id)
    if request.method == 'POST':
        db.session.delete(professional)
        db.session.commit()
        flash(f"Professional {professional.full_name} deleted successfully.", "success")
        return redirect(url_for('admin_dashboard'))
    return render_template('confirm_delete_professional.html', professional=professional)
@app.route('/confirm_delete_service/<int:service_id>', methods=['POST'])
@admin_required
def confirm_delete_service(service_id):
    service = Service.query.get_or_404(service_id)

    
    ServiceRequest.query.filter_by(service_id=service_id).update({'service_id': None})
    db.session.commit()

    db.session.delete(service)
    db.session.commit()

    flash(f"Service '{service.name}' has been deleted successfully.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/')
def home():
    return render_template('home.html')

migrate = Migrate(app, db)

if __name__ == '__main__':
    app.run(debug=True)

