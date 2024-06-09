# Import necessary libraries and classes
from flask import Flask, render_template, request, redirect, url_for, flash, session
from passlib.hash import bcrypt
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
import os
from dotenv import load_dotenv
from model import Database, User, Contact
import cloudinary
from cloudinary.uploader import upload
from cloudinary.utils import cloudinary_url
from PIL import Image
import numpy as np
from tensorflow.keras.models import load_model
import datetime
from flask import jsonify

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# Configure Flask-Mail
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD')
)
mail = Mail(app)
db = Database()
s = URLSafeTimedSerializer(app.secret_key)

# Configure Cloudinary
cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET')
)

# Load the machine learning model
model = load_model("model/model_inception.h5")

# Helper function to get class label
def class_label(val):
    if val == 0:
        return "Diseased cotton leaf"
    elif val == 1:
        return "Diseased cotton plant"
    elif val == 2:
        return "Fresh cotton leaf"
    else:
        return "Fresh cotton plant"

# Helper function to preprocess image
def preprocess_image(image):
    np_image = Image.open(image)
    np_image = np_image.resize((224, 224))  # Resize the image to 224x224 pixels
    np_image = np.array(np_image).astype('float32') / 255
    np_image = np.expand_dims(np_image, axis=0)
    return np_image

@app.route('/', methods=['GET'])
def index():
    return render_template('home.html')

@app.route('/predict', methods=['GET', 'POST'])
def home():
    if 'username' in session:
        if request.method == 'POST':
            image = request.files['image']
            if image:
                # Save the image locally
                image_path = os.path.join('uploads', image.filename)
                image.save(image_path)

                # Delete the previous image from Cloudinary if it exists
                if 'last_public_id' in session:
                    try:
                        cloudinary.uploader.destroy(session['last_public_id'])
                    except cloudinary.exceptions.Error as e:
                        print(f"Failed to delete previous image: {e}")

                try:
                    # Upload the image to Cloudinary
                    upload_result = cloudinary.uploader.upload(image_path, timeout=60)
                    image_url = upload_result['secure_url']
                    public_id = upload_result['public_id']
                    
                    # Store the public_id of the uploaded image in the session
                    session['last_public_id'] = public_id
                except cloudinary.exceptions.Error as e:
                    print(f"Upload failed: {e}")
                    return "Image upload failed. Please try again."

                # Process the image for prediction
                processed_image = preprocess_image(image_path)
                prediction = model.predict(processed_image)
                class_index = np.argmax(prediction)
                predicted_label = class_label(class_index)

                # Save prediction details to the database
                

                # Delete the local image file
                os.remove(image_path)

                # Route to the appropriate HTML file based on prediction
                if predicted_label == "Fresh cotton plant":
                    return render_template('h_p.html', user_image=image_url, pred_output=predicted_label)
                elif predicted_label == "Fresh cotton leaf":
                    return render_template('h_l.html', user_image=image_url, pred_output=predicted_label)
                elif predicted_label == "Diseased cotton plant":
                    return render_template('d_p.html', user_image=image_url, pred_output=predicted_label)
                else:
                    return render_template('d_l.html', user_image=image_url, pred_output=predicted_label)
        return render_template('main.html')
    else:
        flash('Please login first', 'danger')
        return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if db.get_user_by_email(email):
            flash('Email address already exists.', 'danger')
            return redirect(url_for('signup'))

        user = User(username, email, password)
        db.insert_user(user)

        token = s.dumps(email, salt='email-confirm')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('email_template.html', confirm_url=confirm_url)
        msg = Message('Confirm Your Email', sender=os.getenv('MAIL_USERNAME'), recipients=[email])
        msg.body = 'Please click the link to confirm your email.'
        msg.html = html
        mail.send(msg)

        flash('A confirmation email has been sent to your email address.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        flash('You are already logged in.', 'info')
        if session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template("home.html")

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = db.get_user_by_email(email)
        if user:
            password_hash = user.get('password_hash')
            if password_hash:
                if bcrypt.verify(password, password_hash):
                    if user['is_verified']:
                        session['username'] = user['username']
                        session['is_admin'] = user['is_admin']
                        flash('Login successful.', 'success')
                        if user['is_admin']:
                            return redirect(url_for('admin_dashboard'))
                        else:
                            render_template('home.html')
                    else:
                        flash('Please verify your email before logging in.', 'danger')
                else:
                    flash('Invalid email or password.', 'danger')
            else:
                flash('Password hash not found.', 'danger')
        else:
            flash('User not found.', 'danger')

    return render_template('login.html')


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('signup'))

    user = db.get_user_by_email(email)
    if user:
        db.users_collection.update_one({'email': email}, {'$set': {'is_verified': True}})
        flash('Email confirmed. Please log in.', 'success')
    else:
        flash('Email confirmation failed. User does not exist.', 'danger')

    return redirect(url_for('login'))






@app.route('/contact')
def contact():
    if 'username' not in session:
        flash('Please log in to access the contact page.', 'danger')
        return redirect(url_for('login'))

    return render_template('contact.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

# User management routes
@app.route('/admin/dashboard', methods=['GET'])
def admin_dashboard():
    if 'username' not in session or not session.get('is_admin'):
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('login'))

    users = db.get_all_users()
    contacts = db.get_all_contacts()
    return render_template('admin_dashboard.html', users=users, contacts=contacts)

@app.route('/admin/user/add', methods=['GET', 'POST'])
def add_user():
    if 'username' not in session or not session.get('is_admin'):
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        is_admin = 'is_admin' in request.form

        if db.get_user_by_email(email):
            flash('Email address already exists.', 'danger')
            return redirect(url_for('add_user'))

        user = User(username, email, password, is_admin)
        db.insert_user(user)
        flash('User added successfully.', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('add_user.html')

@app.route('/admin/user/edit/<email>', methods=['GET', 'POST'])
def edit_user(email):
    if 'username' not in session or not session.get('is_admin'):
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('login'))

    user = db.get_user_by_email(email)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = 'is_admin' in request.form

        updated_user = User(username, email, password, is_admin)
        db.update_user(email, updated_user)
        flash('User updated successfully.', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_user.html', user=user)

@app.route('/admin/user/delete/<email>', methods=['POST'])
def delete_user(email):
    if 'username' not in session or not session.get('is_admin'):
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('login'))

    db.delete_user(email)
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

# Contact management routes
@app.route('/admin/contact/delete/<contact_id>', methods=['POST'])
def delete_contact(contact_id):
    if 'username' not in session or not session.get('is_admin'):
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('login'))

    db.delete_contact(contact_id)
    flash('Contact deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/contact/mark_seen/<contact_id>', methods=['POST'])
def mark_contact_seen(contact_id):
    if 'username' not in session or not session.get('is_admin'):
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('login'))

    db.mark_contact_as_seen(contact_id)
    contact = db.contacts_collection.find_one({'_id': contact_id})
    if contact:
        email = contact['email']
        msg = Message('Your contact message has been seen', sender=os.getenv('MAIL_USERNAME'), recipients=[email])
        msg.body = 'Your contact message has been reviewed by our team. Thank you for reaching out!'
        mail.send(msg)

    flash('Contact marked as seen and email sent successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
