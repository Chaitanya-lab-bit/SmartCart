# ---------------------------------------------------------
# SMARTCART - DAY 2
# Admin Registration + Email OTP + Password Hashing
# ---------------------------------------------------------

from flask import (
    Flask, render_template, request,
    redirect, session, flash, jsonify, url_for
)

from flask_mail import Mail, Message
import mysql.connector
import bcrypt
import secrets
import time
import config

import os
import razorpay

from werkzeug.utils import secure_filename
from PIL import Image, UnidentifiedImageError
from decimal import Decimal, InvalidOperation
from flask import make_response
from utils.pdf_generator import generate_pdf
# ---------------------------------------------------------
# FLASK CONFIGURATION
# ---------------------------------------------------------

app = Flask(__name__)
# Razorpay Client Initialization
razorpay_client = razorpay.Client(
    auth=(
        config.RAZORPAY_KEY_ID,
        config.RAZORPAY_KEY_SECRET
    )
)

app.secret_key = config.SECRET_KEY
# ==========================================
# DAY 4 - IMAGE UPLOAD CONFIGURATION
# ==========================================

# Define product image upload folder
UPLOAD_FOLDER = os.path.join(
    app.root_path,
    'static',
    'uploads',
    'product_images'
)
# Admin Profile Image Upload Folder
ADMIN_UPLOAD_FOLDER = os.path.join(
    app.root_path, 'static', 'uploads', 'admin_profiles'
)

os.makedirs(ADMIN_UPLOAD_FOLDER, exist_ok=True)

app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER

# Create folder automatically if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Configure upload folder
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Maximum upload size: 5 MB
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD

mail = Mail(app)


# ---------------------------------------------------------
# DATABASE CONNECTION
# ---------------------------------------------------------

def get_db_connection():

    conn = mysql.connector.connect(
        host=config.DB_HOST,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME
    )

    return conn


# ---------------------------------------------------------
# ROUTE 1: ADMIN SIGNUP
# ---------------------------------------------------------

@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    if request.method == 'GET':
        return render_template('admin/admin_signup.html')

    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip().lower()

    if not name or not email:
        flash("Name and email are required!", "danger")
        return redirect('/admin-signup')

    # Check duplicate email

    conn = get_db_connection()
    cursor = conn.cursor()

    try:

        cursor.execute(
            "SELECT admin_id FROM admin WHERE email = %s",
            (email,)
        )

        existing_admin = cursor.fetchone()

    finally:
        cursor.close()
        conn.close()

    if existing_admin:

        flash("Email already registered!", "danger")
        return redirect('/admin-signup')

    # Generate 6-digit OTP

    otp = str(secrets.randbelow(900000) + 100000)

    # Store temporary registration details

    session['signup_name'] = name
    session['signup_email'] = email
    session['otp'] = otp
    session['otp_expiry'] = time.time() + 300
    session['otp_attempts'] = 0

    # Send OTP through Gmail

    try:

        message = Message(
            subject="SmartCart Admin OTP",
            sender=config.MAIL_USERNAME,
            recipients=[email]
        )

        message.body = (
            f"Hello {name},\n\n"
            f"Your SmartCart registration OTP is: {otp}\n\n"
            "This OTP expires in 5 minutes."
        )

        mail.send(message)

        flash("OTP sent successfully!", "success")

        return redirect('/verify-otp')

    except Exception:

        session.clear()

        app.logger.exception("OTP email delivery failed")

        flash("Unable to send OTP. Check email configuration.", "danger")

        return redirect('/admin-signup')


# ---------------------------------------------------------
# ROUTE 2: OTP VERIFICATION
# ---------------------------------------------------------

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():

    if 'otp' not in session:
        flash("Please register first!", "danger")
        return redirect('/admin-signup')

    if request.method == 'GET':
        return render_template('admin/verify_otp.html')

    user_otp = request.form.get('otp', '').strip()
    password = request.form.get('password', '')

    # Check OTP expiry

    if time.time() > session.get('otp_expiry', 0):

        session.clear()

        flash("OTP expired. Please register again!", "danger")

        return redirect('/admin-signup')

    # Check OTP attempts

    if session.get('otp_attempts', 0) >= 5:

        session.clear()

        flash("Too many attempts. Please register again!", "danger")

        return redirect('/admin-signup')

    # Verify OTP

    if user_otp != session.get('otp'):

        session['otp_attempts'] += 1

        flash("Invalid OTP. Try again!", "danger")

        return redirect('/verify-otp')

    # Validate password

    if len(password) < 8 or len(password.encode('utf-8')) > 72:

        flash("Password must be at least 8 characters and no more than 72 bytes!", "danger")

        return redirect('/verify-otp')

    # Hash password using bcrypt

    hashed_password = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')

    # Insert admin into MySQL

    conn = get_db_connection()
    cursor = conn.cursor()

    try:

        cursor.execute(
            """
            INSERT INTO admin (name, email, password)
            VALUES (%s, %s, %s)
            """,

            (
                session['signup_name'],
                session['signup_email'],
                hashed_password
            )
        )

        conn.commit()

        # Clear temporary session data

        session.clear()

        flash("Admin registered successfully!", "success")

        return redirect('/admin-signup')

    except mysql.connector.IntegrityError:

        conn.rollback()

        session.clear()

        flash("This email is already registered!", "danger")

        return redirect('/admin-signup')

    finally:

        cursor.close()
        conn.close()


# ---------------------------------------------------------
# RUN APPLICATION
# ---------------------------------------------------------
# =====================================================
# DAY 3 - ROUTE 4: ADMIN LOGIN
# =====================================================

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    # Display login page
    if request.method == 'GET':
        return render_template('admin/admin_login.html')

    # Get email and password
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')

    # Connect to database
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:

        # Fetch admin using email
        cursor.execute(
            "SELECT * FROM admin WHERE email = %s",
            (email,)
        )

        admin = cursor.fetchone()

    finally:
        cursor.close()
        conn.close()

    # Check whether admin exists
    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    # Compare entered password with stored bcrypt hash
    stored_hash = admin['password'].encode('utf-8')

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):

        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    # Clear any previous session data
    session.clear()

    # Create admin session
    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']

    flash("Login successful!", "success")

    return redirect('/admin-dashboard')

# DAY 3 - ADMIN DASHBOARD

@app.route('/admin-dashboard')
def admin_dashboard():

    # Check whether admin is logged in
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template(
        'admin/dashboard.html',
        admin_name=session['admin_name']
    )
# DAY 3 - ADMIN LOGOUT

@app.route('/admin-logout', methods=['POST'])
def admin_logout():

    session.clear()

    flash("Logged out successfully!", "success")

    return redirect('/admin-login')
# Default Homepage
@app.route('/')
def home():
    return redirect('/admin-login')
# =====================================================
# DAY 4 - ROUTE 7: DISPLAY ADD PRODUCT PAGE
# =====================================================

@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    # Check whether admin is logged in
    if 'admin_id' not in session:

        flash("Please login first!", "danger")

        return redirect('/admin-login')

    # Display Add Product HTML page
    return render_template('admin/add_item.html')
# =====================================================
# DAY 4 - ROUTE 8: ADD PRODUCT INTO DATABASE
# =====================================================

from PIL import Image, UnidentifiedImageError
from decimal import Decimal, InvalidOperation


@app.route('/admin/add-item', methods=['POST'])
def add_item():

    # ---------------------------------------
    # STEP 1: Check Admin Session
    # ---------------------------------------

    if 'admin_id' not in session:

        flash("Please login first!", "danger")
        return redirect('/admin-login')

    # ---------------------------------------
    # STEP 2: Get Form Data
    # ---------------------------------------

    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    category = request.form.get('category', '').strip()
    price_input = request.form.get('price', '').strip()

    image_file = request.files.get('image')

    # ---------------------------------------
    # STEP 3: Validate Form Data
    # ---------------------------------------

    if not name or not description or not category or not price_input:

        flash("All fields are required!", "danger")
        return redirect('/admin/add-item')

    try:
        price = Decimal(price_input)

        if not price.is_finite() or price <= 0:
            raise InvalidOperation

    except InvalidOperation:

        flash("Please enter a valid product price!", "danger")
        return redirect('/admin/add-item')

    if image_file is None or image_file.filename == "":

        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    # ---------------------------------------
    # STEP 4: Validate Image
    # ---------------------------------------

    allowed_formats = {
        'JPEG': 'jpg',
        'PNG': 'png',
        'WEBP': 'webp',
        'GIF': 'gif'
    }

    try:

        image = Image.open(image_file.stream)

        image_format = image.format

        if image_format not in allowed_formats:
            flash("Only JPG, PNG, WEBP and GIF images are allowed!", "danger")
            return redirect('/admin/add-item')

        image.verify()

    except (UnidentifiedImageError, OSError, ValueError):

        flash("Invalid image file!", "danger")
        return redirect('/admin/add-item')

    # ---------------------------------------
    # STEP 5: Generate Secure Filename
    # ---------------------------------------

    safe_name = secure_filename(image_file.filename)

    if not safe_name:
        flash("Invalid image filename!", "danger")
        return redirect('/admin/add-item')

    extension = allowed_formats[image_format]

    original_name = os.path.splitext(safe_name)[0]

    filename = f"{secrets.token_hex(8)}_{original_name}.{extension}"

    # ---------------------------------------
    # STEP 6: Create Image Path
    # ---------------------------------------

    image_path = os.path.join(
        app.config['UPLOAD_FOLDER'],
        filename
    )

    # ---------------------------------------
    # STEP 7: Save Image
    # ---------------------------------------

    image_file.stream.seek(0)

    image_file.save(image_path)

    # ---------------------------------------
    # STEP 8: Insert Product Into MySQL
    # ---------------------------------------

    conn = None
    cursor = None

    try:

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO products
            (name, description, category, price, image)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (name, description, category, price, filename)
        )

        conn.commit()

        flash("Product added successfully!", "success")

    except mysql.connector.Error as e:

        if conn:
            conn.rollback()

        # Delete uploaded image if database insertion fails
        if os.path.exists(image_path):
            os.remove(image_path)

        print("Database Error:", e)

        flash("Unable to add product. Please try again!", "danger")

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()

    return redirect('/admin/add-item')
# =========================================================
# DAY 7: PRODUCT LIST + SEARCH + CATEGORY FILTER
# =========================================================

@app.route('/admin/item-list')
def item_list():

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    # Get search and category values
    search = request.args.get('search', '').strip()
    category_filter = request.args.get('category', '').strip()

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Fetch all unique categories
        cursor.execute("""
            SELECT DISTINCT category
            FROM products
            ORDER BY category
        """)

        categories = cursor.fetchall()

        # Base SQL query
        query = "SELECT * FROM products WHERE 1=1"
        params = []

        # Search by product name
        if search:
            query += " AND name LIKE %s"
            params.append("%" + search + "%")

        # Filter by category
        if category_filter:
            query += " AND category = %s"
            params.append(category_filter)

        # Display latest products first
        query += " ORDER BY product_id DESC"

        # Execute query
        cursor.execute(query, params)
        products = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories
    )

# =====================================================
# DAY 5 - ROUTE 10: VIEW SINGLE PRODUCT
# =====================================================

@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    # Step 1: Check admin session
    if 'admin_id' not in session:

        flash("Please login first!", "danger")
        return redirect('/admin-login')

    # Step 2: Connect to MySQL
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:

        # Step 3: Fetch product using ID
        cursor.execute(
            "SELECT * FROM products WHERE product_id = %s",
            (item_id,)
        )

        product = cursor.fetchone()

    finally:

        cursor.close()
        conn.close()

    # Step 4: Check whether product exists
    if product is None:

        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    # Step 5: Display product details
    return render_template(
        "admin/view_item.html",
        product=product
    )
# =========================================================
# DAY 7: DELETE PRODUCT + DELETE IMAGE
# =========================================================

@app.route('/admin/delete-item/<int:item_id>', methods=['POST'])
def delete_item(item_id):

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    image_name = None

    try:
        # Fetch product image
        cursor.execute(
            "SELECT image FROM products WHERE product_id = %s",
            (item_id,)
        )

        product = cursor.fetchone()

        if not product:
            flash("Product not found!", "danger")
            return redirect('/admin/item-list')

        image_name = product['image']

        # Delete product from MySQL
        cursor.execute(
            "DELETE FROM products WHERE product_id = %s",
            (item_id,)
        )

        conn.commit()

    except Exception as e:
        conn.rollback()
        print("Delete product error:", e)
        flash("Unable to delete product!", "danger")
        return redirect('/admin/item-list')

    finally:
        cursor.close()
        conn.close()

    # Delete image after successful database deletion
    if image_name:
        image_path = os.path.join(
            app.config['UPLOAD_FOLDER'],
            image_name
        )

        if os.path.exists(image_path):
            try:
                os.remove(image_path)
            except OSError as e:
                print("Image deletion error:", e)

    flash("Product deleted successfully!", "success")
    return redirect('/admin/item-list')
# =========================================================
# DAY 6: SHOW UPDATE PRODUCT FORM
# =========================================================

@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    # Check admin login
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    # Fetch existing product
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT * FROM products WHERE product_id = %s",
            (item_id,)
        )
        product = cursor.fetchone()

    finally:
        cursor.close()
        conn.close()

    # Check product exists
    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template(
        "admin/update_item.html",
        product=product
    )
# =========================================================
# DAY 6: UPDATE PRODUCT + OPTIONAL IMAGE REPLACEMENT
# =========================================================

@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    # Get form data
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    category = request.form.get('category', '').strip()
    price = request.form.get('price', '').strip()

    new_image = request.files.get('image')

    # Validate text fields
    if not name or not description or not category:
        flash("All product fields are required!", "danger")
        return redirect(f'/admin/update-item/{item_id}')

    # Validate price
    try:
        updated_price = Decimal(price)

        if not updated_price.is_finite() or updated_price <= 0:
            raise InvalidOperation

    except (InvalidOperation, ValueError):
        flash("Please enter a valid price!", "danger")
        return redirect(f'/admin/update-item/{item_id}')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    new_image_path = None

    try:
        # Fetch existing product
        cursor.execute(
            "SELECT * FROM products WHERE product_id = %s",
            (item_id,)
        )
        product = cursor.fetchone()

        if not product:
            flash("Product not found!", "danger")
            return redirect('/admin/item-list')

        old_image_name = product['image']
        final_image_name = old_image_name

        # Check whether a new image was uploaded
        if new_image and new_image.filename:

            # Validate image using Pillow
            try:
                new_image.stream.seek(0)
                image = Image.open(new_image.stream)
                image_format = image.format

                if image_format not in ['JPEG', 'PNG', 'WEBP', 'GIF']:
                    raise ValueError("Unsupported image format!")

                image.verify()

            except Exception:
                flash("Please upload a valid image!", "danger")
                return redirect(f'/admin/update-item/{item_id}')

            # Generate a unique filename
            extension = {
                'JPEG': '.jpg',
                'PNG': '.png',
                'WEBP': '.webp',
                'GIF': '.gif'
            }[image_format]

            final_image_name = secrets.token_hex(16) + extension

            # Save new image
            new_image_path = os.path.join(
                app.config['UPLOAD_FOLDER'],
                final_image_name
            )

            new_image.stream.seek(0)
            new_image.save(new_image_path)

        # Update MySQL record
        cursor.execute("""
            UPDATE products
            SET name = %s,
                description = %s,
                category = %s,
                price = %s,
                image = %s
            WHERE product_id = %s
        """, (
            name,
            description,
            category,
            updated_price,
            final_image_name,
            item_id
        ))

        conn.commit()

    except Exception as e:
        conn.rollback()

        # Remove newly uploaded image if database update fails
        if new_image_path and os.path.exists(new_image_path):
            os.remove(new_image_path)

        print("Product update error:", e)
        flash("Unable to update product!", "danger")
        return redirect(f'/admin/update-item/{item_id}')

    finally:
        cursor.close()
        conn.close()

    # Delete old image only after successful database update
    if new_image_path and old_image_name:
        old_image_path = os.path.join(
            app.config['UPLOAD_FOLDER'],
            old_image_name
        )

        if os.path.exists(old_image_path):
            try:
                os.remove(old_image_path)
            except OSError as e:
                print("Old image cleanup error:", e)

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')
# =========================================================
# DAY 8: DISPLAY ADMIN PROFILE
# =========================================================

@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT * FROM admin WHERE admin_id = %s",
            (admin_id,)
        )

        admin = cursor.fetchone()

    finally:
        cursor.close()
        conn.close()

    if not admin:
        flash("Admin account not found!", "danger")
        return redirect('/admin-login')

    return render_template(
        "admin/admin_profile.html",
        admin=admin
    )
# =========================================================
# DAY 8: UPDATE ADMIN PROFILE
# =========================================================

@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # Get form data
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    new_password = request.form.get('password', '')
    new_image = request.files.get('profile_image')

    if not name or not email:
        flash("Name and email are required!", "danger")
        return redirect('/admin/profile')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    new_image_path = None
    old_image_name = None

    try:
        # Fetch existing admin
        cursor.execute(
            "SELECT * FROM admin WHERE admin_id = %s",
            (admin_id,)
        )

        admin = cursor.fetchone()

        if not admin:
            flash("Admin account not found!", "danger")
            return redirect('/admin-login')

        old_image_name = admin['profile_image']

        # Keep old password unless a new one is entered
        if new_password:
            hashed_password = bcrypt.hashpw(
                new_password.encode('utf-8'),
                bcrypt.gensalt()
            )
        else:
            hashed_password = admin['password']

        # Keep old image unless a new one is uploaded
        final_image_name = old_image_name

        if new_image and new_image.filename:

            # Validate actual image content
            try:
                new_image.stream.seek(0)
                image = Image.open(new_image.stream)
                image_format = image.format

                if image_format not in ['JPEG', 'PNG', 'WEBP', 'GIF']:
                    raise ValueError("Unsupported image format")

                image.verify()

            except Exception:
                flash("Please upload a valid profile image!", "danger")
                return redirect('/admin/profile')

            # Generate unique filename
            extension = {
                'JPEG': '.jpg',
                'PNG': '.png',
                'WEBP': '.webp',
                'GIF': '.gif'
            }[image_format]

            final_image_name = secrets.token_hex(16) + extension

            # Save new image
            new_image_path = os.path.join(
                app.config['ADMIN_UPLOAD_FOLDER'],
                final_image_name
            )

            new_image.stream.seek(0)
            new_image.save(new_image_path)

        # Update database
        cursor.execute("""
            UPDATE admin
            SET name = %s,
                email = %s,
                password = %s,
                profile_image = %s
            WHERE admin_id = %s
        """, (
            name,
            email,
            hashed_password,
            final_image_name,
            admin_id
        ))

        conn.commit()

    except Exception as e:
        conn.rollback()

        # Remove new image if database update fails
        if new_image_path and os.path.exists(new_image_path):
            os.remove(new_image_path)

        print("Admin profile update error:", e)
        flash("Unable to update profile!", "danger")
        return redirect('/admin/profile')

    finally:
        cursor.close()
        conn.close()

    # Delete old image after successful database update
    if new_image_path and old_image_name:
        old_image_path = os.path.join(
            app.config['ADMIN_UPLOAD_FOLDER'],
            old_image_name
        )

        if os.path.exists(old_image_path):
            try:
                os.remove(old_image_path)
            except OSError as e:
                print("Old profile image deletion error:", e)

    # Update session information
    session['admin_name'] = name
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")

    return redirect('/admin/profile')
# ================= USER REGISTRATION =================

@app.route('/user-register', methods=['GET', 'POST'])
def user_register():

    if request.method == 'POST':

        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not name or not email or not password:
            flash("All fields are required!", "danger")
            return redirect('/user-register')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Check whether email already exists
            cursor.execute(
                "SELECT user_id FROM users WHERE email = %s",
                (email,)
            )
            existing_user = cursor.fetchone()

            if existing_user:
                flash("Email already registered!", "danger")
                return redirect('/user-register')

            # Hash password
            hashed_password = bcrypt.hashpw(
                password.encode('utf-8'),
                bcrypt.gensalt()
            )

            # Insert user
            cursor.execute(
                """
                INSERT INTO users (name, email, password)
                VALUES (%s, %s, %s)
                """,
                (name, email, hashed_password.decode('utf-8'))
            )

            conn.commit()

            flash("Registration successful! Please login.", "success")
            return redirect('/user-login')

        except Exception as e:
            conn.rollback()
            print("User Registration Error:", e)
            flash("Registration failed. Please try again.", "danger")

        finally:
            cursor.close()
            conn.close()

    return render_template('user/user_register.html')
# ================= USER LOGIN =================

@app.route('/user-login', methods=['GET', 'POST'])
def user_login():

    if request.method == 'POST':

        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not email or not password:
            flash("Email and password are required!", "danger")
            return redirect('/user-login')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Fetch user from database
            cursor.execute(
                "SELECT * FROM users WHERE email = %s",
                (email,)
            )

            user = cursor.fetchone()

            if user:
                stored_password = user['password']

                if isinstance(stored_password, str):
                    stored_password = stored_password.encode('utf-8')

                # Verify password
                if bcrypt.checkpw(
                    password.encode('utf-8'),
                    stored_password
                ):
                    session['user_id'] = user['user_id']
                    session['user_name'] = user['name']
                    session['user_email'] = user['email']

                    flash("Login successful!", "success")
                    return redirect('/user-dashboard')

            flash("Invalid email or password!", "danger")
            return redirect('/user-login')

        except Exception as e:
            print("User Login Error:", e)
            flash("Something went wrong. Please try again.", "danger")

        finally:
            cursor.close()
            conn.close()

    return render_template('user/user_login.html')
# ================= USER DASHBOARD =================

@app.route('/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    return render_template(
        'user/user_home.html',
        user_name=session['user_name']
    )
# ================= USER LOGOUT =================

@app.route('/user-logout', methods=['POST'])
def user_logout():

    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)

    flash("You have been logged out successfully!", "success")

    return redirect('/user-login')
# =====================================================
# DAY 10 - USER PRODUCT LISTING (SEARCH + CATEGORY FILTER)
# =====================================================

@app.route('/user/products')
def user_products():

    if 'user_id' not in session:
        flash("Please login to view products!", "danger")
        return redirect('/user-login')

    search = request.args.get('search', '').strip()
    category_filter = request.args.get('category', '').strip()

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT DISTINCT category
            FROM products
            WHERE category IS NOT NULL AND category != ''
            ORDER BY category
        """)

        categories = cursor.fetchall()

        query = "SELECT * FROM products WHERE 1=1"
        params = []

        if search:
            query += " AND name LIKE %s"
            params.append("%" + search + "%")

        if category_filter:
            query += " AND category = %s"
            params.append(category_filter)

        query += " ORDER BY product_id DESC"

        cursor.execute(query, params)
        products = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    # Calculate cart count
    cart = session.get('cart', {})

    cart_count = sum(
        item['quantity'] if isinstance(item, dict) else item
        for item in cart.values()
    )

    return render_template(
        'user/user_products.html',
        products=products,
        categories=categories,
        cart_count=cart_count
    )
# =====================================================
# DAY 10 - USER PRODUCT DETAILS
# =====================================================

@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):

    # Check user login
    if 'user_id' not in session:
        flash("Please login to view product details!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Fetch product using product ID
        cursor.execute(
            "SELECT * FROM products WHERE product_id = %s",
            (product_id,)
        )

        product = cursor.fetchone()

    finally:
        cursor.close()
        conn.close()

    # Check whether product exists
    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template(
        'user/product_details.html',
        product=product
    )
# =====================================================
# DAY 11.1 - ADD TO CART
# =====================================================
# =========================================================
# ROUTE: ADD PRODUCT TO CART (AJAX)
# =========================================================

@app.route('/user/add-to-cart/<int:pid>', methods=['POST'])
def add_to_cart(pid):

    if 'user_id' not in session:
        return jsonify({
            'success': False,
            'message': 'Please login first!'
        }), 401

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Fetch all product details
        cursor.execute("""
            SELECT product_id, name, price, image
            FROM products
        """)

        products = cursor.fetchall()

        # Create product lookup
        product_lookup = {
            str(product['product_id']): product
            for product in products
        }

        product_id = str(pid)

        if product_id not in product_lookup:
            return jsonify({
                'success': False,
                'message': 'Product not found!'
            }), 404

        product = product_lookup[product_id]

        # Get existing cart
        cart = session.get('cart', {})

        # Convert old integer-based cart items
        # into dictionary-based cart items
        for old_id, old_value in list(cart.items()):

            if isinstance(old_value, int):
                old_product = product_lookup.get(old_id)

                if old_product:
                    cart[old_id] = {
                        'name': old_product['name'],
                        'price': float(old_product['price']),
                        'image': old_product['image'],
                        'quantity': old_value
                    }
                else:
                    cart.pop(old_id)

        # Add or increase product quantity
        if product_id in cart:

            cart[product_id]['quantity'] += 1

        else:

            cart[product_id] = {
                'name': product['name'],
                'price': float(product['price']),
                'image': product['image'],
                'quantity': 1
            }

        # Save cart in session
        session['cart'] = cart
        session.modified = True

        # Calculate cart count
        cart_count = sum(
            item['quantity']
            for item in cart.values()
        )

        return jsonify({
            'success': True,
            'message': 'Product added to cart!',
            'cart_count': cart_count
        })

    except Exception as e:

        print("Add to Cart Error:", e)

        return jsonify({
            'success': False,
            'message': 'Unable to add product to cart!'
        }), 500

    finally:
        cursor.close()
        conn.close()

 # =========================================================
# ROUTE: USER CART PAGE
# =========================================================

@app.route('/user/cart')
def user_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})
    print("CURRENT CART DATA:", repr(cart), flush=True)
    print("CART TYPE:", type(cart), flush=True)

    grand_total = sum(
        float(item['price']) * item['quantity']
        for item in cart.values()
    )

    return render_template(
        'user/user_cart.html',
        cart=cart,
        grand_total=grand_total
    )
# =========================================================
# ROUTE: INCREASE CART QUANTITY
# =========================================================

@app.route('/user/cart/increase/<int:pid>')
def increase_cart(pid):

    if 'user_id' not in session:
        return redirect('/user-login')

    cart = session.get('cart', {})
    product_id = str(pid)

    if product_id in cart:
        cart[product_id]['quantity'] += 1

    session['cart'] = cart

    return redirect('/user/cart')
# =========================================================
# ROUTE: DECREASE CART QUANTITY
# =========================================================

@app.route('/user/cart/decrease/<int:pid>')
def decrease_cart(pid):

    if 'user_id' not in session:
        return redirect('/user-login')

    cart = session.get('cart', {})
    product_id = str(pid)

    if product_id in cart:

        cart[product_id]['quantity'] -= 1

        if cart[product_id]['quantity'] <= 0:
            cart.pop(product_id)

    session['cart'] = cart

    return redirect('/user/cart')
# =========================================================
# ROUTE: REMOVE ITEM FROM CART
# =========================================================

@app.route('/user/cart/remove/<int:pid>', methods=['POST'])
def remove_cart_item(pid):

    if 'user_id' not in session:
        return redirect('/user-login')

    cart = session.get('cart', {})
    product_id = str(pid)

    cart.pop(product_id, None)

    session['cart'] = cart

    flash("Product removed from cart!", "success")

    return redirect('/user/cart')
@app.route('/user/checkout-address', methods=['POST'])
def checkout_address():

    # Check user login
    if 'user_id' not in session:
        return redirect(url_for('user_login'))

    # Check cart
    cart = session.get('cart', {})

    if not cart:
        flash("Your cart is empty!", "error")
        return redirect(url_for('user_cart'))

    # Get address details
    full_name = request.form.get('full_name', '').strip()
    mobile = request.form.get('mobile', '').strip()
    address = request.form.get('address', '').strip()
    city = request.form.get('city', '').strip()
    state = request.form.get('state', '').strip()
    pincode = request.form.get('pincode', '').strip()

    # Validate fields
    if not all([full_name, mobile, address, city, state, pincode]):
        flash("Please fill all delivery address fields!", "error")
        return redirect(url_for('user_cart'))

    if not mobile.isdigit() or len(mobile) != 10:
        flash("Enter a valid 10-digit mobile number!", "error")
        return redirect(url_for('user_cart'))

    if not pincode.isdigit() or len(pincode) != 6:
        flash("Enter a valid 6-digit PIN code!", "error")
        return redirect(url_for('user_cart'))

    # Store address in session
    session['delivery_address'] = {
        'full_name': full_name,
        'mobile': mobile,
        'address': address,
        'city': city,
        'state': state,
        'pincode': pincode
    }

    flash("Delivery address saved successfully!", "success")

    return redirect(url_for('pay')) 
@app.route('/user/pay')
def pay():

    # Check user login
    if 'user_id' not in session:
        return redirect(url_for('user_login'))

    # Get cart and delivery address
    cart = session.get('cart', {})
    delivery_address = session.get('delivery_address')

    if not cart:
        flash("Your cart is empty!", "error")
        return redirect(url_for('user_cart'))

    if not delivery_address:
        flash("Please enter your delivery address!", "error")
        return redirect(url_for('user_cart'))

    try:
        # Calculate total amount in paise
        total_amount = sum(
            int(Decimal(str(item['price'])) * item['quantity'] * 100)
            for item in cart.values()
        )

        if total_amount <= 0:
            flash("Invalid payment amount!", "error")
            return redirect(url_for('user_cart'))

        # Create Razorpay order
        order_data = {
            "amount": total_amount,
            "currency": "INR",
            "receipt": "smartcart_" + secrets.token_hex(8)
        }

        razorpay_order = razorpay_client.order.create(
            data=order_data
        )
        # Store Razorpay order ID in session
        session['razorpay_order_id'] = razorpay_order['id']

        # Open payment page
        return render_template(
            'user/payment.html',
            order_id=razorpay_order['id'],
            amount=total_amount,
            key_id=config.RAZORPAY_KEY_ID
        )

    except Exception as e:
        print("Razorpay Order Error:", e)
        flash("Unable to create payment order. Please try again.", "error")
        return redirect(url_for('user_cart'))
@app.route('/verify-payment', methods=['POST'])
def verify_payment():

    if 'user_id' not in session:
        return "Please login first.", 401

    # Receive payment details from Razorpay Checkout
    payment_id = request.form.get('razorpay_payment_id')
    order_id = request.form.get('razorpay_order_id')
    signature = request.form.get('razorpay_signature')

    if not payment_id or not order_id or not signature:
        return "Incomplete payment response.", 400

    # Confirm this is the order created for this user's session
    if order_id != session.get('razorpay_order_id'):
        return "Invalid order ID.", 400

    cart = session.get('cart', {})
    address = session.get('delivery_address', {})

    if not cart or not address:
        return "Cart or delivery address is missing.", 400

    conn = None
    cursor = None

    try:
        # 1. Verify Razorpay payment signature
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        })

        # 2. Fetch payment details from Razorpay
        payment = razorpay_client.payment.fetch(payment_id)

        if payment['order_id'] != order_id:
            return "Payment order mismatch.", 400

        if payment['status'] != 'captured':
            return "Payment has not been captured.", 400

        # 3. Connect to database
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Prevent duplicate order creation
        cursor.execute(
            "SELECT order_id FROM orders WHERE razorpay_order_id = %s",
            (order_id,)
        )

        existing_order = cursor.fetchone()

        if existing_order:
            return redirect(
                url_for('order_success',
                        order_db_id=existing_order['order_id'])
            )

        # 4. Fetch current product prices from database
        order_products = []
        total_amount = Decimal('0.00')

        for product_id, item in cart.items():

            cursor.execute(
                "SELECT product_id, name, price FROM products WHERE product_id = %s",
                (int(product_id),)
            )

            product = cursor.fetchone()

            if not product:
                return "A product in your cart is no longer available.", 400

            quantity = int(item['quantity'])

            if quantity < 1:
                return "Invalid product quantity.", 400

            price = Decimal(str(product['price']))
            total_amount += price * quantity

            order_products.append({
                'product_id': product['product_id'],
                'name': product['name'],
                'price': price,
                'quantity': quantity
            })

        # Compare the actual Razorpay payment amount with database total
        expected_amount = int(total_amount * 100)

        if payment['amount'] != expected_amount:
            return "Payment amount does not match the order total.", 400

        # 5. Save order and order items in one transaction
        

        cursor.execute("""
            INSERT INTO orders (
                user_id, razorpay_order_id, razorpay_payment_id,
                amount, payment_status, full_name, mobile,
                address, city, state, pincode
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            session['user_id'],
            order_id,
            payment_id,
            total_amount,
            'Paid',
            address['full_name'],
            address['mobile'],
            address['address'],
            address['city'],
            address['state'],
            address['pincode']
        ))

        order_db_id = cursor.lastrowid

        for item in order_products:
            cursor.execute("""
                INSERT INTO order_items (
                    order_id, product_id, product_name,
                    quantity, price
                )
                VALUES (%s, %s, %s, %s, %s)
            """, (
                order_db_id,
                item['product_id'],
                item['name'],
                item['quantity'],
                item['price']
            ))

        conn.commit()

        # 6. Clear cart only after successful database commit
        session.pop('cart', None)
        session.pop('delivery_address', None)
        session.pop('razorpay_order_id', None)

        return redirect(
            url_for('order_success', order_db_id=order_db_id)
        )

    except Exception as e:

        if conn:
            conn.rollback()

        print("Payment verification error:", str(e))
        return "Payment verification failed. Please contact support.", 400

    finally:
        if cursor:
            cursor.close()

        if conn:
            conn.close()
@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):

    if 'user_id' not in session:
        return redirect(url_for('user_login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT *
            FROM orders
            WHERE order_id = %s AND user_id = %s
        """, (order_db_id, session['user_id']))

        order = cursor.fetchone()

        if not order:
            flash("Order not found.", "danger")
            return redirect(url_for('my_orders'))

        return render_template(
            'user/order_success.html',
            order=order
        )

    finally:
        cursor.close()
        conn.close()
@app.route('/user/my-orders')
def my_orders():

    if 'user_id' not in session:
        return redirect(url_for('user_login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT *
            FROM orders
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (session['user_id'],))

        orders = cursor.fetchall()

        return render_template(
            'user/my_orders.html',
            orders=orders
        )

    finally:
        cursor.close()
        conn.close()
@app.route('/user/download-invoice/<int:order_id>')
def download_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login to download invoice.", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Fetch only this user's paid order
        cursor.execute("""
            SELECT *
            FROM orders
            WHERE order_id = %s
            AND user_id = %s
            AND payment_status = 'Paid'
        """, (order_id, session['user_id']))

        order = cursor.fetchone()

        if not order:
            flash("Order not found.", "danger")
            return redirect('/user/my-orders')

        # Fetch ordered products
        cursor.execute("""
            SELECT product_name, quantity, price
            FROM order_items
            WHERE order_id = %s
        """, (order_id,))

        items = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    # Convert HTML template into PDF
    html = render_template(
        'user/invoice.html',
        order=order,
        items=items
    )

    pdf = generate_pdf(html)

    if pdf is None:
        return "Unable to generate invoice PDF.", 500

    pdf.seek(0)

    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = (
        f'attachment; filename=SmartCart_Invoice_{order_id}.pdf'
    )

    return response
if __name__ == '__main__':

    app.run(debug=True)
    