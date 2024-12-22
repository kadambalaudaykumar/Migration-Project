import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
import hashlib
import boto3
from werkzeug.utils import secure_filename
from botocore.exceptions import NoCredentialsError

app = Flask(__name__)

# Config for MySQL
app.config['MYSQL_HOST'] = 'udaydb.c7sigg2iwh93.ap-south-2.rds.amazonaws.com'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'UdayKumar7'
app.config['MYSQL_DB'] = 'udaydb'

# AWS Configurations
AWS_ACCESS_KEY = 'AKIASU566K3V76KK3ZTV'
AWS_SECRET_KEY = 'hgA+HRCDQFCFbpu+tTj60fLyv7KFTmnIS7qF9Zb8'
AWS_REGION = 'ap-south-2'
AWS_BUCKET_NAME = 'udaymigration'  # This is where you define your S3 bucket name
KMS_KEY_ID = '4cffa25f-09bd-408e-babe-81b77abb03b0'

# File upload configurations
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
mysql = MySQL(app)

app.secret_key = 'your_secret_key'

# Initialize S3 client for file upload
s3_client = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                         aws_secret_access_key=AWS_SECRET_KEY,
                         region_name=AWS_REGION)

# Initialize KMS client for password encryption/decryption (if needed)
kms_client = boto3.client('kms', aws_access_key_id=AWS_ACCESS_KEY,
                          aws_secret_access_key=AWS_SECRET_KEY,
                          region_name=AWS_REGION)

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Function to upload a file to S3
def upload_file_to_s3(file):
    try:
        filename = secure_filename(file.filename)
        # Upload the file to S3
        s3_client.upload_fileobj(file, AWS_BUCKET_NAME, filename)
        # Return the public URL of the uploaded file
        return f"https://{AWS_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/{filename}"
    except NoCredentialsError:
        flash('Credentials not available for AWS S3.', 'danger')
        return None
    except Exception as e:
        flash(f'Error occurred: {str(e)}', 'danger')
        return None

# Function to hash password using SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Home route
@app.route('/')
def index():
    return render_template('signin.html')

# Signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        
        # Hash the password before storing it in the database
        hashed_password = hash_password(password)

        # Handle image upload (same as before)
        image = request.files['image']
        image_url = None
        if image and allowed_file(image.filename):
            image_url = upload_file_to_s3(image)
        
        if image_url:
            # Insert user into the database with hashed password
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO users (name, email, password, image_url) VALUES (%s, %s, %s, %s)", 
                        (name, email, hashed_password, image_url))
            mysql.connection.commit()
            cur.close()

            flash('Sign up successful! Please sign in.', 'success')
            return redirect(url_for('signin'))
        else:
            flash('Image upload failed. Please try again.', 'danger')
            return redirect(url_for('signup'))

    return render_template('signup.html')

# Signin page
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Hash the entered password for comparison
        hashed_password = hash_password(password)

        # Fetch hashed password from the database
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user and user[3] == hashed_password:  # Compare the hashed passwords
            # Storing user details in session
            session['user_id'] = user[0]
            session['user_name'] = user[1]
            session['user_email'] = user[2]
            session['user_image'] = user[4]
            
            return redirect(url_for('welcome'))
        else:
            flash('Invalid credentials, please try again.', 'danger')

    return render_template('signin.html')

# Welcome page
@app.route('/welcome')
def welcome():
    if 'user_id' in session:
        return render_template('welcome.html', 
                               name=session['user_name'], 
                               email=session['user_email'],
                               image_url=session['user_image'])
    else:
        flash('You need to sign in first!', 'danger')
        return redirect(url_for('signin'))

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('signin'))

if __name__ == '__main__':
    app.run(debug=True)

