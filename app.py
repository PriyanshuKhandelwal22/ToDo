import os
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

# ──────────────────────────────────────────────
#  App & Config
# ──────────────────────────────────────────────

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-in-prod")

# Database Configuration: Local SQLite, Vercel /tmp SQLite, or Remote SQL database
database_url = os.environ.get("DATABASE_URL")
if database_url:
    # Use pure-Python pg8000 driver instead of psycopg2 to prevent C compilation build errors on Windows/Python 3.14
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql+pg8000://", 1)
    elif database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+pg8000://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    
    # Explicitly configure SSL for pg8000 (required for Neon and Supabase)
    if "pg8000" in database_url:
        import ssl
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "connect_args": {
                "ssl_context": ssl.create_default_context()
            }
        }
elif os.environ.get("VERCEL"):
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////tmp/focusflow.db"
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///focusflow.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Log database connection target (masking password) for Vercel debug logging
db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
if "@" in db_uri:
    print(f"[DB LOG] Connecting to database host: {db_uri.split('@')[-1]}")
else:
    print(f"[DB LOG] Connecting to database: {db_uri}")

# Ensure tables are created safely without crashing the WSGI server on boot if connection fails
try:
    with app.app_context():
        db.create_all()
    print("[DB LOG] Database tables successfully verified/created.")
except Exception as e:
    print(f"[DB LOG ERROR] Database initialization failed: {e}")

login_manager = LoginManager(app)
login_manager.login_view = "login"          # redirect here when @login_required fails
login_manager.login_message = "Please log in to access your tasks."
login_manager.login_message_category = "info"

# ──────────────────────────────────────────────
#  Models
# ──────────────────────────────────────────────

class User(UserMixin, db.Model):
    """Registered user account."""
    __tablename__ = "users"

    id           = db.Column(db.Integer, primary_key=True)
    email        = db.Column(db.String(254), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    tasks = db.relationship("Task", backref="owner", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Task(db.Model):
    """A to-do task belonging to a single user."""
    __tablename__ = "tasks"

    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title       = db.Column(db.String(500), nullable=False)
    priority    = db.Column(db.String(10), default="medium")   # high / medium / low
    completed   = db.Column(db.Boolean, default=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def created_fmt(self) -> str:
        return self.created_at.strftime("%b %d, %Y %I:%M %p")


# ──────────────────────────────────────────────
#  Flask-Login user loader
# ──────────────────────────────────────────────

@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


# ──────────────────────────────────────────────
#  Auth Routes
# ──────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")

        # --- validation ---
        if not email or "@" not in email:
            flash("Please enter a valid email address.", "error")
        elif len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
        else:
            user = User(email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash("Account created! Welcome to FocusFlow.", "success")
            return redirect(url_for("index"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user     = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user, remember=True)
            next_page = request.args.get("next")
            return redirect(next_page or url_for("index"))
        else:
            flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ──────────────────────────────────────────────
#  Task Routes  (all require login)
# ──────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    tasks = Task.query.filter_by(user_id=current_user.id)\
                      .order_by(Task.completed.asc(), Task.created_at.desc())\
                      .all()
    total = len(tasks)
    done  = sum(1 for t in tasks if t.completed)
    return render_template("index.html", tasks=tasks, total=total, done=done)


@app.route("/add", methods=["POST"])
@login_required
def add_task():
    title    = request.form.get("title", "").strip()
    priority = request.form.get("priority", "medium")
    if title:
        task = Task(user_id=current_user.id, title=title, priority=priority)
        db.session.add(task)
        db.session.commit()
    return redirect(url_for("index"))


@app.route("/toggle/<int:task_id>", methods=["POST"])
@login_required
def toggle_task(task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first_or_404()
    task.completed = not task.completed
    db.session.commit()
    return redirect(url_for("index"))


@app.route("/delete/<int:task_id>", methods=["POST"])
@login_required
def delete_task(task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first_or_404()
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for("index"))


@app.route("/clear-completed", methods=["POST"])
@login_required
def clear_completed():
    Task.query.filter_by(user_id=current_user.id, completed=True).delete()
    db.session.commit()
    return redirect(url_for("index"))


# ──────────────────────────────────────────────
#  Entry Point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, port=5000)
