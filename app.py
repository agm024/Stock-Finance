from flask import Flask, render_template, request, redirect, session
from cs50 import SQL
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import lookup, apology

# Configure application
app = Flask(__name__)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Secret key for session management
app.secret_key = 'super_secret_key'


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username and password are provided
        if not username or not password or not confirmation:
            return apology("All fields are required")

        # Ensure passwords match
        if password != confirmation:
            return apology("Passwords do not match")

        # Check if username already exists
        existing_user = db.execute(
            "SELECT * FROM users WHERE username = :username", username=username)
        if existing_user:
            return apology("Username already exists")

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Insert new user into database
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                   username=username, hash=hashed_password)

        # Redirect to login page
        return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    # Forget any user_id
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("Invalid username or password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/quote", methods=["GET", "POST"])
def quote():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quote = lookup(symbol)
        if not quote:
            return apology("Symbol not found")
        # Convert price to float for better precision
        quote["price"] = float(quote["price"])
        return render_template("quoted.html", quote=quote)
    else:
        return render_template("quote.html")


@app.route("/buy", methods=["GET", "POST"])
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Ensure symbol and shares are provided
        if not symbol or not shares:
            return apology("All fields are required")

        # Ensure shares is a positive integer
        try:
            shares = int(shares)
            if shares <= 0:
                return apology("Shares must be a positive integer")
        except ValueError:
            return apology("Shares must be a positive integer")

        quote = lookup(symbol)
        if not quote:
            return apology("Symbol not found")

        price = quote["price"]
        total_cost = price * shares

        # Ensure user has enough cash
        user_id = session.get("user_id")
        user = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=user_id)[0]
        if user["cash"] < total_cost:
            return apology("Insufficient funds")

        # Update user's cash balance
        db.execute("UPDATE users SET cash = cash - :total_cost WHERE id = :user_id",
                   total_cost=total_cost, user_id=user_id)

        # Record the purchase
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (:user_id, :symbol, :shares, :price)",
                   user_id=user_id, symbol=symbol, shares=shares, price=price)

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/")
def index():
    user_id = session.get("user_id")
    if user_id is None:
        return redirect("/login")

    # Retrieve user's portfolio
    portfolio = db.execute(
        "SELECT symbol, SUM(shares) AS total_shares FROM transactions WHERE user_id = :user_id GROUP BY symbol",
        user_id=user_id
    )

    # Calculate total value of the portfolio
    total_value = 0
    for stock in portfolio:
        quote = lookup(stock["symbol"])
        if quote:
            stock["name"] = quote["name"]
            stock["price"] = quote["price"]
            stock["total_value"] = quote["price"] * stock["total_shares"]
            total_value += stock["total_value"]

    # Retrieve user's cash balance
    cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=user_id)[0]["cash"]

    # Calculate total value including cash
    total_value += cash

    return render_template("index.html", portfolio=portfolio, cash=cash, total_value=total_value)


@app.route("/sell", methods=["GET", "POST"])
def sell():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        # Ensure symbol and shares are provided
        if not symbol or not shares:
            return apology("All fields are required")

        # Check if user owns enough shares to sell
        user_id = session.get("user_id")
        user_shares = db.execute("SELECT SUM(shares) AS total_shares FROM transactions WHERE user_id = :user_id AND symbol = :symbol",
                                 user_id=user_id, symbol=symbol)[0]["total_shares"]
        if not user_shares or user_shares < shares:
            return apology("Not enough shares to sell")

        # Get current price of the stock
        quote = lookup(symbol)
        price = quote["price"]

        # Update user's cash balance
        total_earnings = price * shares
        db.execute("UPDATE users SET cash = cash + :total_earnings WHERE id = :user_id",
                   total_earnings=total_earnings, user_id=user_id)

        # Record the sale
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (:user_id, :symbol, :shares, :price)",
                   user_id=user_id, symbol=symbol, shares=-shares, price=price)

        return redirect("/")
    else:
        user_id = session.get("user_id")
        # Retrieve distinct symbols from user's portfolio
        portfolio = db.execute("SELECT DISTINCT symbol FROM transactions WHERE user_id = :user_id",
                               user_id=user_id)
        return render_template("sell.html", portfolio=portfolio)


@app.route("/history")
def history():
    user_id = session.get("user_id")
    transactions = db.execute(
        "SELECT * FROM transactions WHERE user_id = :user_id", user_id=user_id)
    return render_template("history.html", transactions=transactions)


@app.route("/logout")
def logout():
    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)
