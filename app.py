import os
import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # get user id
    user_id = session["user_id"]

    # group amount of shares pers sumbol
    transactions = db.execute("SELECT symbol, SUM(shares) AS shares, price FROM transactions WHERE user_id = ?", user_id)

    # total cash amount
    cash_amount = db.execute("SELECT cash FROM users WHERE id = ?", user_id)

    cash = cash_amount[0]['cash']

    return render_template('index.html', stocks=transactions, cash=cash, usd=usd)



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # render page
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = request.form.get("symbol")
        stock = lookup(symbol.upper())

        # conditions for empty fields
        if not symbol:
            return apology("Please enter a symbol, 400")

        elif not stock:
            return apology("invalid symbol, 400")

        # ensure correct values for stocks
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Shares must be an whole number", 400)

        if shares <= 0:
            return apology("Shares must be a positive integer", 400)

        # find out user's amount of cash

        user_id = session["user_id"]
        amount = db.execute("SELECT cash FROM users WHERE id = :id", id=user_id)
        cash = amount[0]["cash"]

        # find the total amount for stocks
        share_price = stock["price"]
        total_price = share_price * shares

        final_amount = cash - total_price

        # get date of transaction
        date = datetime.datetime.now()

        # make sure user has enough cash
        if cash < total_price:
            return apology("not enough cash")
        else:
            # update tables
            db.execute("UPDATE users SET cash = ? WHERE id = ?", final_amount, user_id)
            db.execute("INSERT INTO transactions (user_id, symbol, price, shares, date) VALUES (?, ?, ?, ?, ?)",
                       user_id, stock["symbol"], stock["price"], shares, date)
            # user confirmation
            flash("Bought!")

            return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # show entire table of transactions
    user_id = session["user_id"]
    total_transactions = db.execute("SELECT * FROM transactions WHERE user_id = :id", id=user_id)
    return render_template("history.html", transactions=total_transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # render quote page
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol")

        # conditions if input is empty
        if not symbol:
            return apology("Please input a symbol", 400)

        # checks to see if stock exists
        stock = lookup(symbol.upper())

        if stock == None:
            return apology("Symbol does not exist")

        return render_template("quoted.html", name=stock["name"], price=stock["price"], symbol=stock["symbol"])




@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # renders register page
    if request.method == "GET":
        return render_template("register.html")
    else:
        password = request.form.get("password")
        username = request.form.get("username")
        confirmation = request.form.get("confirmation")

        # conditions for empty fields
        if not username:
            return apology("Please provide a username", 400)

        # Ensure password was submitted
        elif not password:
            return apology("Please provide a password", 400)

        elif not confirmation:
            return apology("Please confirm password", 400)

        # confrim password is the same
        elif password != confirmation:
            return apology("Passwords don't match", 400)

        # generate new hash

        hash = generate_password_hash(password)

        # will insert new user if all conditions are passed
        try:
            new_user = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        except:
            return apology("Username already exists", 400)

        # Remember which user has logged in
        session["user_id"] = new_user

        flash("Registered!")

        # Redirect user to home page
        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        # shows selection of stocks arleady in portfolio
        user_id = session["user_id"]
        user_symbols = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = :id GROUP BY symbol HAVING SUM(shares) > 0", id=user_id)
        return render_template("sell.html", symbols=[row["symbol"] for row in user_symbols])

    else:
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        # conditions for empty fields
        if not symbol:
            return apology("Please provide a symbol", 403)

        # must have a share of 1 or greater
        if shares < 1:
            return apology("Please input a number of shares above 0", 403)

        # check stock from API
        stock = lookup(symbol.upper())

        price = shares * stock["price"]

        # find amount of cash user has
        user_id = session["user_id"]
        amount = db.execute("SELECT cash FROM users WHERE id = :id", id=user_id)
        cash = amount[0]["cash"]

        # finds how many shares of the symbol user has
        user_shares = db.execute(
            "SELECT shares FROM transactions WHERE user_id = :user_id AND symbol = :symbol GROUP BY symbol", user_id=user_id, symbol=symbol)

        # check if user has any shares  at all
        if user_shares:
            shares_amount = user_shares[0]["shares"]
        else:
            return apology("You don't have any shares of that symbol")

        # condition if they try to sell more shares than they have
        if shares > shares_amount:
            return apology("You don't have that amount of shares")

        # update amount of cash the user will now have
        updated = cash + price

        db.execute("UPDATE users SET cash = ? WHERE id = ?", updated, user_id)

        # date of transaction
        date = datetime.datetime.now()

        # update transactions table
        db.execute("INSERT INTO transactions (user_id, symbol, price, shares, date) VALUES (?, ?, ?, ?, ?)",
                    user_id, stock["symbol"], stock["price"], (-1) * shares, date)

        # confirmation
        flash("Sold!")

        return redirect("/")


@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    """Add cash to bank"""
    # render add_cash page
    if request.method == "GET":
        return render_template("add_cash.html")
    else:
        # turn string to integer
        deposit = int(request.form.get("deposit"))

        # condition for empty fields
        if not deposit:
            apology("You must add an amount")

        # retrieve amount of cash the user has
        user_id = session["user_id"]
        amount = db.execute("SELECT cash FROM users WHERE id = :id", id=user_id)
        cash = amount[0]["cash"]

        # add amount of user input
        updated = deposit + cash

        # update users table
        db.execute("UPDATE users SET cash = ? WHERE id = ?", updated, user_id)

        return redirect("/")




@app.route("/settings", methods=["GET", "POST"])
@login_required
def change_password():
    """Change password"""
    if request.method == "GET":
        # showcase the username
        user_id = session["user_id"]
        user_select = db.execute("SELECT username FROM users WHERE id = :id", id=user_id)
        username = user_select[0]["username"]
        return render_template("settings.html", username=username)

    else:
        user_id = session["user_id"]

        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        new_password = request.form.get("new_pass")

        # conditions for empty fields
        if not new_password:
            return apology("Please provide a new password", 403)

        if not password:
            return apology("Please provide your current password", 403)

        if not confirmation:
            return apology("Please confirm the new password", 403)

        if password != confirmation:
            return apology("Passwords don't match", 403)

        # Check if the current password is correct
        rows = db.execute("SELECT * FROM users WHERE id = ?", user_id)
        if not check_password_hash(rows[0]["hash"], password):
            return apology("Incorrect password", 403)

        # Update the password
        new_hash = generate_password_hash(new_password)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, user_id)

        flash("Password changed successfully!")
        return redirect("/")