from unicodedata import name
from app import app
from flask import render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from app.forms import SignUpForm, AddressForm, LoginForm
from app.models import User, Address

@app.route('/')
def index():
    addresses = Address.query.all()
    return render_template('index.html', addresses=addresses)


@app.route('/signup', methods=["GET","POST"])
def signup():
    form = SignUpForm()
    # if the form is submitted and all the data is valid
    if form.validate_on_submit():
        print('Form has been validated! Hooray!!!!')
        email = form.email.data
        username = form.username.data
        password = form.password.data
        #Before we add the user to the database, check to see if there is already a user with username or email
        existing_user = User.query.filter((User.email == email)|(User.username == username)).first()
        if existing_user:
            flash('A user with that username or email already exists.', 'danger')
            return redirect(url_for('signup'))

        new_user = User(email=email, username=username, password=password)
        flash(f"{new_user.username} has been created.","success")
        return redirect(url_for('index'))
    return render_template('signup.html',form=form)


@app.route('/create', methods=["GET", "POST"])
@login_required
def create():
    form = AddressForm()
    if form.validate_on_submit():
        name = form.name.data
        streetaddress = form.streetaddress.data
        city = form.city.data
        state = form.state.data
        zipcode = form.zipcode.data
        country = form.country.data
        #Create a new instance of address with the form data
        new_address = Address(name=name, streetaddress=streetaddress, city=city, state=state, zipcode=zipcode, country=country, user_id=current_user.id)
        
        flash(f'{new_address.name} has been created.','secondary')
        #Redirect back to home page
        return redirect(url_for('index'))
    return render_template('createaddress.html',form=form)

@app.route('/login',methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        #Get username and password from form
        username = form.username.data
        password = form.password.data
        #Query the user table for a user with the same username as the form
        user = User.query.filter_by(username=username).first()
        #If the user exists and the password is correct for that user
        if user is not None and user.check_password(password):
            #Log the user in with the login_user function from flask_login
            login_user(user)
            #Flash a success message
            flash(f"Welcome back {user.username}!", "success")
            #Redirect back to homepage
            return redirect(url_for('index'))
        # If no user with username or password incorrect
        else:
            # flash a danger message
            flash('Incorrect username and/or password.  Please try again.', 'danger')
            # Redirect back to login page
            return redirect(url_for('login'))
    return render_template('login.html',form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have successfully logged out.', 'primary')
    return redirect(url_for('index'))

@app.route('/addresses/<address_id>')
@login_required
def view_address(address_id):
    address = Address.query.get_or_404(address_id)
    return render_template('address.html', address=address)
    

@app.route('/addresses/<address_id>/edit', methods=["GET","POST"])
@login_required
def edit_address(address_id):
    address_to_edit = Address.query.get_or_404(address_id)
    # make sure the address to edit is owned by the current user
    if address_to_edit.author != current_user:
        flash("You do not have permission to edit this address","danger")
        return redirect(url_for('view_address', address_id=address_id))
    form = AddressForm()
    if form.validate_on_submit():
        name = form.name.data
        streetaddress = form.streetaddress.data
        city = form.city.data
        state = form.state.data
        zipcode = form.zipcode.data
        country = form.country.data
        address_to_edit.update(name=name, streetaddress=streetaddress, city=city, state=state, zipcode=zipcode, country=country)
        flash(f'{address_to_edit.name} has been updated', 'success')
        return redirect(url_for('view_address', address_id = address_id))

    return render_template('edit_address.html', address=address_to_edit, form=form)

@app.route('/addresses/<address_id>/delete')
@login_required
def delete_address(address_id):
    address_to_delete = Address.query.get_or404(address_id)
    if address_to_delete.author != current_user:
        flash("You do not have permission to delete this Address", )
        return(redirect(url_for('index')))
    #delete the address
    
    address_to_delete.delete()
    flash(f"{address_to_delete.name} has been deleted", 'info')
    return redirect(url_for('index'))