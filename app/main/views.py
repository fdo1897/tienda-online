# main/views.py

from flask import render_template, redirect, url_for, abort, flash, request, current_app
from app import create_app, db
from ..models import Permission, Role, User, Shoe, Category, Purchase
from ..decorators import admin_required, permission_required
from . import main
from .forms import PurchaseShoeForm
from flask_login import login_user, logout_user, login_required, current_user

@main.route('/')
@main.route('/index')
def index():
    return render_template('index.html')

@main.route('/market')
def market():
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Número de elementos por página
    pagination = Shoe.query.paginate(page, per_page)
    shoes = pagination.items
    return render_template('market.html', shoes=shoes, pagination=pagination, endpoint='main.market')

@main.route('/shoe/<int:shoe_id>', methods=['GET', 'POST'])
def shoe_details(shoe_id):
    purchase_form = PurchaseShoeForm()
    p_shoe_object = Shoe.query.get(shoe_id)

    if request.method == 'POST' and purchase_form.validate_on_submit():
        if p_shoe_object:
            if current_user.is_authenticated:
                if p_shoe_object in current_user.purchases:
                    # No es necesario agregar la compra al carrito si ya está presente
                    flash("El artículo ya está en tu carrito de compras.", category='warning')
                else:
                    purchase = Purchase(user=current_user, shoe=p_shoe_object)
                    db.session.add(purchase)
                    db.session.commit()
                    flash(f"Artículo agregado a tu carrito: {p_shoe_object.name} por {p_shoe_object.price}$", category='success')
                return redirect(url_for('main.shopping_cart'))
            flash("Debes iniciar sesión para agregar artículos al carrito de compras.", category='warning')
            return redirect(url_for('auth.login'))

    return render_template('shoe_details.html', shoe=p_shoe_object, purchase_form=purchase_form)

@main.route('/shopping-cart', methods=['GET'])
@login_required
def shopping_cart():
    purchases = Purchase.query.filter_by(user=current_user).all()

    return render_template('shopping_cart.html', purchases=purchases)

@main.route('/remove-from-cart/<int:purchase_id>', methods=['GET', 'POST'])
@login_required
def remove_from_cart(purchase_id):
    purchase = Purchase.query.get(purchase_id)

    if purchase:
        db.session.delete(purchase)
        db.session.commit()
        flash("Artículo eliminado del carrito de compras", category='success')

    return redirect(url_for('main.shopping_cart'))
