import { Router } from "express";
import passport from 'passport';

import CartController from '../controllers/CartController.js';
import ProductController from '../controllers/ProductController.js';
import TicketController from '../controllers/TicketController.js';
import { roleauth } from "../middlewares/role-authorization.js";

const cartsRouter = Router();
const CM = new CartController();
const PM = new ProductController();
const TM = new TicketController();

// Create New Empty Cart
cartsRouter.post('/', passport.authenticate('jwt', {session: false}), roleauth('admin'), async (req, res) => {
    const result = await CM.addCart();
    result['success'] ? res.status(201).send(result) : res.status(400).send({error: "Cart couldn't be created."});
});

// Get Cart By Id
cartsRouter.get('/:cid', passport.authenticate('jwt', {session: false}), async (req, res) => {
    let cartId = req.params.cid;
    const carts = await CM.getCartById(cartId);
    carts['error'] ? res.status(400).send(carts) : res.send({carts});
});

// Add Product to Cart
cartsRouter.post('/:cid/product/:pid', passport.authenticate('jwt', {session: false}), async (req, res) => {
    let cartId = req.params.cid;
    let productId = req.params.pid;
    const product = await PM.getProductById(productId);
    // if ( product['error'] ) return res.status(400).send(product);
    // Checkear error
    const result = await CM.AddProductToCart(cartId, productId);
    // result['success'] ? res.status(201).send(result) : res.status(400).send(result);
    // Validar error

    res.redirect("/allproducts");
});

// Delete All Products From Cart
cartsRouter.delete('/:cid', passport.authenticate('jwt', {session: false}), async (req, res) => {
    let cartId = req.params.cid;
    const carts = await CM.emptyCartById(cartId);
    carts['error'] ? res.status(400).send(carts) : res.send({carts});
});

// Delete Single Product From Cart
cartsRouter.post('/:cid/product/:pid/delete', passport.authenticate('jwt', {session: false}), async (req, res) => {
    let cartId = req.params.cid;
    let productId = req.params.pid;
    const carts = await CM.deleteProductFromCart(cartId, productId);
    // carts['error'] ? res.status(400).send(carts) : res.send({carts});
    // Validar error

    res.redirect(`/carts/${cartId}`);
});

// PUT Single Cart With Products Object
cartsRouter.put('/:cid', passport.authenticate('jwt', {session: false}), async (req, res) => {
    let { products } = req.body;
    let cartId = req.params.cid;
    // For loop, for every product id in products array
    for (const item of products) {
        const productId = item.product;
        const product = await PM.getProductById(productId);
        if ( product['error'] ) return res.status(400).send(product);
    } // If all products exist, we continue with the update
    const carts = await CM.updateProductsFromCart(cartId, products);
    carts['error'] ? res.status(400).send(carts) : res.send({carts});
});

// PUT Quantity of Product From Cart
cartsRouter.put('/:cid/product/:pid', passport.authenticate('jwt', {session: false}), async (req, res) => {
    let { quantity } = req.body;
    let cartId = req.params.cid;
    let productId = req.params.pid;
    const carts = await CM.updateProductQuantityFromCart(cartId, productId, quantity);
    carts['error'] ? res.status(400).send(carts) : res.send({carts});
});

// Finish purchase of cart
cartsRouter.post('/:cid/purchase', passport.authenticate('jwt', {session: false}), async (req, res) => {
    let cartId = req.params.cid;
    const cart = await CM.getCartById(cartId);
    let number = 0

    for (const product of cart.products) {
        if (product.quantity <= product.product.stock) {
            await CM.deleteProductFromCart(cartId, product.product._id);
            await PM.updateProduct(product.product._id, { stock: product.product.stock - product.quantity });
            number += 1;
        }
    }
    
    if (number > 0) {
        const ticket = await TM.createTicket({
            purchase_datetime: Date.now(),
            amount: number,
            purchaser: req.user.email,
        });
        req.ticket = ticket.result;
        res.redirect(`/carts/${cartId}?ticket=${req.ticket._id}`);
    } else {
        res.redirect(`/carts/${cartId}`);
    }
});

export default cartsRouter;