import { Router } from "express";
import passport from "passport";

import ProductController from '../controllers/ProductController.js';
import { uploader } from "../utils/multerUtil.js";
import productModel from '../models/productModel.js';
import { roleauth } from "../middlewares/role-authorization.js";

import CustomError from "../services/errors/customError.js";
import { generateUserErrorInfo } from "../services/errors/info.js";
import ErrorCodes from "../services/errors/enums.js";

const productsRouter = Router();
const PM = new ProductController();

// Get All Products - Get All Products With Page, Limit, Sort and Query
productsRouter.get('/', async (req, res) => {
    try {
        let { page = 1, limit = 10, sort } = req.query;
        page = parseInt(page);
        limit = parseInt(limit);
        const options = {
            page,
            limit,
            lean: true
        };
        const sortOptions = {};
        if (sort === 'asc') {
            sortOptions.price = 1;
        } else if (sort === 'desc') {
            sortOptions.price = -1;
        }
        const queryOptions = {};
        if (req.query.category) {
            queryOptions.category = req.query.category;
        } else if (req.query.stock) {
            queryOptions.stock = parseInt(req.query.stock);
        }
        options.sort = sortOptions;
        const result = await productModel.paginate(queryOptions, options);
        const baseURL = "http://localhost:8080/api/products";
        if (result.hasPrevPage) {
            let strURLprev = `${baseURL}?page=${result.prevPage}`;
            for (const itemQueryKey in req.query) {
                if (itemQueryKey != 'page') {
                    strURLprev = strURLprev + '&' + itemQueryKey + '=' + req.query[itemQueryKey]
                }
            }
            result.prevLink = strURLprev;
        } else {
            result.prevLink = "";
        }
        if (result.hasNextPage) {
            let strURLprev = `${baseURL}?page=${result.nextPage}`;
            for (const itemQueryKey in req.query) {
                if (itemQueryKey != 'page') {
                    strURLprev = strURLprev + '&' + itemQueryKey + '=' + req.query[itemQueryKey]
                }
            }
            result.nextLink = strURLprev;
        } else {
            result.nextLink = "";
        }
        result.isValid = !(page <= 0 || page > result.totalPages);
        const response = {
            status: 'success',
            payload: result.docs,
            totalPages: result.totalPages,
            prevPage: result.prevPage,
            nextPage: result.nextPage,
            page: result.page,
            hasPrevPage: result.hasPrevPage,
            hasNextPage: result.hasNextPage,
            prevLink: result.prevLink,
            nextLink: result.nextLink,
            isValid: result.isValid
        };
        res.status(200).send(response);
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});

// Get Product By Id
productsRouter.get('/:pid', async (req, res) => {
    let productId = req.params.pid;
    const products = await PM.getProductById(productId);
    products['error'] ? res.status(400).send(products) : res.send({...products, _id: products._id.toString()});
});

// Create New Product
productsRouter.post('/', passport.authenticate('jwt', {session: false}), roleauth('admin'), async (req, res, next) => {
    uploader.array('thumbnails') (
        req, 
        res, 
        (err) => {
            if (err) {
                return res.status(400).send({error: "Error uploading image."});
            }
            next();
        });
    }, async (req, res, next) => {
        let thumbnails = []

        // If there are files, get their paths
        if (req.files && req.files.length > 0) {
            thumbnails = req.files.map(file => file.path);
        }

        // Get Product Data from Body
        let { title, description, code, price, stock, category } = req.body;

        // Status is true by default
        // Thumbnails is not required, [] by default
        const newObjectData = {title, description, code, price, stock, category, thumbnails};
        const result = await PM.addProduct(newObjectData);
        if (result['error']) {
            try {
                CustomError.createError({
                    name: 'User creation error',
                    cause: generateUserErrorInfo({ title, price, description, code, stock, category }),
                    message: 'Error in create User',
                    code: ErrorCodes.INVALID_TYPES_ERROR,
                });
            } catch (e) {
                next(e)
            }
        } else {
            res.status(201).send(result);
        }
});

// Update Existing Product
productsRouter.put('/:pid', passport.authenticate('jwt', {session: false}), roleauth('admin'), async (req, res) => {
    // Get Product Data from Body
    let { title, description, code, price, stock, category, thumbnails } = req.body;
    // Get Product Id from Params
    let productId = req.params.pid;

    const newObjectData = {title, description, code, price, stock, category, thumbnails};
    const result = await PM.updateProduct( productId, newObjectData );
    result['success'] ? res.status(201).send(result) : res.status(400).send(result);
});

// Delete Existing Product
productsRouter.delete('/:pid', passport.authenticate('jwt', {session: false}), roleauth('admin'), async (req, res) => {
    // Get Product Id from Params
    let productId = req.params.pid;
    const result = await PM.deleteProduct(productId);
    result['success'] ? res.status(201).send(result) : res.status(400).send(result);
});

export default productsRouter;