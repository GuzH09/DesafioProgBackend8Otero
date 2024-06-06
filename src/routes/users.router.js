import {Router} from 'express';
import passport from 'passport';
import jwt from "jsonwebtoken";
import UserController from '../controllers/UserController.js';
import CurrentUserDTO from '../DTOs/currentuser.dto.js';
import { roleauth } from '../middlewares/role-authorization.js';

const usersRouter = Router();
const SessionService = new UserController();

// API Register
usersRouter.post('/register', async (req, res) => {
    const result = await SessionService.registerUser(req.body);
    result['error'] ? req.failRegister = true : req.failRegister = false;
    res.redirect("/login");
    // result['error'] ? res.status(400).send(result) : res.send({status: 'success', token: result});
})

// API Login
usersRouter.post('/login', async (req, res) => {
    const {email, password} = req.body
    const result = await SessionService.loginUser(email, password);
    if ( result['error'] ) {
        req.failLogin = true;
        return res.redirect("/login");
    } else {
        req.failLogin = false;
        res.cookie("auth", result, { maxAge: 60*60*1000 });
        return res.redirect("/allproducts");
    }
    // result['error'] ? res.status(400).send(result) : res.cookie("auth", result, { maxAge: 60*60*1000 }).send({status: 'success', token: result});
})

// API Login with Github
usersRouter.get("/github", passport.authenticate('github', {scope: ['user:email']} ), (req, res) => {
    res.send({
        status: 'success',
        message: 'Success'
    });
});

// API Login Callback with Github
usersRouter.get("/githubcallback", passport.authenticate('github', {session: false, failureRedirect: "/login"}), (req, res) => {
    delete req.user.password;
    const token = jwt.sign(req.user, "coderSecret", {expiresIn: "1h"});
    res.cookie("auth", token, { maxAge: 60*60*1000 });
    res.redirect('/allproducts');
});

// API Current
usersRouter.get('/current', passport.authenticate("jwt", {session: false}), async (req, res) => {
    // Envia un DTO gracias a roleauth
    res.send({
        user: req.user
    });
});

// API Logout
usersRouter.get('/logout', async (req, res) => {
    res.clearCookie("auth");
    res.redirect("/login")
});

// API User ID
usersRouter.get('/:uid', passport.authenticate("jwt", {session: false}), roleauth('admin'), async (req, res) => {
    const result = await SessionService.getUser(req.params.uid);
    result['error'] ? res.status(400).send(result) : res.send({status: 'success', payload: result});
});

export default usersRouter;