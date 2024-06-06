import dotenv from 'dotenv';
import process from 'process';
import cors from 'cors';

dotenv.config();

import express from 'express';
import handlebars from "express-handlebars";
import mongoose from 'mongoose';
import passport from 'passport';
import cookieParser from 'cookie-parser';

import productsRouter from './routes/products.router.js';
import cartsRouter from './routes/carts.router.js';
import viewsRouter from './routes/views.router.js';
import usersRouter from './routes/users.router.js';
import initializatePassport from './config/passportConfig.js';
import errorHandler from './middlewares/errors/index.js';

import __dirname from './utils/constantsUtil.js';

import { Server } from 'socket.io';
import websocket from './websocket.js';

const app = express();

//MongoDB connect
const uri = process.env.MONGO_URI;
mongoose.connect(uri);

//Handlebars Config
app.engine("handlebars", handlebars.engine());
app.set("views", `${__dirname}/../views`)
app.set("view engine", "handlebars");

//Middlewares
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({extended:true}));
app.use("/static", express.static(`${__dirname}/../../public`));
app.use(cookieParser());

initializatePassport();
app.use(passport.initialize());

//Routers
app.use("/", viewsRouter);
app.use('/api/sessions', usersRouter);
app.use("/api/products", productsRouter);
app.use("/api/carts", cartsRouter);
app.use(errorHandler);

const PORT = 8080;
const httpServer = app.listen(PORT, () => {console.log(`Servidor activo en http://localhost:${PORT}`)});

const io = new Server(httpServer);

websocket(io);