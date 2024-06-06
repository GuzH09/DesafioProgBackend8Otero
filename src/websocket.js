import MessageService from './services/MessageService.js';
import ProductService from './services/ProductService.js';
const PM = new ProductService();
const CHM = new MessageService();

export default (io) => {
    io.on("connection", socket => {
        console.log("Nuevo cliente conectado -----> ", socket.id);
    
        socket.on("addProduct", async (data) => {
            // Get Product Data
            let { title, description, code, price, stock, category } = data;

            let thumbnails = [];
            // Status is true by default
            // Thumbnails is not required, [] by default            
            const newObjectData = {title, description, code, price, stock, category, thumbnails};
            const result = await PM.addProduct(newObjectData);

            if ( result['success'] ) {
                const products = await PM.getProducts();
                io.emit("refreshProducts", products)
            } else {
                io.emit("statusError", result)
            }
        });
    
        socket.on("deleteProduct", async (data) => {
            // Delete Existing Product
            // Get Product Id
            let productId = data;
            const result = await PM.deleteProduct(productId);
            if ( result['success'] ) {
                const products = await PM.getProducts();
                io.emit("refreshProducts", products)
            } else {
                io.emit("refreshProducts", result)
            }
        });

        socket.on("message", async (data) => {
            const result = await CHM.addMessage(data);
            const messages = await CHM.getAllMessages();
            io.emit("messagesLogs", messages);
        });

        socket.on("userConnect", async (data) => {
            const messages = await CHM.getAllMessages();
            socket.emit("messagesLogs", messages);
            socket.broadcast.emit("newUser", data);
        });

    });
}
