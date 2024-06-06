export const generateUserErrorInfo = (user) => {
    return `One or more properties were incomplete or not valid.\nList of required properties:
* title       : needs to be a String, received ${user.title}
* price       : needs to be a Number, received ${user.price}
* description : needs to be a String, received ${user.description}
* code        : needs to be a String, received ${user.code}
* stock       : needs to be a Number, received ${user.stock}
* category    : needs to be a String, received ${user.category}`;
}