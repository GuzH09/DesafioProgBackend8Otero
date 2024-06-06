import { faker } from '@faker-js/faker';

export const generateMockingProduct = () => {
    return {
        title: faker.commerce.productName(),
        price: faker.commerce.price({dec: 0}),
        description: faker.commerce.productDescription(),
        code: faker.commerce.isbn(),
        stock: faker.string.numeric(2),
        category: faker.commerce.product()
    }
}