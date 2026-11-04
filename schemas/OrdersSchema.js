const { Schema } = require("mongoose");

const OrdersSchema = new Schema({
    userId: {
        type: String,
        default: "ZU9344",
    },
    orderId: {
        type: String,
        default: () => "OD" + Date.now().toString().slice(-8),
    },
    name: String,
    qty: Number,
    price: Number,
    mode: String,
    product: String,
    status: {
        type: String,
        default: "COMPLETE",
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
});

module.exports = { OrdersSchema };
