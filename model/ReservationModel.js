const { Schema, model } = require("mongoose");
const ReservationSchema = new Schema({
  userId: { type: String, required: true, index: true },
  name: { type: String, required: true },
  qty: { type: Number, required: true },
  price: { type: Number, required: true },
  mode: { type: String, enum: ["BUY","SELL"], required: true },
  product: { type: String, enum: ["CNC","MIS","NRML"], required: true },
  cashPaise: { type: Number, required: true },
  collateralPaise: { type: Number, required: true },
  shares: { type: Number, default: 0 },
  status: { type: String, enum: ["PENDING","FILLED","CANCELLED"], default: "PENDING", index: true },
  order: Schema.Types.ObjectId,
  parentGtt: Schema.Types.ObjectId,
  linkedPosition: Schema.Types.ObjectId,
  reason: String
}, { timestamps: true });
module.exports = { ReservationModel: model("order_reservation", ReservationSchema) };
