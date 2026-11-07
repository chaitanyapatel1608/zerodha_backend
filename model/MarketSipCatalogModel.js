const { model } = require("mongoose");
const { MarketSipCatalogSchema } = require("../schemas/MarketSipCatalogSchema");

const MarketSipCatalogModel = model("marketsipcatalog", MarketSipCatalogSchema);

module.exports = { MarketSipCatalogModel };
