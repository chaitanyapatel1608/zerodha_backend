const { Schema } = require("mongoose");

const IpoSchema = new Schema({
  symbol: {
    type: String,
    required: true,
    unique: true,
  },
  name: String,
  dates: String,
  priceRange: String,
  minQty: Number,
  minAmount: String,
  status: {
    type: String,
    default: "Upcoming", // "Apply", "Pre-apply", "Closed", "Upcoming"
  },
  type: {
    type: String,
    default: "IPO",
  },
  gmp: { type: String, default: "+₹18 (+5.2%)" },
  gmpPercent: { type: String, default: "+5.2%" },
  issueSize: { type: String, default: "₹1,250 Cr" },
  freshIssue: { type: String, default: "₹850 Cr" },
  ofs: { type: String, default: "₹400 Cr" },
  registrar: { type: String, default: "Link Intime India Pvt. Ltd." },
  leadManagers: { type: String, default: "Kotak Mahindra Capital, Morgan Stanley, Citigroup" },
  rhpUrl: { type: String, default: "https://www.sebi.gov.in" },
  subscription: {
    retail: { type: String, default: "2.85x" },
    qib: { type: String, default: "6.40x" },
    nii: { type: String, default: "4.15x" },
    total: { type: String, default: "4.92x" },
  },
  timeline: {
    openDate: { type: String, default: "06 Nov 2024" },
    closeDate: { type: String, default: "08 Nov 2024" },
    allotmentDate: { type: String, default: "11 Nov 2024" },
    refundDate: { type: String, default: "12 Nov 2024" },
    dematCreditDate: { type: String, default: "12 Nov 2024" },
    listingDate: { type: String, default: "13 Nov 2024" },
  },
});

module.exports = { IpoSchema };
