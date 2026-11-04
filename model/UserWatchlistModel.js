const { model } = require("mongoose");
const { UserWatchlistSchema } = require("../schemas/UserWatchlistSchema");

const UserWatchlistModel = model("user_watchlist", UserWatchlistSchema);

module.exports = { UserWatchlistModel };
