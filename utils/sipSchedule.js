const DAY = 86400000;
// 10:00 Asia/Kolkata is 04:30 UTC on the same calendar date.
function nextSipDate(frequency, scheduleDay, after = new Date()) {
  const date = new Date(after);
  let candidate = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate(), 4, 30));
  if (frequency === "MONTHLY") {
    for (let offset = 0; offset < 2; offset++) {
      const month = date.getUTCMonth() + offset;
      const last = new Date(Date.UTC(date.getUTCFullYear(), month + 1, 0)).getUTCDate();
      candidate = new Date(Date.UTC(date.getUTCFullYear(), month, Math.min(scheduleDay, last), 4, 30));
      if (candidate > date) return candidate;
    }
  }
  if (candidate <= date) candidate = new Date(+candidate + DAY);
  if (frequency === "WEEKLY") {
    candidate = new Date(+candidate + ((scheduleDay % 7 - candidate.getUTCDay() + 7) % 7) * DAY);
  }
  return candidate;
}
module.exports = { nextSipDate, DAY };
