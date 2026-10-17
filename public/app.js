
const allowed = job.owner_id === req.user.id ||
  job.worker_id === req.user.id ||
  (job.status === "open" && req.user.id !== job.owner_id);
