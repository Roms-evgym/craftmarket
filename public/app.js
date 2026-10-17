
const allowed =
  Number(job.owner_id) === Number(req.user.id) ||
  Number(job.worker_id) === Number(req.user.id) ||
  (job.status === "open" &&
   Number(req.user.id) !== Number(job.owner_id));
