const router = require("express").Router();
const verify = require("../verifytoken");

router.get("/", verify, (req, res) => {
  res.send("Post Page");
});

module.exports = router;
