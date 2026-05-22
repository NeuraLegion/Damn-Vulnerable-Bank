var express = require('express');
var router = express.Router();
var Model = require('../../../models/index');
var Response = require('../../Response');
var statusCodes = require('../../statusCodes');
var { encryptResponse, decryptRequest } = require("../../../middlewares/crypt");
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "dvba_change_me_to_env_secret_9f4f2d7b7a734f85aab6b2439fd4b4c2";
const JWT_OPTIONS = {
    algorithm: "HS256",
    expiresIn: "15m",
    issuer: "dvba-api",
    audience: "dvba-mobile"
};

/**
 * Login route
 * This endpoint allows the user to login
 * @path                             - /api/user/login
 * @middleware                       - Checks admin authorization
 * @param username                   - Username to login
 * @param password                   - Password to login
 * @return                           - JWT token
 */
router.post('/', decryptRequest, (req, res) => {
    var r = new Response();
    let username = req.body.username;
    let password = req.body.password;
    
    Model.users.findOne({
        where: {
            username: username,
            password: password
        }
    }).then((data) => {
        if(data) {
            const accessToken = jwt.sign({
                username: data.username,
                is_admin: data.is_admin
            }, JWT_SECRET, JWT_OPTIONS);
            r.status = statusCodes.SUCCESS;
            r.data = {
                "accessToken": accessToken
            };
            return res.json(encryptResponse(r));
        } else {
            r.status = statusCodes.BAD_INPUT;
            r.data = {
                "message": "Incorrect username or password"
            }
            return res.json(encryptResponse(r));
        }
    }).catch((err) => {
        r.status = statusCodes.SERVER_ERROR;
        r.data = {
            "message": err.toString()
        };
        return res.json(encryptResponse(r));
    });
});

module.exports = router;
