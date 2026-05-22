const Model = require("../models/index");
const Response = require('../lib/Response');
const statusCodes = require("../lib/statusCodes");
const jwt = require("jsonwebtoken");
var { encryptResponse } = require("../middlewares/crypt");

const JWT_SECRET = process.env.JWT_SECRET || "dvba_change_me_to_env_secret_9f4f2d7b7a734f85aab6b2439fd4b4c2";
const JWT_VERIFY_OPTIONS = {
  algorithms: ["HS256"],
  issuer: "dvba-api",
  audience: "dvba-mobile"
};

/**
 * User token validation middleware
 * This middleware validates user JWT token, extracts the associated
 * account number of user and adds it to the request object
 * @header authorization             - JWT token
 * @return                           - Calls the next function on success
 */
const validateUserToken = function(req, res, next) {
  var r = new Response();

  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) {
      r.status = statusCodes.NOT_AUTHORIZED;
      r.data = {
        "message": "Not authorized"
      }
      return res.status(401).json(encryptResponse(r));
  }

  jwt.verify(token, JWT_SECRET, JWT_VERIFY_OPTIONS, (err, data) => {
      if (err) {
          r.status = statusCodes.FORBIDDEN;
          r.data = {
              "message": err.toString()
          }
          return res.status(403).json(encryptResponse(r));
      }
      
      Model.users.findOne({
          where: {
              username: data.username
          },
          attributes: ["account_number"]
      }).then((data) => {
          req.account_number = data.account_number;
          next();
      }).catch((err) => {
        r.status = statusCodes.SERVER_ERROR;
        r.data = {
            "message": err.toString()
        };
        return res.status(500).json(encryptResponse(r));
    });
  });
};

/**
 * Admin token validation middleware
 * This middleware validates admin JWT token, extracts the associated
 * account number of admin and adds it to the request object along with
 * is_admin flag
 * @header authorization             - JWT token
 * @return                           - Calls the next function on success
 */
const validateAdminToken = function(req, res, next) {
    var r = new Response();
  
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
  
    if (token == null) {
        r.status = statusCodes.NOT_AUTHORIZED;
        r.data = {
            "message": "Not authorized"
        }
        return res.status(401).json(encryptResponse(r));
    }
  
    jwt.verify(token, JWT_SECRET, JWT_VERIFY_OPTIONS, (err, data) => {
        if (err) {
            r.status = statusCodes.FORBIDDEN;
            r.data = {
                "message": err.toString()
            }
            return res.status(403).json(encryptResponse(r));
        }
        
        Model.users.findOne({
            where: {
                username: data.username
            },
            attributes: ["account_number", "is_admin"]
        }).then((data) => {
            req.account_number = data.account_number;
            if (!data.is_admin) {
                r.status = statusCodes.FORBIDDEN;
                r.data = {
                    "message": "Exclusive endpoint for admins only"
                };
                return res.status(403).json(encryptResponse(r));
            } else {
                next();
            }
        }).catch((err) => {
            r.status = statusCodes.SERVER_ERROR;
            r.data = {
                "message": err.toString()
            };
            return res.status(500).json(encryptResponse(r));
        });
    });
};

module.exports =  {
    validateUserToken,
    validateAdminToken
}
