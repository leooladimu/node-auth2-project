const { JWT_SECRET } = require("../secrets") // use this secret!
const jwt = require("jsonwebtoken")
const User = require("./../users/users-model")

const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if (!token) {
    return next({ status: 401, message: "Token required" })
  }
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return next({
        status: 401,
        message: "Token invalid",
      })
    }
    req.decodedJwt = decoded
    next()
  })
}

  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */


const only = role_name => (req, res, next) => {
  if (req.decodedJwt.role_name !== role_name) {
    next({
      status: 403,
      message: "This is not for you"
    })
  } else {
    next()
  }
}

  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */

const checkUsernameExists = (req, res, next) => {
  User.findBy({ username: req.body.username })
  .then((user) => {
    user.length < 1
    ? next({ status: 401, message: "Invalid credentials" })
    : (req.userFromDb = user[0])
    next()
  })
  .catch(next)
}

  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */

const validateRoleName = (req, res, next) => {
  if (req.body.role_name === undefined) {
    req.body.role_name = "student"
    next()
  } else {
    const trimmedRole = req.body.role_name.trim()
    if (!trimmedRole) {
      req.body.role_name = "student"
      next()
    } else if (trimmedRole === "admin") {
      next({ status: 422, message: "role name can not be admin" })
    } else if (trimmedRole.length > 32) {
      next({
        status: 422,
        message: "role name can not be longer than 32 chars"
      })
    } else {
      req.body.role_name = trimmedRole
      next()
    }
  }
}

  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only
}
