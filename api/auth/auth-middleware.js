const { JWT_SECRET } = require("../secrets"); // use this secret!
const { body, checkSchema, validationResult } = require("express-validator");
const jwt = require("jsonwebtoken")
const {findBy} = require("../users/users-model");
const bcrypt = require("bcryptjs");
const checkValidationResult=(req,res,next)=>{
  const errors = validationResult(req);
  if(errors.isEmpty()){
    next();
  }
  else{
    const {status,message} = errors.array()[0].msg;
    res.status(status).json({message});
  } 
}

const restricted = [
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
    // new Promise((resolve,reject)=>{
    //   try{
    //     const decoded = jwt.verify(value,JWT_SECRET);
    //     req.decoded = decoded;
    //     resolve();
    //   }
    //   catch(err){
    //     reject();
    //   }
    // });
    // header("authorization.token").isString().withMessage()
    checkSchema({
      "authorization.token":{
        in:["header"],
        isString:{
          errorMessage:{status:401,message:"Token required"}
        },
        custom:{
          options:(value,{req})=>{ //this callback is a validator
            try{
              req.decoded = jwt.verify(value,JWT_SECRET);
              return true;
            }
            catch{
              return false;
            }
          },
          errorMessage:{status:401,message:"Token invalid"}
        }
      }
    }),
    checkValidationResult
]

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
    if(role_name === req.decoded.role_name){
      next();
    }
    else{
      res.status(403).json({message:"This is not for you"});
    }
}


const checkUsernameExists = [
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
    body("username").isString()
    .custom(async(value,{req})=>{
      const usersFound = await findBy({username:value});
      if(usersFound.length !== 1){
        return Promise.reject();
      }
      const user = usersFound[0];
      const isValid = bcrypt.compareSync(req.body.password,user.password);
      if(!isValid){
        return Promise.reject();
      }
      req.user = user;
      return Promise.resolve();
    })
    .withMessage({
      status:401,
      message:"Invalid credentials"
    }),
    checkValidationResult
]

const validateRoleName = [
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
    checkSchema({
      role_name:{
        trim:{},
        customSanitizer:{
          options:(value)=>value===""?"student":value
        },
        custom:{
          options:(value)=>value!=="admin",
          errorMessage:{status:422,message:"Role name can not be admin"}
        },
        isLength:{
          options:{max:32},
          errorMessage:{status:422,message:"Role name can not be longer than 32 chars"}
        }
      }
    }),
    checkValidationResult   
  ]

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
