// Model.js
import { Schema, model } from "mongoose";

const loginSchema = new Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetToken: String,
  resetTokenExpiration: Date,
});

const Login = model("Login", loginSchema);

export default Login;









// import { Schema, model } from "mongoose";

// const loginSchema = new Schema({
//   email: { type: String, required: true, unique: true },
//   password: { type: String, required: true },
// });

// const Login = model("Login", loginSchema);

// export default Login;
