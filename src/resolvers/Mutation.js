import { generatePhoneOtp, verifyOTP } from "../util/otp.js";
import bcrypt from "bcrypt";
// import { verifyOTP } from "../util/otp.js";
import encodeOpaqueId from "@reactioncommerce/api-utils/encodeOpaqueId.js";

import password_1 from "@accounts/password";
import server_1 from "@accounts/server";
import ReactionError from "@reactioncommerce/reaction-error";
import { sendEmailOTP } from "../util/otp.js";

const genericOtpFunc = async (createdUser, ctx) => {
  let data;
  if (createdUser.type == "phoneNo" && createdUser?.username) {
    console.log("here");
    data = await generatePhoneOtp(ctx, createdUser.username, userId);
    console.log("Phone otp response ", data);
  }
  if (createdUser.type == "email" && createdUser.emails.length) {
    data = await sendEmailOTP(ctx, createdUser.emails[0].address, "temp");
    console.log("Email is ", data);
  }

  return data;
};

export default {
  createUser: async (_, { user }, ctx) => {
    const { injector, infos } = ctx;
    const accountsServer = injector.get(server_1.AccountsServer);
    const accountsPassword = injector.get(password_1.AccountsPassword);
    let userId;
    try {
      userId = await accountsPassword.createUser(user);
    } catch (error) {
      // If ambiguousErrorMessages is true we obfuscate the email or username already exist error
      // to prevent user enumeration during user creation
      if (
        accountsServer.options.ambiguousErrorMessages &&
        error instanceof server_1.AccountsJsError &&
        (error.code === password_1.CreateUserErrors.EmailAlreadyExists ||
          error.code === password_1.CreateUserErrors.UsernameAlreadyExists)
      ) {
        return {};
      }
      throw error;
    }
    if (!accountsServer.options.enableAutologin) {
      return {
        userId: accountsServer.options.ambiguousErrorMessages ? null : userId,
      };
    }
    // When initializing AccountsServer we check that enableAutologin and ambiguousErrorMessages options
    // are not enabled at the same time
    const createdUser = await accountsServer.findUserById(userId);
    // If we are here - user must be created successfully
    // Explicitly saying this to Typescript compiler
    const loginResult = await accountsServer.loginWithUser(createdUser, infos);
    return {
      userId,
      loginResult,
    };
  },

  async createUserWithOtp(_, { user, profile }, ctx) {
    const { injector, infos, collections } = ctx;
    const accountsServer = injector.get(server_1.AccountsServer);
    const accountsPassword = injector.get(password_1.AccountsPassword);
    const { Accounts, users } = collections;
    let userId;
    if (!(user?.email || user.username)) {
      throw new ReactionError(
        "invalid-parameter",
        "Please provide either an email address or a phone number to proceed."
      );
    }

    if (user.username) {
      console.log("added p");
      user.username = "p" + user.username;
      console.log("new user name is ", user.username);
    }

    try {
      userId = await accountsPassword.createUser(user);
    } catch (error) {
      // If ambiguousErrorMessages is true we obfuscate the email or username already exist error
      // to prevent user enumeration during user creation
      if (
        accountsServer.options.ambiguousErrorMessages &&
        error instanceof server_1.AccountsJsError &&
        (error.code === password_1.CreateUserErrors.EmailAlreadyExists ||
          error.code === password_1.CreateUserErrors.UsernameAlreadyExists)
      ) {
        return {};
      }
      throw error;
    }
    if (!accountsServer.options.enableAutologin) {
      return {
        userId: accountsServer.options.ambiguousErrorMessages ? null : userId,
      };
    }

    const adminCount = await Accounts.findOne({
      _id: userId,
    });
    console.log("adminCount", adminCount);
    if (userId) {
      console.log("user", user);
      const account = {
        _id: userId,
        acceptsMarketing: false,
        emails: [
          {
            address: user.email,
            verified: false,
            provides: "default",
          },
        ],
        groups: [],
        name: null,
        profile: {
          firstName: profile.firstName,
          lastName: profile.lastName,
          state: profile.state,
          city: profile.city,
          phone: profile.phone,
        },
        shopId: null,
        state: "new",
        userId: userId,
        isDeleted: false,
        type: user.type,
      };
      const accountAdded = await Accounts.insertOne(account);

      //console.log("addedd acount is ",accountAdded);
    }
    // When initializing AccountsServer we check that enableAutologin and ambiguousErrorMessages options
    // are not enabled at the same time
    const createdUser = await accountsServer.findUserById(userId);
    console.log("create user is ", createdUser);
    // If we are here - user must be created successfully
    // Explicitly saying this to Typescript compiler
    // const loginResult = await accountsServer.loginWithUser(createdUser, infos);
    //console.log("Login Result ", loginResult);

    let genericOtpResponse = await genericOtpFunc(createdUser, ctx);
    console.log("genericOtpResponse ", genericOtpResponse);
    return {
      userId,
      // loginResult,
      createdUser,
    };
  },

  async verifyOTPSignUp(_, { user }, ctx) {
    // const { serviceName, params } = args;
    const { injector, infos, collections } = ctx;
    const { users, Accounts } = collections;

    //checking if account is deleted or not
    const checkedAccount = await ctx.mutations.deleteAccountCheck(ctx, {
      userId: user.userId,
    });

    if (!user.userId) {
      throw new ReactionError(
        "invalid-parameter",
        "Please provide userId to proceed."
      );
    }

    try {
      console.log("User Id is ", user);
      const userObj = await users.findOne({ _id: user.userId });
      console.log("User Id is ", userObj);

      if (userObj) {
        if (userObj.otp === user.otp) {
          console.log("Same otp now check expiration date");

          const expirationTime = new Date().getTime() + 15 * 60 * 1000;

          // Check if the OTP is still valid
          const isOtpValid = expirationTime > new Date().getTime();
          console.log("isOtpValid ", isOtpValid);
          // Use the value of isOtpValid to perform further actions, for example:
          if (isOtpValid) {
            console.log("OTP is still valid");
            let updateOtp;
            const options = { new: true };

            if (userObj.type === "phoneNo") {
              console.log("in phone");
              updateOtp = { $set: { phoneVerified: true } };
            } else if (userObj.type === "email") {
              console.log("in email");
              updateOtp = { $set: { "emails.0.verified": true } };
            } else {
              console.log("error in loginType");
            }
            const { result } = await users.updateOne(
              { _id: userObj._id },
              updateOtp,
              options
            );

            const { result: accountResult } = await Accounts.updateOne(
              { _id: userObj._id },
              updateOtp,
              options
            );

            console.log("Accounts Result is ", accountResult);

            return result.n;
          } else {
            console.log("OTP has expired");
            return false;
            // Perform further actions for expired OTP
          }
        } else {
          throw new ReactionError("not-found", "Otp is incorrect");
        }
      } else {
        throw new ReactionError("not-found", "Could not found user");
      }
    } catch (err) {
      console.log(err);
      throw new ReactionError(
        "server-error",
        "Something went wrong.Please try again later."
      );
    }
  },

  // async regenerateOtp(_, { user }, ctx) {},

  async loginUser(_, { user }, ctx) {
    const { injector, infos, collections } = ctx;
    const accountsServer = injector.get(server_1.AccountsServer);
    const accountsPassword = injector.get(password_1.AccountsPassword);
    const { Accounts, users } = collections;
    let isVerified = false;
    let userData;
    let newObj;
    if (!(user?.email || user?.username)) {
      throw new ReactionError(
        "invalid-parameter",
        "Please provide either an email address or a phone number to proceed."
      );
    }

    if (user?.email) {
      userData = await users.findOne({ "emails.address": user.email });
    }

    if (user?.username) {
      console.log("added p");
      user.username = "p" + user.username;
      console.log("new user name is ", user.username);
      userData = await users.findOne({ username: user.username });
    }

    if (!userData) {
      throw new ReactionError("not-found", "Account not found");
    }

    //checking if account is deleted or not
    const checkedAccount = await ctx.mutations.deleteAccountCheck(ctx, {
      userId: userData._id,
    });

    if (!accountsServer.options.enableAutologin) {
      return {
        userId: accountsServer.options.ambiguousErrorMessages
          ? null
          : userData._id,
      };
    }

    if (userData.type === "email") {
      console.log("login type is email");
      isVerified = userData.emails[0].verified;
      newObj = {
        user: {
          email: user.email,
        },
        password: user.password,
      };
    }

    if (userData.type === "phoneNo") {
      isVerified = userData.phoneVerified;
      newObj = {
        user: {
          username: user.username,
        },
        password: user.password,
      };
    }

    console.log("userData", userData.emails);

    if (!isVerified) {
      throw new ReactionError(
        "not-found",
        "User is not verified,Regenerate verify"
      );
    }

    // When initializing AccountsServer we check that enableAutologin and ambiguousErrorMessages options
    // are not enabled at the same time
    const createdUser = await accountsServer.findUserById(userData._id);
    const account = await Accounts.findOne({ _id: userData._id });
    console.log("create user is ", createdUser);
    console.log("password is ", createdUser.services.password.bcrypt);
    createdUser.services.password.bcrypt = user.password;
    console.log("new create user is ", createdUser);

    console.log("account is ", account)
    // If we are here - user must be created successfully
    // Explicitly saying this to Typescript compiler
    // const loginResult = await accountsServer.loginWithUser(createdUser, infos);
    // console.log("Login Result ", loginResult);

    const authenticated = await injector
      .get(server_1.AccountsServer)
      .loginWithService("password", newObj, infos);

    console.log("authenticated is ", authenticated);
    console.log("created user is", createdUser);
    let shopId = account?.adminUIShopIds ? account.adminUIShopIds[0] : "";

    if (shopId) shopId = encodeOpaqueId("reaction/shop", shopId);

    return {
      loginResult: authenticated,
      shopId,
    };
  },

  async resetPasswordOtp(_, { user }, ctx) {
    const { injector, infos, collections } = ctx;
    const accountsServer = injector.get(server_1.AccountsServer);
    const accountsPassword = injector.get(password_1.AccountsPassword);
    const { Accounts, users } = collections;
    let userData;

    if (!(user.type && user.emailPhone)) {
      throw new ReactionError(
        "invalid-parameter",
        "Please provide either an email address or a phone number to proceed."
      );
    }

    if (user.type === "phoneNo") {
      userData = await users.findOne({ username: user.emailPhone });
    }
    if (user.type === "email") {
      userData = await users.findOne({ "emails.address": user.emailPhone });
    }

    if (!userData) {
      throw new ReactionError("not-found", "Account not found");
    }

    //checking if account is deleted or not
    const checkedAccount = await ctx.mutations.deleteAccountCheck(ctx, {
      userId: userData._id,
    });

    let data = await genericOtpFunc(userData, ctx);

    if (data) {
      return {
        userId: userData._id,
        success: true,
      };
    }
    return {
      userId: userData._id,
      success: false,
    };
  },

  async resetPasswordOtpVerify(_, { user }, ctx) {
    const { injector, infos, collections } = ctx;
    const { users } = collections;
    const salt = bcrypt.genSaltSync();

    console.log("in reset password otp verify");

    if (!user.userId) {
      throw new ReactionError(
        "invalid-parameter",
        "Please provide userId to proceed."
      );
    }

    if (!user.password) {
      throw new ReactionError(
        "invalid-parameter",
        "Please provide new password"
      );
    }

    //checking if account is deleted or not
    const checkedAccount = await ctx.mutations.deleteAccountCheck(ctx, {
      userId: user.userId,
    });

    console.log("User Id is ", user);
    const userObj = await users.findOne({ _id: user.userId });
    console.log("User Id is ", userObj);

    if (userObj) {
      if (userObj.otp === user.otp) {
        console.log("Same otp now check expiration date");

        const expirationTime = new Date().getTime() + 15 * 60 * 1000;

        // Check if the OTP is still valid
        const isOtpValid = expirationTime > new Date().getTime();
        console.log("isOtpValid ", isOtpValid);
        // Use the value of isOtpValid to perform further actions, for example:
        if (isOtpValid) {
          console.log("OTP is still valid");
          let updateOtp;
          const options = { new: true };

          console.log(
            "createdUser.services.password.bcrypt ",
            userObj.services.password.bcrypt
          );

          const hashedPassword = bcrypt.hashSync(user.password, salt);

          if (userObj.type === "phoneNo") {
            console.log("in phone");
            updateOtp = {
              $set: {
                "services.password.bcrypt": hashedPassword,
                phoneVerified: true,
              },
            };
          } else if (userObj.type === "email") {
            console.log("in email");
            updateOtp = {
              $set: {
                "services.password.bcrypt": hashedPassword,
                "emails.0.verified": true,
              },
            };
          } else {
            console.log("error in loginType");
          }

          console.log("Original Password:", user.password);
          console.log("Hashed Password:", hashedPassword);

          const { result } = await users.updateOne(
            { _id: userObj._id },
            updateOtp,
            options
          );
          return result.n > 0 ? true : false;
        } else {
          console.log("OTP has expired");
          return false;
          // Perform further actions for expired OTP
        }
      } else {
        throw new ReactionError("not-found", "Otp is incorrect");
      }
    } else {
      throw new ReactionError("not-found", "Could not found user");
    }
  },

  changePassword: async (_, input, context) => {
    let { oldPassword, newPassword } = input;
    let { user, injector } = context;
    console.log("mutations is ", context.mutations);
    if (!(user && user.id)) {
      throw new Error("Unauthorized");
    }

    const userId = user.id;
    console.log("before delete account check");
    //checking if account is deleted or not
    const checkedAccount = await context.mutations.deleteAccountCheck(context, {
      userId: user.userId,
    });

    let responsePassword = await injector
      .get(password_1.AccountsPassword)
      .changePassword(userId, oldPassword, newPassword);
    console.log("change password response ", responsePassword);
    return true;
  },

  authenticate: async (_, args, ctx) => {
    const { serviceName, params } = args;
    const { injector, infos, collections } = ctx;
    const { users } = collections;
    console.log("authenticate");
    const authenticated = await injector
      .get(server_1.AccountsServer)
      .loginWithService(serviceName, params, infos);
    return authenticated;
  },
  // authenticateWithOTP: async (_, args, ctx) => {
  //   const { serviceName, params } = args;
  //   const { injector, infos, collections } = ctx;
  //   const { users } = collections;
  //   const userExist = await users.findOne({
  //     "emails.0.address": params?.user?.email,
  //   });
  //   console.log("user exist is ", userExist);
  //   //const resOTP = await verifyOTP(userExist.phone, params.code, ctx);

  //   // console.log(userExist)
  //   // if (userExist.phoneVerified) {
  //   //         const authenticated = await injector
  //   //                 .get(server_1.AccountsServer)
  //   //                 .loginWithService(serviceName, params, infos);
  //   //         return authenticated;
  //   // }
  //   // else
  //   if (!resOTP?.status) {
  //     return null;
  //   } else {
  //     const authenticated = await injector
  //       .get(server_1.AccountsServer)
  //       .loginWithService(serviceName, params, infos);
  //     console.log("authenticated", authenticated);
  //     return authenticated;
  //   }
  // },
};
