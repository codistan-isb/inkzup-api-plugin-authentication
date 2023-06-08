import _ from "lodash";
import ReactionError from "@reactioncommerce/reaction-error";
import config from "../config.js";
import generateOTPForResetPassword from "./generateOTPForResetPassword.js";
import Twilio from "twilio";

// const { REACTION_IDENTITY_PUBLIC_VERIFY_EMAIL_URL } = config;

/**
 * @method sendVerificationEmail
 * @summary Send an email with a link the user can use verify their email address.
 * @param {Object} context Startup context
 * @param {Object} input Input options
 * @param {String} input.userId - The id of the user to send email to.
 * @param {String} [input.bodyTemplate] Template name for rendering the email body
 * @returns {Job} - returns a sendEmail Job instance
 */

var dict = {};

var accountSid = process.env.TWILIO_ACCOUNT_SID;
var authToken = process.env.TWILIO_AUTH_TOKEN;
const client = new Twilio(accountSid, authToken);

export async function sendEmailOTP(
  context,
  email,
  { bodyTemplate = "accounts/otpEmail", temp }
) {
  //{ bodyTemplate = "coreDefault", userId }
  //console.log("User ID", userId);

  const {
    collections: { Accounts, Shops, users },
  } = context;

  console.log("email is ", email);
  const { otp, expirationTime } = await generateOTPForResetPassword();
  console.log(`Your OTP is: ${otp}`);
  console.log(`Expires at: ${new Date(expirationTime).toLocaleTimeString()}`);

  //   const { users } = context.collections;
  const options = { new: true };
  const updateOtp = { $set: { otp: otp, expirationTime: expirationTime } };

  const UserData = await users.findOne({ "emails.address": email });
  if (!UserData) {
    // The user document does not exist, throw an error or handle it as needed
    throw new ReactionError("not-found", "Account not found");
  }
  console.log("User Response :- ", UserData._id);
  const account = await Accounts.findOne({ _id: UserData._id });
  console.log("Account Resonse :-", account);
  if (!account) throw new ReactionError("not-found", "Account not found");

  const updateUserResult = await users.updateOne(
    { "emails.address": email },
    updateOtp,
    options
  );

  console.log("otp and expiry updated: ", updateUserResult);

  // Account emails are always sent from the primary shop email and using primary shop
  // email templates.
  const shop = await Shops.findOne({ shopType: "primary" });
  if (!shop) throw new ReactionError("not-found", "Shop not found");

  const dataForEmail = {
    // Reaction Information
    contactEmail: "awahab1116@gmail.com",
    homepage: _.get(shop, "storefrontUrls.storefrontHomeUrl", null),
    copyrightDate: new Date().getFullYear(),
    legalName: _.get(shop, "addressBook[0].company"),
    physicalAddress: {
      address: `${_.get(shop, "addressBook[0].address1")} ${_.get(
        shop,
        "addressBook[0].address2"
      )}`,
      city: _.get(shop, "addressBook[0].city"),
      region: _.get(shop, "addressBook[0].region"),
      postal: _.get(shop, "addressBook[0].postal"),
    },
    shopName: shop.name,
    // confirmationUrl: REACTION_IDENTITY_PUBLIC_VERIFY_EMAIL_URL.replace("TOKEN", token),
    confirmationUrl: otp,
    userEmailAddress: "awahab1116@gmail.com",
  };
  const language =
    (account.profile && account.profile.language) || shop.language;

  return context.mutations.sendEmail(context, {
    data: dataForEmail,
    fromShop: shop,
    templateName: bodyTemplate,
    language,
    to: "awahab1116@gmail.com",
  });
}

export async function generatePhoneOtp(context, number, userId) {
  const {
    collections: { Accounts, Shops, users },
  } = context;

  console.log("generate phone otp is ");
  console.log("User ID", userId);
  console.log("phone number is ", number);
  const { otp, expirationTime } = await generateOTPForResetPassword();
  console.log(`Your OTP is: ${otp}`);
  console.log(`Expires at: ${new Date(expirationTime).toLocaleTimeString()}`);

  //   const { users } = context.collections;
  const options = { new: true };
  const updateOtp = { $set: { otp: otp, expirationTime: expirationTime } };

  const UserData = await users.findOne({ username: number });
  if (!UserData) {
    // The user document does not exist, throw an error or handle it as needed
    throw new ReactionError("not-found", "Account not found");
  }
  console.log("User Response :- ", UserData._id);
  const account = await Accounts.findOne({ _id: UserData._id });
  console.log("Account Resonse :-", account);
  if (!account) throw new ReactionError("not-found", "Account not found");

  const updateAccountResult = await users.updateOne(
    { username: number },
    updateOtp,
    options
  );

  console.log("otp and expiry updated: ", updateAccountResult);

  return otp;

  // return new Promise((resolve, reject) => {
  //   try {
  //     // let min = 100000;
  //     // let max = 999999;
  //     // let my_otp = 123456; // () => [ min, max );
  //     // // let my_otp = Math.floor(Math.random() * (max - min + 1) + min); // () => [ min, max );
  //     // dict[number] = { code: my_otp, expiry: new Date().getTime() + 60000 };
  //     // console.log(
  //     //   "otp generated",
  //     //   number,
  //     //   "Your verification code for is " + my_otp
  //     // );

  //     sendOtp(number, "Your verification code for is " + my_otp)
  //       .then((res) => {
  //         console.log("send otp response");
  //         console.log(res);
  //         resolve(true);
  //       })
  //       .catch((err) => {
  //         console.log(err);
  //         resolve(false);
  //       });

  //     // return res;
  //   } catch (err) {
  //     console.log("reaching", err);
  //     resolve(false);
  //   }
  // });
}

export async function verifyOTP(number, otp, context) {
  console.log(number, otp);
  if (dict[number] == undefined || dict[number] == {}) {
    return {
      status: false,
      response: "OTP code invalid",
    };
  }
  const isValid = dict[number]["expiry"] - new Date().getTime() > 0;
  console.log("isValid", isValid);
  if (!isValid) {
    delete dict[number];

    return {
      status: false,
      response: "OTP code expired",
    };
  }
  const res = dict[number]["code"] == otp;
  if (res == true) {
    delete dict[number];
    const { collections } = context;
    const { users } = collections;

    const userObj = await users.updateOne(
      { phone: number },
      {
        $set: { phoneVerified: "true" },
        $set: { transactionId: "testtransactionid" },
      }
    );
    console.log("isValid", isValid);

    return {
      status: true,
      response: "Verified successfully",
    };
  } else {
    return {
      status: false,
      response: "Invalid code entered",
    };
  }
}
