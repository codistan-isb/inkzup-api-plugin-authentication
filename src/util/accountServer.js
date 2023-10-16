import mongoConnectWithRetry from "@reactioncommerce/api-core/src/util/mongoConnectWithRetry.js";
import { Mongo } from "@accounts/mongo";
import { AccountsServer } from "@accounts/server";
import { AccountsPassword } from "@accounts/password";
import mongoose from "mongoose";
import config from "../config.js";
import pkg from "@accounts/graphql-api";

const { AccountsModule } = pkg;
let accountsServer;
let accountsGraphQL;

export default async (app) => {
  if (accountsServer && accountsGraphQL) {
    return { accountsServer, accountsGraphQL };
  }
  const { MONGO_URL, STORE_URL, TOKEN_SECRET } = config;
  const { context } = app;
  const client = await mongoConnectWithRetry(MONGO_URL);
  const db = client.db();
  const accountsMongo = new Mongo(db, {
    convertUserIdToMongoObjectId: false,
    convertSessionIdToMongoObjectId: false,
    idProvider: () => mongoose.Types.ObjectId().toString(),
  });

  const password = new AccountsPassword({
    validateNewUser: async (user) => {
      // You can apply some custom validation
      const { legacyUsername, username, email } = user;
      let userObj = {};
      if (!email || email == "") {
        if (username === "insecure") {
          if (!legacyUsername || legacyUsername == "") {
            throw new Error(
              "legacyUsername is required with insecure username mode"
            );
          } else {
            const usersCollection = accountsMongo.db.collection("users");

            const UsernameExist = await usersCollection.findOne({
              username: legacyUsername,
            });

            const UserEmailExist = await usersCollection.findOne({
              "email.address": email,
            });

            console.log("user email already exists ", UserEmailExist);
            if (UsernameExist) {
              throw new Error("Username already exists");
            }
            if (UserEmailExist) {
              throw new Error("email already exists");
            }
          }
        }
      }
      userObj = {
        ...user,
        username: username === "insecure" ? user.legacyUsername : user.username,
      };

      // We specify all the fields that can be inserted in the database
      return userObj;
    },
  });

  accountsServer = new AccountsServer(
    {
      siteUrl: STORE_URL,
      tokenSecret: TOKEN_SECRET,
      db: accountsMongo,
      enableAutologin: true,
      tokenConfigs: {
        accessToken: {
          expiresIn: "30d",
        },
        refreshToken: {
          expiresIn: "90d",
        },
      },
      ambiguousErrorMessages: false,
      sendMail: async ({ to, text }) => {
        const query = text.split("/");
        const token = query[query.length - 1];
        const url = `${STORE_URL}/?resetToken=${token}`;
        await context.mutations.sendResetAccountPasswordEmail(context, {
          email: to,
          url,
        });
      },
      emailTemplates: {
        resetPassword: {
          from: null,
          // hack to pass the URL to sendMail function
          text: (user, url) => url,
        },
      },
    },
    {
      password,
    }
  );
  accountsGraphQL = AccountsModule.forRoot({ accountsServer });
  return { accountsServer, accountsGraphQL };
};
