import pkg from "../package.json";
import tokenMiddleware from "./util/tokenMiddleware.js";
import getAccounts from "./util/accountServer.js";
import Account from "./resolvers/Account.js";
import Mutation from "./resolvers/Mutation.js";

import importAsString from "@reactioncommerce/api-utils/importAsString.js";

const mySchema = importAsString("./schema.graphql");

/**
 * @summary Registers the authentication plugin
 * @param {ReactionAPI} app The ReactionAPI instance
 * @returns {undefined}
 */
export default async function register(app) {
  const { accountsGraphQL, accountsServer } = await getAccounts(app);

  let ResolverObj = accountsGraphQL.resolvers;
  ResolverObj["Account"] = Account;
  ResolverObj["Mutation"] = Mutation;
  await app.registerPlugin({
    label: "Authentication-LoS",
    name: "authentication",
    autoEnable: true,
    version: pkg.version,
    functionsByType: {
      graphQLContext: [({ req }) => accountsGraphQL.context({ req })],
    },
    collections: {
      users: {
        name: "users",
      },
    },
    graphQL: {
      schemas: [mySchema],
      typeDefsObj: [accountsGraphQL.typeDefs],
      resolvers: ResolverObj,
    },
    expressMiddleware: [
      {
        route: "graphql",
        stage: "authenticate",
        fn: tokenMiddleware,
      },
    ],
  });
}
