
export default {

    async legacyUsername (parent, args, context, info){
        const {collections}=context;
        const {users}=collections;
        const userObj=await users.findOne({"_id":context.userId})
        return "userObj.firstName";
    }

}