import CurrentUserDTO from "../DTOs/currentuser.dto.js";

export const roleauth = (role) => {
    return (req, res, next) => {
        req.user = new CurrentUserDTO(req.user);
        if (req.user.role === role) return next();

        res.status(403).send({
            status: "error",
            message: "Unauthorized"
        })
    }
}