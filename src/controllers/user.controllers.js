const catchError = require('../utils/catchError');
const User = require('../models/User');
const EmailCode = require('../models/EmailCode')
const bcrypt = require('bcrypt');
const sendEmail = require('../utils/sendEmail');
const jwt = require('jsonwebtoken')

const getAll = catchError(async(_req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const {email, password, firstName, lastName, country, image, frontBaseUrl} = req.body
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
        email,
        password: hashedPassword,
        firstName, 
        lastName, 
        country, 
        image
    });
    const code = require('crypto').randomBytes(32).toString("hex");
    const link = `${frontBaseUrl}/verify_email/${code}`
    await sendEmail({
        to: email,
        subject: "veficate email for user app",
        html:`
        <h1>Hello ${firstName} ${lastName}</h1>
        <p>Verify your account cheking the link</p>
        <a href=${link} target="_blank">${link}</a>
        `
    })
    await EmailCode.create({ code, userId: user.id })
    return res.status(201).json({user, message:"Email sent succesfully"});
});

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    await User.destroy({ where: {id} });
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.update(
        req.body,
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyCode = catchError(async(req, res) => {
    const { code }= req.params;
    const codeFound = await EmailCode.findOne( { where: { code } } );
    if (!codeFound)return res.status(401).json({message: 'Invalid code' });
    const user = await User.update(
        { isVerified: true },
        { where: { id: codeFound.userId } , returning: true }
    );
    await codeFound.destroy();
    return res.json(user);
});

const login = catchError(async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ where: {email} });
    if(!user) return res.status(401).json({ message: "invalid credentials" });
    const isValid = await bcrypt.compare(password, user.password);
    if(!isValid) return res.status(401).json({ message: "invalid credentials" });
    if(!user.isVerified)return res.status(401).json({ message: "Not Verified" });
    const token = jwt.sign(
        {user},
        process.env.TOKEN_SECRET,
        { expiresIn: "1d" }
    )
    return res.json({user, token});
});

const getLoggedUser = catchError(async(req, res) => {
    const user = req.user;
    return res.json(user);
});

const linkPassword = catchError(async(req, res)=>{
    const {email, frontBaseUrl} = req.body;
    const user = await User.findOne({ where: {email} });
    if(!user) return res.status(401).json({ message: "invalid email" }); 
    //Debe buscar el usuario al que le pertenezca el email del body. Si no lo encuentra debe retornar 401
    const code = require('crypto').randomBytes(32).toString("hex");
    //Debe generar un código
    const link = `${frontBaseUrl}/reset_password/${code}`
    await sendEmail({
        to: email,
        subject: "Reset youy password for user app",
        html:`
        <h1>Hello User</h1>
        <p>Reset youy password cheking the link</p>
        <a href=${link} target="_blank">${link}</a>
        `
    });
    //Debe enviar un correo al usuario con este link {frontBaseUrl}/reset_password/{code}
    await EmailCode.create({
        code:code,
        userId:user.id
    });
    //Guardará el código y el id del usuario encontrado en EmailCode
    return res.status(201).json({ message: "Send email for reset password" });
});

const resetPassword = catchError( async (req, res) => {
    const { password } = req.body;
    // Recibirá en el body la nueva contraseña
    const { code } = req.params
    // Debe recibir el código generado anteriormente por parámetros 
    const codeFound = await EmailCode.findOne( { where: {code} } )
    if(!codeFound) return res.status(401).json({ message: "invalid code" });
    //Verificar que el código esté en el modelo EmailCode, de lo contrario devolver 401
    const hashedPassword = await bcrypt.hash(password, 10);
    //Debe encriptar la contraseña
    await User.update(
        { password: hashedPassword },
        { where: { id: codeFound.userId }}
    );
    //Debe actualizar la contraseña al usuario del código de EmailCode.
    return res.status(201).json({ message: "Update password" });
});

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyCode,
    login, 
    getLoggedUser,
    linkPassword,
    resetPassword
}