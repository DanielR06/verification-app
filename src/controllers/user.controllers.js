const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const sendEmail = require('../utils/sendEmail');

const getAll = catchError(async(req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const {email, password, firstName, lastName, country, image} = req.body
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await User.create({
        email,
        password: hashedPassword,
        firstName, 
        lastName, 
        country, 
        image
    });
    await sendEmail({
        to: email,
        subject: "veficate email for user app",
        html:`
        <h1>Hello ${firstName} ${lastName}</h1>
        <p>Thanks for sing in user app</p>
        `
    })
    return res.status(201).json({result, message:"Email sent succesfully"});
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

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update
}