const { validationResult } = require('express-validator/check');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const User = require('../models/user');


exports.signUp = (req, res, next) => {
    const err = validationResult(req);
    if (!err.isEmpty()) {
        const error = new Error('Validation failed!, entered data is incorrect.');
        error.statusCode = 422;
        error.data = err.array();
        throw error;
    }
    const email = req.body.email;
    const name = req.body.name;
    const password = req.body.password;
    bcrypt.hash(password, 12)
        .then(hashedPsd => {
            const user = new User({
                email: email,
                password: hashedPsd,
                name: name
            });
            return user.save();
        })
        .then(result => {
            res.status(201).json({ message: 'User Created', userId: result._id });
        })
        .catch(err => {
            if (!err.statusCode) {
                err.statusCode = 500;
            }
            next(err);
        });
};


exports.login = (req, res, next) => {
    const email = req.body.email;
    const password = req.body.password;
    let loadedUser;
    User.findOne({ email: email })
        .then(user => {
            if (!user) {
                const error = new Error('User not found with this email ID!');
                error.statusCode = 401;
                throw error;
            }
            loadedUser = user;
            return bcrypt.compare(password, user.password);
        })
        .then(isEqual => {
            if (!isEqual) {
                const error = new Error('Password is incorrect.');
                error.statusCode = 401;
                throw error;
            }
            const token = jwt.sign({
                email: loadedUser.email,
                userId: loadedUser._id.toString()
            },
                'thisupersecretisgeneratedbykrat',
                { expiresIn: '1h' }
            );
            res.status(200).json({ message: 'Success', token: token, userId: loadedUser._id.toString() });
        })
        .catch(err => {
            if (!err.statusCode) {
                err.statusCode = 500;
            }
            next(err);
        });
};