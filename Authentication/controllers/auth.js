const bcrypt = require('bcryptjs')
const nodemailer = require('nodemailer')
const endgridTransport = require('nodemailer-sendgrid-transport')
const crypto = require('crypto')
const {validationResult} = require('express-validator')
const User = require('../models/user');

const transporter = nodemailer.createTransport({
    service: 'gmail', auth: {
        user: '<mailname>@gmail.com', pass: '<app-password>'
    }
})

exports.getLogin = (req, res, next) => {
    let message = req.flash('error');
    if (message.length > 0) {
        message = message[0];
    } else {
        message = null;
    }
    res.render('auth/login', {
        path: '/login',
        pageTitle: 'Login',
        errorMessage: message,
        oldInput: {
            email: '',
            password: '',
        },
        validationErrors: []
    });
};

exports.getSignup = (req, res, next) => {
    let message = req.flash('error');
    if (message.length > 0) {
        message = message[0];
    } else {
        message = null;
    }
    res.render('auth/signup', {
        path: '/signup', pageTitle: 'Signup', errorMessage: message, oldInput: {
            email: "", password: "", confirmPassword: ""
        }, validationErrors: []

    });
};

exports.postLogin = (req, res, next) => {
    const email = req.body.email;
    const password = req.body.password;

    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        return res.status(422).render('auth/login', {
            path: '/login',
            pageTitle: 'Login',
            errorMessage: errors.array()[0].msg,
            oldInput: {
                email: email,
                password: password,
            },
            validationErrors: errors.array()
        });
    }

    User.findOne({email: email})
        .then((user) => {
            if (!user) {
                return res.status(422).render('auth/login', {
                    path: '/login', pageTitle: 'login',
                    errorMessage: 'Invalid email or password',
                    oldInput: {
                        email: email,
                        password: password,
                    },
                    validationErrors: []
                });
            }
            bcrypt.compare(password, user.password)
                .then((doMatch) => {
                    if (doMatch) {
                        req.session.isLoggedIn = true;
                        req.session.user = user;
                        return req.session.save(err => {
                            console.log(err);
                            res.redirect('/');
                        });
                    }
                    return res.status(422).render('auth/login', {
                        path: '/login', pageTitle: 'login',
                        errorMessage: 'Invalid email or password',
                        oldInput: {
                            email: email,
                            password: password,
                        },
                        validationErrors: []
                    });
                })
                .catch(err => console.log(err))
        })
        .catch(err => {
            const error = new Error('Error')
            error.httpStatusCode = 500;
            return next(error)
        });
};

exports.postSignup = (req, res, next) => {
    const email = req.body.email;
    const password = req.body.password;
    const confirmPassword = req.body.confirmPassword;

    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        return res.status(422).render('auth/signup', {
            path: '/signup', pageTitle: 'Signup', errorMessage: errors.array()[0].msg, oldInput: {
                email: email, password: password, confirmPassword: confirmPassword
            }, validationErrors: errors.array()
        });
    }
    bcrypt.hash(password, 12)
        .then(hashPassword => {
            const user = new User({
                email: email, password: hashPassword, cart: {items: []}
            })
            return user.save()
        }).then(result => {
        res.redirect('/login')
        const mailOptions = {
            to: email, from: 'bayzt.irem@gmail.com', subject: 'Signup succeeded!', text: 'Signup succeeded!'
        };

        return transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                console.log('Email error: ', error);
            } else {
                console.log('Email sent: ' + info.response);
            }
        });
    })
        .catch(err => {
            const error = new Error('Error')
            error.httpStatusCode = 500;
            return next(error)
        });
};

exports.postLogout = (req, res, next) => {
    req.session.destroy(err => {
        console.log(err);
        res.redirect('/');
    });
};

exports.getReset = (req, res, next) => {
    let message = req.flash('error');
    if (message.length > 0) {
        message = message[0];
    } else {
        message = null;
    }
    res.render('auth/reset', {
        path: '/reset', pageTitle: 'Reset Password', errorMessage: message
    });
};

exports.postReset = (req, res, next) => {
    crypto.randomBytes(32, (err, buffer) => {
        if (err) {
            console.log(err)
            return res.redirect('/reset')
        }
        const token = buffer.toString('hex')
        User.findOne({email: req.body.email})
            .then(user => {
                if (!user) {
                    req.flash('error', 'No account with that email found!')
                    return res.redirect('/reset')
                }
                user.resetToken = token;
                user.resetTokenExpiration = Date.now() + 3600000;
                user.save()
            })
            .then(result => {
                res.redirect('/')
                return transporter.sendMail({
                    to: req.body.email, from: 'bayzt.irem@gmail.com', subject: 'Reset Password!', html: `
                        <p>You request  password reset</p>
                        <p>Click this <a href="http://localhost:3000/reset/${token}">Link</a> to set a new password</p>                    
                    `
                })
            })
            .catch(err => {
                console.log(err)
                return res.redirect('/reset')
            })
    })
}

exports.getNewPassword = (req, res, next) => {
    const token = req.params.token

    User.findOne({resetToken: token, resetTokenExpiration: {$gt: Date.now()}})
        .then(user => {
            let message = req.flash('error');
            if (message.length > 0) {
                message = message[0];
            } else {
                message = null;
            }
            res.render('auth/new-password', {
                path: '/new-password',
                pageTitle: 'New Password',
                errorMessage: message,
                userId: user._id.toString(),
                passwordToken: token
            });
        })
        .catch(err => {
            const error = new Error('Error')
            error.httpStatusCode = 500;
            return next(error)
        });
}

exports.postNewPassword = (req, res, next) => {
    const newPassword = req.body.password;
    const userId = req.body.userId;
    const passwordToken = req.body.passwordToken
    let resetUser;

    User.findOne({
        resetToken: passwordToken, resetTokenExpiration: {$gt: Date.now()}, _id: userId
    })
        .then(user => {
            resetUser = user;
            return bcrypt.hash(newPassword, 12)
        })
        .then(hashPassword => {
            resetUser.password = hashPassword;
            resetUser.resetToken = null;
            resetUser.resetTokenExpiration = undefined;
            return resetUser.save()
        })
        .then(result => {
            res.redirect('/login')
        })
        .catch(err => {
            const error = new Error('Error')
            error.httpStatusCode = 500;
            return next(error)
        });
}