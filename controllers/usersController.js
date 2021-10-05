const { User, Review } = require('../models')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const joi = require('joi')



require('dotenv').config()

module.exports = {
    signUp: async(req, res) => {
        const body = req.body
        try {
            const schema = joi.object({
                fullName: joi.string().required(),
                email: joi.string().required(),
                password: joi.string().min(6).required(),
                isAdmin: joi.string()
            })

            const { error } = schema.validate({...body }, { abortEarly: false })

            if (error) {
                return res.status(400).json({
                    status: "failed",
                    message: "Please input email or password",
                    error: error["details"][0]["message"]
                })
            }

            const checkEmail = await User.findOne({ where: { email: body.email } })
            if (checkEmail) {
                return res.status(400).json({
                    status: "failed",
                    message: "email already used"
                })
            }

            bcrypt.hash(body.password, 10, async(err, hash) => {
                const createUser = await User.create({
                    fullName: body.fullName,
                    email: body.email,
                    password: hash,
                    isAdmin: false
                })

                return res.status(200).json({
                    status: "Success",
                    message: "Register successfully",
                })
            })

        } catch (error) {
            res.status(500).json({
                status: "failed",
                message: "Internal Server Error"
            })
        }
    },
    editUserBasic: async(req, res) => {
        const body = req.body
        const user = req.user
        const profilePict = req.file ? req.file.path : body.profilePict
        try {
            const findUser = await User.findOne({ where: { id: user.id } })
            if (!findUser) {
                return res.status(400).json({
                    status: "failed",
                    message: "User not found"
                })
            }
            const edit = await User.update({
                email: body.email,
                password: body.password,
                fullName: body.fullName,
                profilePict: profilePict,
                isAdmin: false
            }, {
                where: {
                    id: user.id
                }
            })

            if (!edit) {
                res.status(400).json({
                    status: "failed",
                    message: "Cannot Update Data"
                })
            }

            return res.status(200).json({
                status: "success",
                message: "success updated data"
            })

        } catch (error) {
            res.status(500).json({
                status: "failed",
                message: "Internal Server Error"
            })
        }
    },
    editUserByAdmin: async(req, res) => {
        const id = req.params.id
        try {
            const findUser = await User.findOne({ where: { id: id } })
            if (!findUser) {
                return res.status(400).json({
                    status: "failed",
                    message: "User not found"
                })
            }
            const edit = await User.update({
                email: body.email,
                password: body.password,
                fullName: body.fullName,
                profilePict: body.profilePict,
                isAdmin: body.isAdmin
            }, {
                where: {
                    id: id
                }
            })

            if (!edit) {
                res.status(400).json({
                    status: "failed",
                    message: "Cannot Update Data"
                })
            }

            return res.status(200).json({
                status: "success",
                message: "success updated data"
            })

        } catch (error) {
            res.status(500).json({
                status: "failed",
                message: "Internal Server Error"
            })
        }
    },
    getOneUser: async(req, res) => {
        const user = req.user
        const id = req.params.id
        try {
            const data = await User.findOne({
                where: {
                    id: id
                },
                attributes: { exclude: ['createdAt', 'updatedAt'] },
                include: [{
                    model: Review,
                    where: {
                        userId: id
                    },
                    attributes: { exclude: ['createdAt', 'updatedAt'] }
                }]
            })

            if (!data) {
                return res.status(400).json({
                    status: "failed",
                    message: "Cannot find user"
                })
            }

            return res.status(200).json({
                status: "success",
                message: "success retrieved data",
                data: data
            })

        } catch (error) {
            res.status(500).json({
                status: "failed",
                message: "Internal Server Error"
            })
        }
    },
    signIn: async(req, res) => {
        const body = req.body
        try {
            const schema = joi.object({
                email: joi.string().required(),
                password: joi.string().required()
            })

            const { error } = schema.validate({...body }, { abortEarly: false })

            if (error) {
                return res.status(400).json({
                    status: "failed",
                    message: "Please insert email or password"
                })
            }

            const checkAdmin = await User.findOne({
                where: {
                    email: body.email
                }
            })

            if (!checkAdmin) {
                return res.status(400).json({
                    status: "failed",
                    message: "Invalid email or password"
                })
            }

            const checkPassword = await bcrypt.compare(body.password, checkAdmin.dataValues.password)

            if (!checkPassword) {
                return res.status(400).json({
                    status: "failed",
                    message: "Invalid email or password"
                })
            }

            const payload = {
                email: checkAdmin.dataValues.email,
                isAdmin: checkAdmin.dataValues.isAdmin,
                id: checkAdmin.dataValues.id
            }

            jwt.sign(payload, process.env.PWD_TOKEN, { expiresIn: 24 * 3600 }, (err, token) => {
                return res.status(200).json({
                    status: "success",
                    message: "Success signin",
                    data: token
                })
            })
        } catch (error) {
            return res.status(500).json({
                status: "failed",
                message: "Internal server error"
            })
        }
    },

    getUserLogin: async(req, res) => {
        const user = req.user
        try {
            const userLogin = await User.findOne({
                where: {
                    id: user.id
                },
                attributes: { exclude: ['createdAt', 'updatedAt'] },
                include: [{
                    model: Review,
                    where: {
                        userId: user.id
                    },
                    attributes: { exclude: ['createdAt', 'updatedAt'] }
                }]
            })
            if (!userLogin) {
                return res.status(400).json({
                    status: "failed",
                    message: "Cannot find user"
                })
            }

            return res.status(200).json({
                status: "success",
                message: "success retrieved data",
                data: userLogin
            })
        } catch (error) {
            console.log(error)
            res.status(500).json({
                status: 'failed',
                message: 'Internal server error'
            })
        }
    },
    delete: async(req, res) => {
        const id = req.params.id
        try {
            const deleteUser = await User.destroy({
                where: { id }
            })
            if (!deleteUser) {
                return res.status(400).json({
                    status: "failed",
                    message: "cannot delete this user"
                })
            }

            return res.status(200).json({
                status: 'success',
                message: "success deleted user"
            })

        } catch (error) {
            res.status(500).json({
                status: 'failed',
                message: 'Internal server error'
            })
        }
    }
}