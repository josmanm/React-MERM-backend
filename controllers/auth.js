const {response} = require('express');
const bcryopt = require('bcryptjs');
const Usuario = require('../models/Usuario');
const { generarJWT } = require('../helpers/jwt');

const crearUsuario = async (req, res = response)=>{

    const { email, password} = req.body;
    try {

        let usuario = await Usuario.findOne({email});
        
        if(usuario){
            return res.status(400).json({
                ok: false,
                msg : 'Un usuario ya existe con ese correo',
            })
        }

        usuario = new Usuario( req.body );

        //Encriptar contraseña
        const salt = bcryopt.genSaltSync();
        usuario.password = bcryopt.hashSync(password, salt);

        await usuario.save();

        //Generar el token - JWT
        const token = await generarJWT(usuario.id, usuario.name);
    
        res.status(201).json({
            ok: true,
            uid: usuario.id,
            name: usuario.name,
            token,
        })
        
    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            msg : 'Hable con el administrador',
        })
    }
}

const loginUsuario =async (req, res = response)=>{

    const { email, password} = req.body;

    try {
        const usuario = await Usuario.findOne({email});
        
        if(!usuario){
            return res.status(400).json({
                ok: false,
                msg : 'el usuario no existe con ese email',
            })
        }


        //Confirmar los password
        const validPassword = bcryopt.compareSync(password, usuario.password);

        if(!validPassword){
            return res.status(400).json({
                ok: false,
                msg : 'Password incorrecto',
            })
        }

        //Generar el token - JWT
        const token = await generarJWT(usuario.id, usuario.name);
        
        res.status(201).json({
            ok: true,
            uid: usuario.id,
            name: usuario.name,
            token,
        })
        
    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            msg : 'Hable con el administrador',
        })
    }
}

const revalidarToken =async (req, res = response)=>{

    const {uid, name} = req;

    //Generar un nuevo token
    const token = await generarJWT(uid, name);

    res.json({
        ok: true,
        uid,
        name,
        token
    })
}


module.exports = {
    crearUsuario,
    loginUsuario,
    revalidarToken,
};