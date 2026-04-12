// ============================================
// SERVIDOR DE SINCRONIZACIÓN PARA INVENTARIO
// VERSIÓN COMPLETA CON TODAS LAS FUNCIONALIDADES
// ============================================

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  },
  transports: ['websocket', 'polling']
});

// Middlewares
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ============================================
// CONFIGURACIÓN DE SEGURIDAD
// ============================================

const CONTRASENA_MAESTRA = process.env.CONTRASENA_MAESTRA || "AdminSuperSecreto2025!";
const JWT_SECRET = process.env.JWT_SECRET || "miSecretoSuperSeguroParaTokens2025";

// ============================================
// BASE DE DATOS EN MEMORIA
// ============================================

const negocios = {};

function generarCodigo(longitud = 8) {
    const caracteres = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let resultado = '';
    for (let i = 0; i < longitud; i++) {
        resultado += caracteres.charAt(Math.floor(Math.random() * caracteres.length));
    }
    return resultado;
}

function inicializarNegocio(clave) {
    if (!negocios[clave]) {
        negocios[clave] = {
            // Seguridad
            contrasena: 'admin123',
            contrasenaHash: bcrypt.hashSync('admin123', 10),
            codigoRecuperacion: generarCodigo(8),
            dispositivos: new Set(),
            
            // Datos principales
            productos: [],
            ventas: [],
            gastos: [],
            deudores: [],
            incidencias: [],
            donaciones: [],
            botellas: [],
            depositos: [],
            vasos: [],
            tareas: [],
            horarios: {},
            
            // Configuración
            config: {
                tasaCambio: 36.50,
                limiteStockBajo: 5,
                sobreprecio: {
                    horaActivacion: "20:00",
                    porcentaje: 15
                },
                deliveryActivo: false,
                horariosEspecialesActivo: false,
                logoFondo: null,
                combosPorCategoria: {
                    lata: [
                        { nombre: "Individual", cantidad: 1, precioMultiplicador: 1.0 },
                        { nombre: "6-Pack", cantidad: 6, precioMultiplicador: 0.95 },
                        { nombre: "Caja (24)", cantidad: 24, precioMultiplicador: 0.90 }
                    ],
                    botella: [
                        { nombre: "Individual", cantidad: 1, precioMultiplicador: 1.0 },
                        { nombre: "6-Pack", cantidad: 6, precioMultiplicador: 0.95 },
                        { nombre: "Caja (12)", cantidad: 12, precioMultiplicador: 0.92 }
                    ],
                    licor: [
                        { nombre: "Individual", cantidad: 1, precioMultiplicador: 1.0 },
                        { nombre: "Combo Ron + Coca 1L", cantidad: 2, precioMultiplicador: 0.85 },
                        { nombre: "Combo Whisky + Hielo", cantidad: 2, precioMultiplicador: 0.90 }
                    ],
                    comida: [
                        { nombre: "Individual", cantidad: 1, precioMultiplicador: 1.0 },
                        { nombre: "Combo Familiar", cantidad: 4, precioMultiplicador: 0.85 },
                        { nombre: "Combo Pareja", cantidad: 2, precioMultiplicador: 0.90 }
                    ],
                    cigarro: [
                        { nombre: "Individual", cantidad: 1, precioMultiplicador: 1.0 },
                        { nombre: "Media Caja (10)", cantidad: 10, precioMultiplicador: 0.90 },
                        { nombre: "Caja (20)", cantidad: 20, precioMultiplicador: 0.80 }
                    ],
                    otro: [
                        { nombre: "Individual", cantidad: 1, precioMultiplicador: 1.0 },
                        { nombre: "Pack x3", cantidad: 3, precioMultiplicador: 0.95 },
                        { nombre: "Pack x6", cantidad: 6, precioMultiplicador: 0.90 }
                    ]
                }
            },
            
            // Última sincronización
            ultimaSincronizacion: new Date(),
            historialSincronizacion: []
        };
    }
    return negocios[clave];
}

// ============================================
// API DE AUTENTICACIÓN Y SEGURIDAD
// ============================================

app.post('/api/verificar-contrasena', express.json(), (req, res) => {
    const { claveNegocio, contrasena } = req.body;
    const negocio = inicializarNegocio(claveNegocio);
    
    if (bcrypt.compareSync(contrasena, negocio.contrasenaHash)) {
        const token = jwt.sign({ claveNegocio }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ 
            valida: true, 
            token: token, 
            config: negocio.config 
        });
    } else {
        res.status(401).json({ valida: false });
    }
});

app.post('/api/cambiar-contrasena', express.json(), (req, res) => {
    const { claveNegocio, nuevaContrasena, contrasenaMaestra } = req.body;
    
    if (contrasenaMaestra !== CONTRASENA_MAESTRA) {
        return res.status(401).json({ error: 'Contraseña maestra incorrecta' });
    }
    
    if (!nuevaContrasena || nuevaContrasena.length < 6) {
        return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
    }
    
    const negocio = inicializarNegocio(claveNegocio);
    
    negocio.historialSincronizacion.push({
        fecha: new Date(),
        tipo: 'cambio_contrasena',
        ip: req.ip
    });
    
    negocio.contrasena = nuevaContrasena;
    negocio.contrasenaHash = bcrypt.hashSync(nuevaContrasena, 10);
    
    io.to(claveNegocio).emit('contrasena-cambiada', { 
        mensaje: 'La contraseña ha sido actualizada',
        fecha: new Date()
    });
    
    res.json({ exito: true, mensaje: 'Contraseña actualizada correctamente' });
});

app.post('/api/solicitar-codigo-recuperacion', express.json(), (req, res) => {
    const { claveNegocio, contrasenaMaestra } = req.body;
    
    if (contrasenaMaestra !== CONTRASENA_MAESTRA) {
        return res.status(401).json({ error: 'Contraseña maestra incorrecta' });
    }
    
    const negocio = inicializarNegocio(claveNegocio);
    negocio.codigoRecuperacion = generarCodigo(8);
    
    res.json({
        exito: true,
        codigoRecuperacion: negocio.codigoRecuperacion
    });
});

app.post('/api/recuperar-acceso', express.json(), (req, res) => {
    const { claveNegocio, codigoRecuperacion } = req.body;
    const negocio = inicializarNegocio(claveNegocio);
    
    if (negocio.codigoRecuperacion === codigoRecuperacion) {
        const nuevaContrasena = generarCodigo(8);
        negocio.contrasena = nuevaContrasena;
        negocio.contrasenaHash = bcrypt.hashSync(nuevaContrasena, 10);
        negocio.codigoRecuperacion = generarCodigo(8);
        
        res.json({
            exito: true,
            nuevaContrasena: nuevaContrasena,
            mensaje: 'Acceso restablecido'
        });
    } else {
        res.status(401).json({ error: 'Código de recuperación incorrecto' });
    }
});

// ============================================
// API DE SINCRONIZACIÓN DE DATOS
// ============================================

app.post('/api/sincronizar', express.json(), (req, res) => {
    const { token, datos } = req.body;
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const negocio = inicializarNegocio(decoded.claveNegocio);
        
        if (datos.productos) negocio.productos = datos.productos;
        if (datos.ventas) negocio.ventas = datos.ventas;
        if (datos.gastos) negocio.gastos = datos.gastos;
        if (datos.deudores) negocio.deudores = datos.deudores;
        if (datos.incidencias) negocio.incidencias = datos.incidencias;
        if (datos.donaciones) negocio.donaciones = datos.donaciones;
        if (datos.botellas) negocio.botellas = datos.botellas;
        if (datos.depositos) negocio.depositos = datos.depositos;
        if (datos.vasos) negocio.vasos = datos.vasos;
        if (datos.tareas) negocio.tareas = datos.tareas;
        if (datos.horarios) negocio.horarios = datos.horarios;
        if (datos.config) {
            negocio.config = { ...negocio.config, ...datos.config };
        }
        
        negocio.ultimaSincronizacion = new Date();
        negocio.historialSincronizacion.push({
            fecha: new Date(),
            tipo: 'sincronizacion',
            datos: Object.keys(datos)
        });
        
        res.json({ exito: true, ultimaSincronizacion: negocio.ultimaSincronizacion });
        
    } catch (error) {
        res.status(401).json({ error: 'Token inválido' });
    }
});

app.post('/api/obtener-datos', express.json(), (req, res) => {
    const { token } = req.body;
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const negocio = inicializarNegocio(decoded.claveNegocio);
        
        res.json({
            exito: true,
            productos: negocio.productos,
            ventas: negocio.ventas,
            gastos: negocio.gastos,
            deudores: negocio.deudores,
            incidencias: negocio.incidencias,
            donaciones: negocio.donaciones,
            botellas: negocio.botellas,
            depositos: negocio.depositos,
            vasos: negocio.vasos,
            tareas: negocio.tareas,
            horarios: negocio.horarios,
            config: negocio.config,
            ultimaSincronizacion: negocio.ultimaSincronizacion
        });
        
    } catch (error) {
        res.status(401).json({ error: 'Token inválido' });
    }
});

// ============================================
// WEBSOCKETS PARA TIEMPO REAL
// ============================================

io.on('connection', (socket) => {
    console.log('🔌 Dispositivo conectado:', socket.id);
    
    socket.on('registrar-dispositivo', (data) => {
        try {
            const decoded = jwt.verify(data.token, JWT_SECRET);
            const claveNegocio = decoded.claveNegocio;
            
            socket.join(claveNegocio);
            socket.claveNegocio = claveNegocio;
            socket.token = data.token;
            
            const negocio = inicializarNegocio(claveNegocio);
            negocio.dispositivos.add(socket.id);
            
            io.to(claveNegocio).emit('dispositivos-actualizados', {
                cantidad: negocio.dispositivos.size
            });
            
            console.log(`✅ Dispositivo registrado en: ${claveNegocio}`);
            console.log(`📊 Total dispositivos: ${negocio.dispositivos.size}`);
            
        } catch (error) {
            socket.emit('error-autenticacion', { mensaje: 'Token inválido' });
        }
    });

    socket.on('actualizacion-tiempo-real', (data) => {
        if (socket.claveNegocio) {
            socket.to(socket.claveNegocio).emit('actualizacion', data);
        }
    });

    socket.on('solicitar-respaldo', () => {
        if (socket.claveNegocio) {
            const negocio = inicializarNegocio(socket.claveNegocio);
            socket.emit('datos-completos', {
                productos: negocio.productos,
                ventas: negocio.ventas,
                gastos: negocio.gastos,
                deudores: negocio.deudores,
                donaciones: negocio.donaciones,
                config: negocio.config
            });
        }
    });

    socket.on('disconnect', () => {
        console.log('🔌 Dispositivo desconectado:', socket.id);
        
        if (socket.claveNegocio && negocios[socket.claveNegocio]) {
            negocios[socket.claveNegocio].dispositivos.delete(socket.id);
            
            io.to(socket.claveNegocio).emit('dispositivos-actualizados', {
                cantidad: negocios[socket.claveNegocio].dispositivos.size
            });
        }
    });
});

// ============================================
// API DE ADMINISTRACIÓN
// ============================================

app.post('/api/admin/estado', express.json(), (req, res) => {
    const { contrasenaMaestra } = req.body;
    
    if (contrasenaMaestra !== CONTRASENA_MAESTRA) {
        return res.status(401).json({ error: 'No autorizado' });
    }
    
    const estadisticas = {};
    for (let [clave, negocio] of Object.entries(negocios)) {
        estadisticas[clave] = {
            dispositivos: negocio.dispositivos.size,
            productos: negocio.productos.length,
            ventas: negocio.ventas.length,
            gastos: negocio.gastos.length,
            deudores: negocio.deudores.length,
            donaciones: negocio.donaciones.length,
            ultimaSincronizacion: negocio.ultimaSincronizacion
        };
    }
    
    res.json({
        totalNegocios: Object.keys(negocios).length,
        detalles: estadisticas
    });
});

app.post('/api/admin/resetear-negocio', express.json(), (req, res) => {
    const { claveNegocio, contrasenaMaestra } = req.body;
    
    if (contrasenaMaestra !== CONTRASENA_MAESTRA) {
        return res.status(401).json({ error: 'No autorizado' });
    }
    
    if (negocios[claveNegocio]) {
        delete negocios[claveNegocio];
    }
    
    res.json({ exito: true, mensaje: `Negocio ${claveNegocio} reseteado` });
});

// ============================================
// INICIALIZACIÓN DEL SERVIDOR
// ============================================

const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => {
    console.log('\n=================================');
    console.log('🚀 SERVIDOR DE INVENTARIO INICIADO');
    console.log('=================================');
    console.log(`📡 Puerto: ${PORT}`);
    console.log(`🔐 Contraseña maestra: ${CONTRASENA_MAESTRA}`);
    console.log(`📱 Acceso local: http://localhost:${PORT}`);
    console.log(`🌐 Acceso red: http://${getLocalIp()}:${PORT}`);
    console.log('=================================\n');
});

function getLocalIp() {
    const { networkInterfaces } = require('os');
    const nets = networkInterfaces();
    for (const name of Object.keys(nets)) {
        for (const net of nets[name]) {
            if (net.family === 'IPv4' && !net.internal) {
                return net.address;
            }
        }
    }
    return 'localhost';
}

// Manejo de errores
process.on('uncaughtException', (err) => {
    console.error('❌ Error no capturado:', err);
});

process.on('unhandledRejection', (err) => {
    console.error('❌ Promesa rechazada:', err);
});