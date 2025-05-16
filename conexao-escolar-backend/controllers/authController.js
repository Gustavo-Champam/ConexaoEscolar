import Usuario from "../models/Usuario.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

export const registrar = async (req, res) => {
  const { email, senha } = req.body;
  try {
    const senhaHash = await bcrypt.hash(senha, 10);
    const novoUsuario = await Usuario.create({ email, senha: senhaHash });
    res.status(201).json({ mensagem: "Usuário criado com sucesso" });
  } catch (err) {
    res.status(400).json({ erro: "Erro ao criar usuário", detalhes: err });
  }
};

export const login = async (req, res) => {
  const { email, senha } = req.body;
  const usuario = await Usuario.findOne({ email });
  if (!usuario) return res.status(404).json({ erro: "Usuário não encontrado" });

  const senhaValida = await bcrypt.compare(senha, usuario.senha);
  if (!senhaValida) return res.status(401).json({ erro: "Senha inválida" });

  const token = jwt.sign({ id: usuario._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
  res.json({ token });
};
