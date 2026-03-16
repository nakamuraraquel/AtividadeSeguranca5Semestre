import { Request, Response } from "express";
import db from "../database";

// ✅ CORRIGIDO: usa parâmetros $1/$2 (já estava assim) — mantido.
// ⚠️  ATENÇÃO: Em produção, nunca compare senha em texto puro.
//     Utilize bcrypt: bcrypt.compare(password, result.rows[0].senha)
export const login = async (req: Request, res: Response) => {
    const { email, password } = req.body;
    console.log(`Recebendo login para email: ${email}`);

    const query = `SELECT * FROM usuario WHERE email = $1 AND senha = $2`;
    console.log(`Query Executada: ${query}`);

    const result = await db.query(query, [email, password]);

    if (result.rowCount && result.rowCount > 0) {
        res.json({ success: true, user: result.rows[0] });
    } else {
        res.status(401).json({ success: false, message: "Falha no login" });
    }
};

export const novoLogin = async (req: Request, res: Response) => {
    const { email, password, nome } = req.body;

    const nomeNormalizado = normalizarNome(nome);

    // ✅ CORRIGIDO: era concatenação direta de string
    const queryNomeIptuExiste = `SELECT * FROM iptu WHERE nome = $1`;
    const iptuResult = await db.query(queryNomeIptuExiste, [nomeNormalizado]);

    if (iptuResult.rowCount && iptuResult.rowCount > 0) {

        // ✅ CORRIGIDO: era template literal com variáveis diretas
        const query = `INSERT INTO usuario (email, senha, nome, tipo_usuario_id) VALUES ($1, $2, $3, 3)`;
        console.log(`Query Executada: ${query}`);
        const result = await db.query(query, [email, password, nome]);

        // ✅ CORRIGIDO: era template literal com variáveis diretas
        const queryIdUsuario = `SELECT id FROM usuario WHERE email = $1 AND senha = $2`;
        const resultIdUsuario = await db.query(queryIdUsuario, [email, password]);

        // ✅ CORRIGIDO: era template literal com variáveis diretas
        const queryUpdateTabelaIptu = `UPDATE iptu SET usuario_id = $1 WHERE nome = $2`;
        const resultUpdate = await db.query(queryUpdateTabelaIptu, [
            resultIdUsuario.rows[0].id,
            nomeNormalizado,
        ]);

        if (
            result.rowCount && result.rowCount > 0 &&
            resultUpdate.rowCount && resultUpdate.rowCount > 0
        ) {
            res.json({ success: true, user: result.rows[0] });
        } else {
            res.status(401).json({ success: false, message: "Falha no login" });
        }
    } else {
        // ✅ CORRIGIDO: removido o nome do usuário da mensagem de erro
        //    (evita vazar input do usuário na resposta)
        res.status(404).json({
            success: false,
            message: "Nome não encontrado no cadastro de municipes",
        });
    }
};

export const atualizarIptu = async (req: Request, res: Response) => {
    const { usuarioId, novoValor } = req.body;

    // ✅ CORRIGIDO: era interpolação direta de valores numéricos
    const query = `UPDATE iptu SET valor = $1 WHERE usuario_id = $2`;

    try {
        await db.query(query, [novoValor, usuarioId]);
        res.json({ message: "IPTU atualizado" });
    } catch (err: any) {
        res.status(500).json({ error: err.message });
    }
};

export const getIptuPorIdUsuario = async (req: Request, res: Response) => {
    const usuarioId = req.query.usuarioId as string;

    // ✅ CORRIGIDO: era interpolação direta de query param
    const query = `SELECT * FROM iptu WHERE usuario_id = $1`;
    console.log(`Query Executada: ${query}`);

    try {
        const result = await db.query(query, [usuarioId]);
        console.log(`Retorno: ${result}`);
        res.json({ iptu: result.rows });
    } catch (err: any) {
        res.status(500).json({ error: err.message });
    }
};

export const getQRCodeOrCodBarras = async (req: Request, res: Response) => {
    const tipo = req.query.tipo as string;
    let codigoHtml = "";

    // ✅ CORRIGIDO: era XSS — o valor de `tipo` era refletido diretamente no HTML
    //    Agora usamos whitelist de valores permitidos
    const tiposPermitidos = ["codigoDeBarras", "qrcode"];

    if (!tiposPermitidos.includes(tipo)) {
        return res.status(400).json({ error: "Tipo inválido" });
    }

    if (tipo === "codigoDeBarras") {
        codigoHtml = `<img src="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=123456789" />`;
    } else if (tipo === "qrcode") {
        codigoHtml = `<img src="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=QRCodeDemo" />`;
    }

    // ✅ CORRIGIDO: `tipo` agora é seguro pois passou pela whitelist acima
    res.send(`<h2>Tipo selecionado: ${tipo}</h2>${codigoHtml}`);
};

export function normalizarNome(nome: string): string {
    return nome
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toUpperCase()
        .trim();
}
