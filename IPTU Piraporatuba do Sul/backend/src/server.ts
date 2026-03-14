import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import userRoutes from "./routes/usuarioRoutes";
import commentRoutes from "./routes/comentarioRoutes";
import hackerMalvadao from "./routes/hackerMalvadaoRoutes";

// ======================================================
// MITIGAÇÕES DE SEGURANÇA APLICADAS NESTE ARQUIVO:
//
// CSRF (Cross-Site Request Forgery):
//   O ataque CSRF funciona assim:
//   1. O usuário está logado no nosso sistema
//   2. Ele visita um site malicioso
//   3. Esse site faz uma requisição POST para o nosso
//      backend usando os cookies de sessão do usuário
//   4. O backend, sem saber, executa a ação
//
//   A defesa é o padrão "Double Submit Cookie":
//   - Ao receber qualquer requisição, geramos um token
//     aleatório e o enviamos em um cookie.
//   - O frontend lê esse cookie e o reenvia em um header
//     chamado 'X-CSRF-Token'.
//   - O backend valida se o header bate com o cookie.
//   - Um site malicioso não consegue ler os cookies do
//     nosso domínio (política Same-Origin do navegador),
//     então não consegue enviar o header correto.
//
// Dependências adicionais:
//   npm install cookie-parser
//   npm install --save-dev @types/cookie-parser
// ======================================================

const app = express();

// cors() configurado para aceitar credenciais (cookies).
// origin deve apontar para o endereço do frontend.
// Em produção, troque pela URL real do frontend.
app.use(cors({
    origin: "http://localhost:5173", // endereço padrão do Vite (frontend)
    credentials: true,               // permite enviar/receber cookies cross-origin
}));

app.use(express.json());

// cookieParser() permite ler os cookies da requisição via req.cookies
app.use(cookieParser());

// -------------------------------------------------------
// Middleware de geração do token CSRF
// Executa em TODA requisição que chegar ao servidor.
// Se o cookie 'csrfToken' ainda não existe, cria um novo
// token aleatório e o envia para o navegador via cookie.
// -------------------------------------------------------
app.use((req, res, next) => {
    if (!req.cookies["csrfToken"]) {
        // Gera um token de 32 bytes aleatórios em hexadecimal
        const token = crypto.randomBytes(32).toString("hex");

        // httpOnly: false -> o frontend PRECISA ler via JS (document.cookie)
        // sameSite: "strict" -> o cookie só é enviado para requisições
        //   originadas do mesmo site, como camada extra de proteção
        res.cookie("csrfToken", token, {
            httpOnly: false,
            sameSite: "strict",
        });
    }
    next(); // passa para o próximo middleware/rota
});

// -------------------------------------------------------
// Middleware de validação do token CSRF
// Executa em requisições que MODIFICAM dados (POST, PUT, DELETE).
// Compara o token do cookie com o token enviado no header.
// -------------------------------------------------------
app.use((req, res, next) => {
    // Só valida em métodos que alteram estado no servidor
    const metodosProtegidos = ["POST", "PUT", "DELETE", "PATCH"];
    if (!metodosProtegidos.includes(req.method)) {
        return next(); // requisições GET, HEAD etc. passam sem validação
    }

    const tokenDoCookie = req.cookies["csrfToken"];
    const tokenDoHeader = req.headers["x-csrf-token"] as string;

    // Se os tokens não existem ou não batem, rejeita a requisição
    if (!tokenDoCookie || !tokenDoHeader || tokenDoCookie !== tokenDoHeader) {
        res.status(403).json({ error: "Token CSRF inválido ou ausente" });
        return;
    }

    next(); // tokens válidos: permite a requisição prosseguir
});

// Registra as rotas da aplicação
app.use("/usuario", userRoutes);
app.use("/comentario", commentRoutes);
app.use("/hacker-malvadao", hackerMalvadao);

app.listen(3001, () => {
    console.log("Servidor rodando na porta 3001");
});
