import { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

// ======================================================
// MITIGAÇÕES DE SEGURANÇA APLICADAS NESTE ARQUIVO:
//
// 1. XSS (Cross-Site Scripting):
//    - type="email" no input de e-mail: o navegador valida
//      o formato e impede a maioria dos scripts maliciosos
//    - maxLength nos inputs: limita o tamanho do texto,
//      dificultando a injeção de scripts longos
//
// 2. CSRF (Cross-Site Request Forgery):
//    - O token CSRF é lido do cookie que o backend envia
//      e reenviado no header 'X-CSRF-Token' de cada
//      requisição POST. O backend valida esse header.
//    - Sem o token correto, requisições vindas de outros
//      sites são bloqueadas.
// ======================================================

// Função auxiliar que lê o valor de um cookie pelo nome.
// O backend salva o token CSRF em um cookie chamado "csrfToken".
function getCookie(name: string): string {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop()?.split(";").shift() || "";
    return "";
}

function Login() {
    const navigate = useNavigate();
    const [isRegistering, setIsRegistering] = useState(false);

    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [nome, setNome] = useState("");
    const [message, setMessage] = useState("");

    const handleLogin = async (e: React.FormEvent) => {
        e.preventDefault();

        try {
            // Lê o token CSRF do cookie antes de enviar a requisição.
            // O backend terá gerado esse token e enviado via Set-Cookie.
            const csrfToken = getCookie("csrfToken");

            const response = await axios.post(
                "http://localhost:3001/usuario/login",
                { email, password },
                {
                    // Envia o token CSRF no header para o backend validar.
                    // Se a requisição vier de outro site (ataque CSRF),
                    // ele não terá acesso ao cookie e o ataque é bloqueado.
                    headers: { "X-CSRF-Token": csrfToken },
                    // withCredentials: envia os cookies junto com a requisição,
                    // necessário para que o navegador inclua o cookie do CSRF.
                    withCredentials: true,
                }
            );
            const user = response.data.user;

            // Salva o usuário no localStorage para uso nas outras telas
            localStorage.setItem("user", JSON.stringify(user));

            navigate("/dashboard");
        } catch {
            setMessage("Erro no login");
        }
    };

    const handleRegister = async (e: React.FormEvent) => {
        e.preventDefault();

        try {
            // Mesmo padrão: lê e envia o token CSRF em toda requisição POST
            const csrfToken = getCookie("csrfToken");

            const response = await axios.post(
                "http://localhost:3001/usuario/novo-login",
                { email, password, nome },
                {
                    headers: { "X-CSRF-Token": csrfToken },
                    withCredentials: true,
                }
            );
            if (response.data.success) {
                setMessage("Usuário criado com sucesso!");
                setIsRegistering(false);
            }
        } catch {
            setMessage("Erro no cadastro");
        }
    };

    return (
        <div style={styles.container}>
            <h1>{isRegistering ? "Criar Conta" : "Login"}</h1>

            <form
                onSubmit={isRegistering ? handleRegister : handleLogin}
                style={styles.form}
            >
                {isRegistering && (
                    <input
                        type="text"
                        placeholder="Nome Completo"
                        value={nome}
                        onChange={(e) => setNome(e.target.value)}
                        style={styles.input}
                        required
                        // maxLength limita o tamanho do input, dificultando
                        // a inserção de scripts XSS longos no campo de nome
                        maxLength={100}
                    />
                )}

                {/* type="email" faz o navegador validar se o texto é um
                    e-mail válido, bloqueando scripts como <script>alert()</script>.
                    maxLength impede scripts longos */}
                <input
                    type="email"
                    placeholder="E-mail"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    style={styles.input}
                    required
                    maxLength={150}
                />

                {/* maxLength na senha limita scripts injetados via campo de senha */}
                <input
                    type="password"
                    placeholder="Senha"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    style={styles.input}
                    required
                    maxLength={64}
                />

                <button type="submit" style={styles.button}>
                    {isRegistering ? "Cadastrar" : "Entrar"}
                </button>
            </form>

            <p style={{ marginTop: 10 }}>{message}</p>

            <button
                onClick={() => {
                    setMessage("");
                    setIsRegistering(!isRegistering);
                }}
                style={styles.linkButton}
            >
                {isRegistering
                    ? "Já tem conta? Fazer login"
                    : "Não tem conta? Criar uma"}
            </button>
        </div>
    );
}

const styles = {
    container: {
        display: "flex",
        flexDirection: "column" as const,
        alignItems: "center",
        justifyContent: "center",
        height: "100vh",
        fontFamily: "Arial",
    },
    form: {
        display: "flex",
        flexDirection: "column" as const,
        width: "320px",
    },
    input: {
        marginBottom: "10px",
        padding: "8px",
        fontSize: "16px",
    },
    button: {
        padding: "10px",
        fontSize: "16px",
        cursor: "pointer",
    },
    linkButton: {
        marginTop: "15px",
        background: "none",
        border: "none",
        color: "blue",
        cursor: "pointer",
        textDecoration: "underline",
    },
};

export default Login;
