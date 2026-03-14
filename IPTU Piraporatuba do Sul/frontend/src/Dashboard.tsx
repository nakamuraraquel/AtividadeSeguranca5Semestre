import axios from "axios";
import { useEffect, useState } from "react";
// Importamos a biblioteca 'xss' para sanitizar HTML antes de exibir
// Instalar com: npm install xss @types/xss
import xss from "xss";

import type { Comentario } from "./Tipos/Comentario";
import type { Iptuu } from "./Tipos/Iptuu";

// ======================================================
// MITIGAÇÕES DE SEGURANÇA APLICADAS NESTE ARQUIVO:
//
// 1. XSS (Cross-Site Scripting):
//    - Substituímos dangerouslySetInnerHTML por renderização
//      direta de texto via JSX, que escapa automaticamente
//      qualquer HTML/script malicioso nos comentários.
//    - Na seção do QR Code, usamos a biblioteca 'xss'
//      para sanitizar o HTML retornado pelo backend antes
//      de injetá-lo na página com dangerouslySetInnerHTML.
//      Isso remove tags e atributos perigosos como <script>
//      ou onerror="...".
//
// 2. CSRF (Cross-Site Request Forgery):
//    - Toda requisição POST lê o token CSRF do cookie e
//      o envia no header 'X-CSRF-Token'.
//    - Isso garante que só o nosso frontend (que tem acesso
//      ao cookie do domínio correto) consegue fazer ações.
// ======================================================

// Lê o valor de um cookie pelo nome
function getCookie(name: string): string {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop()?.split(";").shift() || "";
    return "";
}

function Dashboard() {
    const user = JSON.parse(localStorage.getItem("user") || "{}");

    const [menuAberto, setMenuAberto] = useState(false);
    const [iptu, setIptu] = useState<Iptuu | null>(null);
    const [comentarios, setComentarios] = useState<Comentario[]>([]);
    const [novoComentario, setNovoComentario] = useState("");
    const [tipoCodigo, setTipoCodigo] = useState("codigoDeBarras");
    const [htmlRetorno, setHtmlRetorno] = useState("");

    useEffect(() => {
        const buscarDados = async () => {
            try {
                const response = await axios.get<{ iptu: Iptuu[] }>(
                    "http://localhost:3001/usuario/iptu-por-usuario?usuarioId=" + user.id
                );
                setIptu(response.data.iptu[0]);
            } catch (error) {
                console.error("Erro ao buscar IPTU", error);
            }
        };

        const buscarComentarios = async () => {
            try {
                const response = await axios.get("http://localhost:3001/comentario");
                setComentarios(response.data);
            } catch (error) {
                console.error("Erro ao buscar comentários", error);
            }
        };

        if (user?.id) {
            buscarDados();
            buscarComentarios();
        }
    }, [user]);

    const enviarComentario = async () => {
        if (!novoComentario.trim()) return;

        try {
            // Lê o token CSRF do cookie antes de enviar a requisição POST
            const csrfToken = getCookie("csrfToken");

            await axios.post(
                "http://localhost:3001/comentario",
                { usuarioId: user.id, texto: novoComentario },
                {
                    // Envia o token no header para o backend validar.
                    // Sem esse token, o backend rejeita a requisição.
                    headers: { "X-CSRF-Token": csrfToken },
                    withCredentials: true,
                }
            );

            const response = await axios.get("http://localhost:3001/comentario");
            setComentarios(response.data);
            setNovoComentario("");
        } catch (error) {
            console.error("Erro ao enviar comentário", error);
        }
    };

    const buscarCodigo = async () => {
        const response = await axios.get(
            "http://localhost:3001/usuario/codigo-qr-ou-barra?tipo=" + tipoCodigo
        );

        // CORREÇÃO XSS: sanitizamos o HTML recebido do backend com a
        // biblioteca 'xss' antes de injetar na página.
        // Isso remove qualquer <script>, atributos como onerror="...",
        // ou outros vetores de XSS que possam vir na resposta.
        const htmlSanitizado = xss(response.data);
        setHtmlRetorno(htmlSanitizado);
    };

    return (
        <div style={styles.container}>
            <header style={styles.header}>
                {/* Exibir o nome do usuário diretamente via JSX é seguro:
                    o React escapa automaticamente qualquer HTML nesse texto */}
                <h2>Bem-vindo, {user.nome}</h2>

                <div style={{ position: "relative" }}>
                    <button onClick={() => setMenuAberto(!menuAberto)}>
                        ☰ Menu
                    </button>

                    {menuAberto && (
                        <div style={styles.dropdown}>
                            <button onClick={() => alert("Listar Munícipes")}>
                                Listar Munícipes
                            </button>
                            <button onClick={() => alert("Outra opção")}>
                                Outra opção
                            </button>
                        </div>
                    )}
                </div>
            </header>

            <div style={styles.card}>
                <h3>IPTU</h3>
                {iptu && <p>Valor IPTU: {iptu.valor}</p>}
                <p>Status: {iptu?.valor}</p>
            </div>

            <select
                value={tipoCodigo}
                onChange={(e) => setTipoCodigo(e.target.value)}
            >
                <option value="codigoDeBarras">Código de Barras</option>
                <option value="qrcode">QR Code</option>
            </select>

            <button onClick={buscarCodigo}>Gerar Código</button>

            {/* dangerouslySetInnerHTML ainda é usado aqui, mas agora o
                conteúdo foi sanitizado pela biblioteca xss antes de ser exibido */}
            {htmlRetorno && (
                <div dangerouslySetInnerHTML={{ __html: htmlRetorno }} />
            )}

            <div style={{ padding: "40px" }}>
                <h2>Lista de Comentários</h2>
                <div style={{ marginBottom: "20px" }}>
                    <h3>Adicionar Comentário</h3>
                    <textarea
                        value={novoComentario}
                        onChange={(e) => setNovoComentario(e.target.value)}
                        placeholder="Digite seu comentário..."
                        style={{
                            width: "100%",
                            height: "80px",
                            padding: "10px",
                            marginBottom: "10px",
                        }}
                        // maxLength limita o tamanho do comentário,
                        // dificultando injeção de scripts XSS longos
                        maxLength={500}
                    />
                    <button onClick={enviarComentario}>Enviar Comentário</button>
                </div>
                <ul>
                    {comentarios.map((comentario, index) => (
                        // CORREÇÃO XSS: substituímos o dangerouslySetInnerHTML por
                        // renderização direta com JSX. O React escapa automaticamente
                        // qualquer HTML ou script dentro das variáveis {}, impedindo XSS.
                        // Antes, o código montava uma string HTML e a injetava diretamente,
                        // o que permitia que um comentário com <script>...</script>
                        // fosse executado no navegador de outros usuários.
                        <li key={index}>
                            <strong>Usuário:</strong> {comentario.usuario_id}
                            <br />
                            <strong>Mensagem:</strong> {comentario.texto}
                        </li>
                    ))}
                </ul>
            </div>
        </div>
    );
}

const styles = {
    container: { padding: "40px", fontFamily: "Arial" },
    header: { display: "flex", justifyContent: "space-between", alignItems: "center" },
    card: {
        marginTop: "40px",
        padding: "20px",
        border: "1px solid #ccc",
        borderRadius: "8px",
        width: "300px",
    },
    dropdown: {
        position: "absolute" as const,
        top: "40px",
        right: 0,
        background: "white",
        border: "1px solid #ccc",
        display: "flex",
        flexDirection: "column" as const,
        padding: "10px",
        gap: "5px",
    },
};

export default Dashboard;
