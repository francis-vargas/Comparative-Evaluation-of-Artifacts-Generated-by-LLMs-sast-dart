import express from "express";
import path from "path";
import fs from "fs";
import { exec, execSync } from "child_process";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json());

// Initialize Gemini SDK with telemetry header
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    }
  }
});

// API Endpoint: Run Dart SAST Scan
app.post("/api/scan", (req, res) => {
  const { code, filename = "playground.dart" } = req.body;
  
  if (!code) {
    return res.status(400).json({ error: "No code provided for scanning." });
  }

  const tempDir = path.join(process.cwd(), "tmp_scan");
  if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir);
  }

  const tempFilePath = path.join(tempDir, filename);
  
  try {
    fs.writeFileSync(tempFilePath, code, "utf8");
    
    // Execute our real Python SAST CLI on the temporary file
    const pythonCmd = `python3 ${path.join(process.cwd(), "dart_sast", "main.py")} "${tempFilePath}" --format json`;
    
    exec(pythonCmd, (error, stdout, stderr) => {
      // Clean up file immediately
      try {
        if (fs.existsSync(tempFilePath)) {
          fs.unlinkSync(tempFilePath);
        }
      } catch (e) {
        console.error("Error deleting temp file:", e);
      }

      if (error && error.code !== 1 && error.code !== 0) {
        // A code of 1 is returned if findings exist and we configure fail-on, but here it's normal
        console.error("CLI Execution Error:", stderr);
        return res.status(500).json({ error: "Failed to execute SAST engine: " + stderr });
      }

      try {
        const findings = JSON.parse(stdout || "[]");
        // Relativize paths for the client
        const cleanedFindings = findings.map((f: any) => ({
          ...f,
          file: filename
        }));
        res.json({ findings: cleanedFindings });
      } catch (parseError) {
        console.error("Failed to parse SAST JSON output:", stdout);
        res.status(500).json({ error: "Failed to parse SAST scan findings." });
      }
    });

  } catch (err: any) {
    console.error("Scan setup error:", err);
    res.status(500).json({ error: "Failed to prepare scan target: " + err.message });
  }
});

// API Endpoint: AI Security Analyst & Code Patcher using Gemini
app.post("/api/ai-explain", async (req, res) => {
  const { codeSnippet, findingDetails } = req.body;
  
  if (!findingDetails) {
    return res.status(400).json({ error: "Finding details are required." });
  }

  const prompt = `
Você é o Analista de Segurança IA especialista do projeto dart_sast (um software SAST de alta precisão científica para Dart e Flutter em conformidade com o SBRC 2026).
Analise a seguinte vulnerabilidade detectada pela nossa ferramenta de análise estática e forneça um relatório em português do Brasil contendo:
1. Uma explicação didática e detalhada do risco de segurança (CWE ${findingDetails.cwe}: ${findingDetails.name}).
2. Por que o código fornecido é vulnerável.
3. Um exemplo de correção ("Secure Patch") em Dart/Flutter usando as melhores práticas de desenvolvimento seguro (OWASP Mobile Top 10).

Código Vulnerável Detectado:
\`\`\`dart
${codeSnippet || findingDetails.code}
\`\`\`

Detalhes da Vulnerabilidade:
ID da Regra: ${findingDetails.rule_id}
CWE: ${findingDetails.cwe}
Gravidade: ${findingDetails.severity}
Descrição: ${findingDetails.description}
Recomendação da Ferramenta: ${findingDetails.recommendation}

Retorne a resposta formatada em Markdown legível, com títulos claros e blocos de código com sintaxe dart. Seja técnico, encorajador e preciso.
`;

  try {
    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
    });

    const resultText = response.text || "Não foi possível gerar a resposta da IA.";
    res.json({ explanation: resultText });
  } catch (err: any) {
    console.error("Gemini API Error:", err);
    res.status(500).json({ error: "Failed to call Gemini AI explanation: " + err.message });
  }
});

// API Endpoint: Read code files for the file explorer
app.get("/api/source-files", (req, res) => {
  const basePaths = [
    { dir: "dart_sast", name: "dart_sast" },
    { dir: "tests", name: "tests" },
    { file: "setup.py", name: "setup.py" },
    { file: "Dockerfile", name: "Dockerfile" },
    { file: "LICENSE", name: "LICENSE" },
    { file: "README.md", name: "README.md" }
  ];

  const filesList: Array<{ path: string; name: string; content: string }> = [];

  const readDirRecursive = (dirPath: string, relativePrefix: string) => {
    const items = fs.readdirSync(dirPath);
    for (const item of items) {
      const fullPath = path.join(dirPath, item);
      const relPath = path.join(relativePrefix, item);
      const stat = fs.statSync(fullPath);
      if (stat.isDirectory()) {
        readDirRecursive(fullPath, relPath);
      } else if (stat.isFile() && !item.startsWith(".")) {
        const content = fs.readFileSync(fullPath, "utf8");
        filesList.push({ path: relPath, name: item, content });
      }
    }
  };

  try {
    for (const item of basePaths) {
      if (item.dir && fs.existsSync(item.dir)) {
        readDirRecursive(item.dir, item.name);
      } else if (item.file && fs.existsSync(item.file)) {
        const content = fs.readFileSync(item.file, "utf8");
        filesList.push({ path: item.file, name: item.name, content });
      }
    }
    res.json({ files: filesList });
  } catch (err: any) {
    res.status(500).json({ error: "Failed to read source files: " + err.message });
  }
});

// API Endpoint: Download complete bundle zip
app.get("/api/download-bundle", (req, res) => {
  const zipPath = "/tmp/dart_sast_artifact.zip";
  
  try {
    // Generate ZIP using python's built-in zipfile to ensure complete portability
    const pythonZipScript = `
import zipfile
import os

files_to_zip = [
    'setup.py',
    'Dockerfile',
    'LICENSE',
    'README.md'
]
dirs_to_zip = [
    'dart_sast',
    'tests',
    '.github'
]

with zipfile.ZipFile('${zipPath}', 'w', zipfile.ZIP_DEFLATED) as zipf:
    for f in files_to_zip:
        if os.path.exists(f):
            zipf.write(f)
    for d in dirs_to_zip:
        for root, dirs, files in os.walk(d):
            for file in files:
                full_path = os.path.join(root, file)
                zipf.write(full_path)
`;

    // Execute python script to generate zip
    execSync(`python3 -c "${pythonZipScript.replace(/"/g, '\\"')}"`);

    if (fs.existsSync(zipPath)) {
      res.download(zipPath, "dart_sast_sbrc2026_artifact.zip", (err) => {
        if (err) {
          console.error("Error during download:", err);
        }
        try {
          fs.unlinkSync(zipPath); // clean up tmp zip
        } catch (unlinkErr) {
          // ignore cleanup failures
        }
      });
    } else {
      res.status(500).json({ error: "Failed to create artifact archive." });
    }
  } catch (err: any) {
    console.error("Zip generation failed:", err);
    res.status(500).json({ error: "Failed to package source bundle: " + err.message });
  }
});

// Setup Vite Development Server or Production Static Files
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer();
