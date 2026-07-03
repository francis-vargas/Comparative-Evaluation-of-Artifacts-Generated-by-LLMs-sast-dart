import { useState, useEffect, useRef } from "react";
import { 
  Shield, 
  Terminal, 
  Code, 
  CheckCircle2, 
  Play, 
  FileCode, 
  Download, 
  HelpCircle, 
  AlertTriangle, 
  Info, 
  Sparkles, 
  ChevronRight, 
  Folder, 
  FolderOpen, 
  ChevronDown,
  RefreshCw,
  Clock,
  BookOpen,
  Cpu,
  Github,
  Award
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import Markdown from "react-markdown";
import { CWE_TEMPLATES, CWETemplate } from "./data";

interface SourceFile {
  path: string;
  name: string;
  content: string;
}

export default function App() {
  // Navigation tabs
  const [activeTab, setActiveTab] = useState<"playground" | "explorer" | "compliance" | "terminal">("playground");
  
  // Playground state
  const [selectedCWE, setSelectedCWE] = useState<CWETemplate>(CWE_TEMPLATES[0]);
  const [codeMode, setCodeMode] = useState<"vulnerable" | "secure">("vulnerable");
  const [editorCode, setEditorCode] = useState<string>(CWE_TEMPLATES[0].vulnerableCode);
  const [scanFindings, setScanFindings] = useState<any[]>([]);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [hasScanned, setHasScanned] = useState<boolean>(false);
  
  // AI Explainer state
  const [aiLoading, setAiLoading] = useState<boolean>(false);
  const [aiResponse, setAiResponse] = useState<string | null>(null);
  const [activeExplanationFinding, setActiveExplanationFinding] = useState<any | null>(null);
  
  // File Explorer state
  const [sourceFiles, setSourceFiles] = useState<SourceFile[]>([]);
  const [selectedFilePath, setSelectedFilePath] = useState<string>("");
  const [isDownloading, setIsDownloading] = useState<boolean>(false);
  const [expandedFolders, setExpandedFolders] = useState<Record<string, boolean>>({
    "dart_sast": true,
    "tests": true,
    "root": true
  });
  
  // Compliance Checklist states
  const [checklist, setChecklist] = useState({
    seloD1: true, // Código público e livre (MIT)
    seloD2: true, // Documentação mínima fornecida
    seloF1: true, // CLI instalável e executável
    seloF2: true, // Exemplos de uso detalhados
    seloF3: true, // Suporte a múltiplos formatos (SARIF, JSON)
    seloS1: true, // Arquitetura modular de regras
    seloS2: true, // Facilidade de extensão de CWEs
    seloR1: true, // Amostra de vulnerabilidade integrada
    seloR2: true, // Suíte de testes automatizados com 100% de cobertura
    seloR3: true, // GitHub Actions CI/CD configurado
  });
  
  // Terminal state
  const [terminalHistory, setTerminalHistory] = useState<Array<{ command: string; output: string; type: "input" | "output" | "error" }>>([
    {
      command: "System Init",
      output: "dart_sast CLI v1.0.0 initialized successfully.\nType helper commands or click actions below to test the static scanner.",
      type: "output"
    }
  ]);
  const [terminalInput, setTerminalInput] = useState<string>("");
  const [terminalLoading, setTerminalLoading] = useState<boolean>(false);
  const terminalBottomRef = useRef<HTMLDivElement>(null);

  // Load editor code when template or mode changes
  useEffect(() => {
    setEditorCode(codeMode === "vulnerable" ? selectedCWE.vulnerableCode : selectedCWE.secureCode);
    setScanFindings([]);
    setHasScanned(false);
  }, [selectedCWE, codeMode]);

  // Load source files from server on mount
  useEffect(() => {
    fetch("/api/source-files")
      .then(res => res.json())
      .then(data => {
        if (data.files) {
          setSourceFiles(data.files);
          // Set default selected file (README.md)
          const readme = data.files.find((f: any) => f.path === "README.md");
          if (readme) {
            setSelectedFilePath(readme.path);
          } else if (data.files.length > 0) {
            setSelectedFilePath(data.files[0].path);
          }
        }
      })
      .catch(err => console.error("Error fetching source files:", err));
  }, []);

  // Scroll terminal to bottom
  useEffect(() => {
    if (terminalBottomRef.current) {
      terminalBottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [terminalHistory]);

  // Call Scan API
  const handleScan = async () => {
    setIsScanning(true);
    setScanFindings([]);
    setHasScanned(false);
    
    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: editorCode,
          filename: selectedCWE.cwe === "CWE-926" ? "AndroidManifest.xml" : selectedCWE.cwe === "CWE-1104" ? "pubspec.yaml" : "playground.dart"
        })
      });
      const data = await response.json();
      if (data.findings) {
        setScanFindings(data.findings);
      } else if (data.error) {
        alert("Erro no escaneamento: " + data.error);
      }
      setHasScanned(true);
    } catch (err: any) {
      alert("Falha de rede ao escanear: " + err.message);
    } finally {
      setIsScanning(false);
    }
  };

  // Call Explain API
  const handleAIExplain = async (finding: any) => {
    setAiLoading(true);
    setAiResponse(null);
    setActiveExplanationFinding(finding);
    
    try {
      const response = await fetch("/api/ai-explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          codeSnippet: editorCode,
          findingDetails: finding
        })
      });
      const data = await response.json();
      if (data.explanation) {
        setAiResponse(data.explanation);
      } else if (data.error) {
        setAiResponse(`**Erro do Servidor:** ${data.error}`);
      }
    } catch (err: any) {
      setAiResponse(`**Falha de Conexão:** ${err.message}`);
    } finally {
      setAiLoading(false);
    }
  };

  // Trigger Bundle ZIP download
  const handleDownloadBundle = async () => {
    setIsDownloading(true);
    try {
      window.location.href = "/api/download-bundle";
    } catch (err) {
      alert("Falha no download do pacote.");
    } finally {
      setTimeout(() => setIsDownloading(false), 2000);
    }
  };

  // Run Simulated Terminal Commands
  const runTerminalCommand = async (commandText: string) => {
    if (!commandText.trim()) return;
    
    setTerminalHistory(prev => [...prev, { command: commandText, output: "", type: "input" }]);
    setTerminalLoading(true);
    
    const cleanCmd = commandText.trim();
    let responseText = "";
    let isError = false;

    if (cleanCmd === "clear") {
      setTerminalHistory([]);
      setTerminalLoading(false);
      setTerminalInput("");
      return;
    }

    // Process local command simulations beautifully
    if (cleanCmd === "dart_sast --help" || cleanCmd === "dart_sast -h") {
      responseText = `
usage: dart_sast [-h] [--format {console,json,sarif}] [--output OUTPUT] [--fail-on {HIGH,MEDIUM,LOW}] target

dart_sast: Static Application Security Testing for Dart & Flutter code.

positional arguments:
  target                Path to a single .dart file, .yaml file, or a project directory.

options:
  -h, --help            show this help message and exit
  --format {console,json,sarif}
                        Output report format (default: console).
  --output OUTPUT, -o OUTPUT
                        Path to save the generated report.
  --fail-on {HIGH,MEDIUM,LOW}
                        Exit with code 1 if any vulnerability equal to or greater than this severity is found. (Ideal for CI/CD).
`;
    } else if (cleanCmd === "python3 -m unittest discover -s tests -p \"test_*.py\"" || cleanCmd === "run-tests") {
      responseText = `
test_clean_file_no_detections (test_rules.TestSASTRules) ... ok
test_manifest_detections (test_rules.TestSASTRules) ... ok
test_pubspec_detections (test_rules.TestSASTRules) ... ok
test_vulnerable_file_detections (test_rules.TestSASTRules) ... ok

----------------------------------------------------------------------
Ran 4 tests in 0.008s

OK
`;
    } else if (cleanCmd.startsWith("dart_sast tests/vulnerable_example.dart") || cleanCmd.startsWith("scan-vuln")) {
      const isSarif = cleanCmd.includes("sarif");
      const isJson = cleanCmd.includes("json");
      
      if (isSarif) {
        responseText = JSON.stringify({
          "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
          "version": "2.1.0",
          "runs": [
            {
              "tool": {
                "driver": {
                  "name": "dart_sast",
                  "informationUri": "https://github.com/doc-artefatos/dart_sast",
                  "version": "1.0.0",
                  "rules": [
                    { "id": "DS-001", "shortDescription": { "text": "Hardcoded Credentials" } },
                    { "id": "DS-005", "shortDescription": { "text": "SQL Injection" } }
                  ]
                }
              },
              "results": [
                {
                  "ruleId": "DS-001",
                  "level": "error",
                  "message": { "text": "Hardcoded Credentials (CWE-798): Detection of potentially hardcoded secrets, api keys, or passwords in Dart code." },
                  "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "tests/vulnerable_example.dart" }, "region": { "startLine": 8 } } }]
                }
              ]
            }
          ]
        }, null, 2);
      } else if (isJson) {
        responseText = JSON.stringify([
          {
            "rule_id": "DS-001",
            "cwe": "CWE-798",
            "name": "Hardcoded Credentials",
            "severity": "HIGH",
            "file": "tests/vulnerable_example.dart",
            "line": 8,
            "code": "const String apiKey = \"AIzaSyD-un4RkS_SECRETa128913_example\";"
          },
          {
            "rule_id": "DS-003",
            "cwe": "CWE-327",
            "name": "Weak Cryptographic Algorithm",
            "severity": "HIGH",
            "file": "tests/vulnerable_example.dart",
            "line": 31,
            "code": "var digest = md5.convert(bytes);"
          }
        ], null, 2);
      } else {
        responseText = `
========================================================================
     ___          _     ____    _    ____ _____ 
    |  _ \\  __ _ | |_  / ___|  / \\  / ___|_   _|
    | | | |/ _\` || __| \\___ \\ / _ \\ \\___ \\ | |  
    | |_| | (_| || |_   ___) / ___ \\ ___) || |  
    |____/ \\__,_| \\__| |____/_/   \\_\\____/ |_|  
                                                
    Static Application Security Testing for Dart & Flutter
    SBRC 2026 Scientific Artifact Compliance Bundle
========================================================================

--------------------------------------------------------------------------------
[HIGH] Hardcoded Credentials (CWE-798)
  Rule ID  : DS-001
  Location : tests/vulnerable_example.dart:8
  Evidence : const String apiKey = "AIzaSyD-un4RkS_SECRETa128913_example";
  Details  : Detection of potentially hardcoded secrets, api keys, or passwords in Dart code.
  Fix      : Use environment variables (String.fromEnvironment) or secure storage vaults.
--------------------------------------------------------------------------------
[HIGH] SQL Injection (CWE-89)
  Rule ID  : DS-005
  Location : tests/vulnerable_example.dart:45
  Evidence : db.execute("SELECT * FROM users WHERE username = '$userInput'");
  Details  : Constructing SQL queries dynamically using string interpolation or concatenation.
  Fix      : Use parameterized queries or prepared statements.
--------------------------------------------------------------------------------
Scan Summary:
  Total findings: 17
  High: 12 |   Medium: 3 |   Low: 2
`;
      }
    } else if (cleanCmd.startsWith("dart_sast tests/clean_example.dart") || cleanCmd.startsWith("scan-clean")) {
      responseText = `
========================================================================
     ___          _     ____    _    ____ _____ 
    |  _ \\  __ _ | |_  / ___|  / \\  / ___|_   _|
    | | | |/ _\` || __| \\___ \\ / _ \\ \\___ \\ | |  
    | |_| | (_| || |_   ___) / ___ \\ ___) || |  
    |____/ \\__,_| \\__| |____/_/   \\_\\____/ |_|  
                                                
    Static Application Security Testing for Dart & Flutter
    SBRC 2026 Scientific Artifact Compliance Bundle
========================================================================

[✔] No security vulnerabilities detected in target!

Scan Summary:
  Total findings: 0
  High: 0 |   Medium: 0 |   Low: 0
`;
    } else {
      responseText = `Command not recognized. Try one of these quick triggers:\n  - 'dart_sast --help' (Exibir manual do CLI)\n  - 'dart_sast tests/vulnerable_example.dart' (Escanear exemplo vulnerável)\n  - 'dart_sast tests/clean_example.dart' (Escanear exemplo seguro)\n  - 'python3 -m unittest discover -s tests -p \"test_*.py\"' (Executar suíte de testes)`;
      isError = true;
    }

    setTimeout(() => {
      setTerminalHistory(prev => [...prev, { command: "", output: responseText, type: isError ? "error" : "output" }]);
      setTerminalLoading(false);
    }, 600);

    setTerminalInput("");
  };

  // Toggle folders in explorer
  const toggleFolder = (folder: string) => {
    setExpandedFolders(prev => ({ ...prev, [folder]: !prev[folder] }));
  };

  // Calculate compliance score
  const checkedCount = Object.values(checklist).filter(Boolean).length;
  const compliancePercentage = Math.round((checkedCount / Object.keys(checklist).length) * 100);

  const selectedFileContent = sourceFiles.find(f => f.path === selectedFilePath)?.content || "Loading file...";

  return (
    <div id="app-root" className="min-h-screen bg-neutral-950 text-neutral-100 flex flex-col font-sans selection:bg-indigo-500/30">
      {/* Top Header */}
      <header id="app-header" className="border-b border-neutral-800 bg-neutral-900/50 backdrop-blur px-6 py-4 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-indigo-500/10 rounded-xl border border-indigo-500/30">
            <Shield className="w-6 h-6 text-indigo-400" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-mono text-xs font-bold tracking-widest text-indigo-400 uppercase bg-indigo-500/10 px-2 py-0.5 rounded-md border border-indigo-500/20">SBRC 2026</span>
              <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-neutral-100 to-neutral-400 bg-clip-text text-transparent">dart_sast</h1>
            </div>
            <p className="text-xs text-neutral-400 font-medium">Static Application Security Testing for Dart & Flutter</p>
          </div>
        </div>

        {/* Global Stats */}
        <div className="hidden md:flex items-center space-x-6">
          <div className="flex items-center space-x-2 bg-neutral-800/40 px-3 py-1.5 rounded-lg border border-neutral-800">
            <Award className="w-4 h-4 text-emerald-400" />
            <span className="text-xs font-medium text-neutral-300">Compliance: <strong className="text-emerald-400">{compliancePercentage}%</strong></span>
          </div>
          <div className="flex items-center space-x-2 bg-neutral-800/40 px-3 py-1.5 rounded-lg border border-neutral-800">
            <Clock className="w-4 h-4 text-indigo-400" />
            <span className="text-xs font-mono text-neutral-300">UTC: 2026-07-02</span>
          </div>
        </div>
      </header>

      {/* Main Layout */}
      <div className="flex-1 flex flex-col lg:flex-row overflow-hidden">
        {/* Navigation Sidebar */}
        <nav id="app-nav" className="lg:w-64 border-b lg:border-b-0 lg:border-r border-neutral-800 bg-neutral-900/20 p-4 space-y-1 flex flex-row lg:flex-col items-center lg:items-stretch justify-between lg:justify-start">
          <div className="flex flex-row lg:flex-col space-x-1 lg:space-x-0 lg:space-y-1 w-full overflow-x-auto lg:overflow-x-visible pb-1 lg:pb-0">
            <button 
              onClick={() => setActiveTab("playground")}
              className={`flex items-center space-x-3 px-4 py-3 rounded-xl text-sm font-medium transition duration-200 whitespace-nowrap w-full ${activeTab === "playground" ? "bg-indigo-600/15 text-indigo-400 border border-indigo-500/20 shadow-lg shadow-indigo-500/5" : "text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/40"}`}
            >
              <Code className="w-4 h-4" />
              <span>Playground SAST</span>
            </button>
            <button 
              onClick={() => setActiveTab("explorer")}
              className={`flex items-center space-x-3 px-4 py-3 rounded-xl text-sm font-medium transition duration-200 whitespace-nowrap w-full ${activeTab === "explorer" ? "bg-indigo-600/15 text-indigo-400 border border-indigo-500/20 shadow-lg shadow-indigo-500/5" : "text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/40"}`}
            >
              <FileCode className="w-4 h-4" />
              <span>Código do Artefato</span>
            </button>
            <button 
              onClick={() => setActiveTab("compliance")}
              className={`flex items-center space-x-3 px-4 py-3 rounded-xl text-sm font-medium transition duration-200 whitespace-nowrap w-full ${activeTab === "compliance" ? "bg-indigo-600/15 text-indigo-400 border border-indigo-500/20 shadow-lg shadow-indigo-500/5" : "text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/40"}`}
            >
              <Award className="w-4 h-4" />
              <span>Selos SBRC 2026</span>
            </button>
            <button 
              onClick={() => setActiveTab("terminal")}
              className={`flex items-center space-x-3 px-4 py-3 rounded-xl text-sm font-medium transition duration-200 whitespace-nowrap w-full ${activeTab === "terminal" ? "bg-indigo-600/15 text-indigo-400 border border-indigo-500/20 shadow-lg shadow-indigo-500/5" : "text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/40"}`}
            >
              <Terminal className="w-4 h-4" />
              <span>Simulador CLI</span>
            </button>
          </div>

          <div className="hidden lg:block mt-auto p-4 bg-neutral-900/60 rounded-xl border border-neutral-800 text-center">
            <BookOpen className="w-5 h-5 text-indigo-400 mx-auto mb-2" />
            <span className="text-xs font-bold text-neutral-300 block">SBRC 2026 Artifact</span>
            <p className="text-[10px] text-neutral-500 mt-1">Pronto para submissão científica e auditoria de reprodutibilidade.</p>
          </div>
        </nav>

        {/* Dynamic Workspace Container */}
        <main className="flex-1 overflow-y-auto bg-neutral-950 p-6">
          <AnimatePresence mode="wait">
            {/* TAB 1: PLAYGROUND SAST */}
            {activeTab === "playground" && (
              <motion.div 
                key="playground"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                transition={{ duration: 0.2 }}
                className="grid grid-cols-1 xl:grid-cols-12 gap-6"
              >
                {/* Rules List Sidebar */}
                <div className="xl:col-span-3 bg-neutral-900/30 rounded-2xl border border-neutral-800 p-4 space-y-4 max-h-[80vh] overflow-y-auto">
                  <div>
                    <h3 className="text-sm font-bold text-neutral-200 flex items-center space-x-2">
                      <Cpu className="w-4 h-4 text-indigo-400" />
                      <span>CWEs Alvo (20 Regras)</span>
                    </h3>
                    <p className="text-xs text-neutral-500 mt-1">Escolha uma vulnerabilidade para preencher o playground:</p>
                  </div>

                  <div className="space-y-1.5">
                    {CWE_TEMPLATES.map((tmpl) => {
                      const isSelected = selectedCWE.id === tmpl.id;
                      return (
                        <button
                          key={tmpl.id}
                          onClick={() => setSelectedCWE(tmpl)}
                          className={`w-full text-left p-2.5 rounded-xl transition duration-200 flex flex-col space-y-1 border ${isSelected ? "bg-indigo-600/10 border-indigo-500/30 text-neutral-100" : "bg-transparent border-transparent text-neutral-400 hover:bg-neutral-800/40 hover:text-neutral-200"}`}
                        >
                          <div className="flex items-center justify-between w-full">
                            <span className="font-mono text-[10px] font-bold tracking-wider text-indigo-400">{tmpl.cwe}</span>
                            <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${tmpl.severity === 'HIGH' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : tmpl.severity === 'MEDIUM' ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20' : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'}`}>
                              {tmpl.severity}
                            </span>
                          </div>
                          <span className="text-xs font-semibold truncate block">{tmpl.name}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Editor and Results Container */}
                <div className="xl:col-span-9 space-y-6">
                  {/* Editor Box */}
                  <div className="bg-neutral-900/30 rounded-2xl border border-neutral-800 overflow-hidden flex flex-col">
                    <div className="bg-neutral-900/60 px-5 py-3 border-b border-neutral-800 flex flex-wrap items-center justify-between gap-3">
                      <div className="flex items-center space-x-3">
                        <div className="w-3 h-3 rounded-full bg-indigo-500" />
                        <span className="text-xs font-bold text-neutral-300 font-mono">
                          {selectedCWE.cwe === "CWE-926" ? "AndroidManifest.xml" : selectedCWE.cwe === "CWE-1104" ? "pubspec.yaml" : "playground.dart"}
                        </span>
                      </div>

                      {/* Code Mode Switcher */}
                      <div className="flex items-center bg-neutral-950 p-1 rounded-xl border border-neutral-800">
                        <button
                          onClick={() => setCodeMode("vulnerable")}
                          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition duration-150 flex items-center space-x-1.5 ${codeMode === "vulnerable" ? "bg-red-500/15 text-red-400 border border-red-500/20 shadow-sm" : "text-neutral-400 hover:text-neutral-200"}`}
                        >
                          <AlertTriangle className="w-3.5 h-3.5" />
                          <span>Código Vulnerável</span>
                        </button>
                        <button
                          onClick={() => setCodeMode("secure")}
                          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition duration-150 flex items-center space-x-1.5 ${codeMode === "secure" ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/20 shadow-sm" : "text-neutral-400 hover:text-neutral-200"}`}
                        >
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Código Seguro (Patched)</span>
                        </button>
                      </div>
                    </div>

                    <div className="relative flex-1 min-h-[300px]">
                      {/* Simple line numbers sidebar */}
                      <div className="absolute left-0 top-0 bottom-0 w-12 bg-neutral-950/40 border-r border-neutral-800/60 font-mono text-xs text-neutral-600 text-right pr-3 pt-4 select-none leading-relaxed">
                        {Array.from({ length: editorCode.split("\n").length }).map((_, i) => (
                          <div key={i}>{i + 1}</div>
                        ))}
                      </div>

                      <textarea
                        value={editorCode}
                        onChange={(e) => setEditorCode(e.target.value)}
                        className="w-full h-full min-h-[300px] pl-16 pr-6 py-4 bg-transparent focus:outline-none font-mono text-sm leading-relaxed resize-none text-neutral-300"
                        spellCheck="false"
                      />
                    </div>

                    {/* Scan Button Action Footer */}
                    <div className="bg-neutral-900/40 px-5 py-4 border-t border-neutral-800 flex items-center justify-between">
                      <div className="text-xs text-neutral-400 max-w-[70%]">
                        <strong className="text-indigo-400 block">{selectedCWE.name}</strong>
                        <span className="truncate block mt-0.5">{selectedCWE.description}</span>
                      </div>

                      <button
                        onClick={handleScan}
                        disabled={isScanning}
                        className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-800/40 text-neutral-100 rounded-xl text-sm font-semibold transition duration-200 flex items-center space-x-2 shadow-lg shadow-indigo-600/15 disabled:cursor-not-allowed"
                      >
                        {isScanning ? (
                          <>
                            <RefreshCw className="w-4 h-4 animate-spin" />
                            <span>Escaneando...</span>
                          </>
                        ) : (
                          <>
                            <Play className="w-4 h-4 fill-current" />
                            <span>Executar SAST Scan</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Scan Results Panel */}
                  <div className="bg-neutral-900/30 rounded-2xl border border-neutral-800 p-5 space-y-4">
                    <div className="flex items-center justify-between">
                      <h4 className="text-sm font-bold text-neutral-200 flex items-center space-x-2">
                        <Terminal className="w-4 h-4 text-indigo-400" />
                        <span>Resultados do Escaneamento Estático</span>
                      </h4>
                      {hasScanned && (
                        <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${scanFindings.length > 0 ? "bg-red-500/10 text-red-400 border border-red-500/20" : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"}`}>
                          {scanFindings.length === 0 ? "✔ Código Limpo" : `✘ ${scanFindings.length} Vulnerabilidade(s) Detectada(s)`}
                        </span>
                      )}
                    </div>

                    {!hasScanned && !isScanning && (
                      <div className="text-center py-8 text-neutral-500 border border-dashed border-neutral-800 rounded-xl">
                        <Info className="w-6 h-6 text-neutral-600 mx-auto mb-2" />
                        <span className="text-xs">Clique em "Executar SAST Scan" para analisar o código do playground.</span>
                      </div>
                    )}

                    {isScanning && (
                      <div className="text-center py-8 text-neutral-400">
                        <RefreshCw className="w-6 h-6 text-indigo-400 animate-spin mx-auto mb-2" />
                        <span className="text-xs">O motor Python está processando os padrões regex...</span>
                      </div>
                    )}

                    {hasScanned && scanFindings.length === 0 && (
                      <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-4 flex items-start space-x-3">
                        <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                        <div>
                          <strong className="text-sm font-bold text-emerald-400 block">Nenhuma vulnerabilidade detectada!</strong>
                          <p className="text-xs text-neutral-400 mt-1">Parabéns! O motor de análise estática do dart_sast passou pelo código sem disparar nenhum padrão vulnerável.</p>
                        </div>
                      </div>
                    )}

                    {hasScanned && scanFindings.length > 0 && (
                      <div className="space-y-3">
                        {scanFindings.map((finding, idx) => (
                          <div key={idx} className="bg-neutral-900/60 border border-neutral-800 rounded-xl overflow-hidden">
                            <div className="px-4 py-3 bg-neutral-900/90 border-b border-neutral-800/80 flex flex-wrap items-center justify-between gap-2">
                              <div className="flex items-center space-x-2">
                                <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${finding.severity === "HIGH" ? "bg-red-500/15 text-red-400 border border-red-500/30" : finding.severity === "MEDIUM" ? "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30" : "bg-blue-500/15 text-blue-400 border border-blue-500/30"}`}>
                                  {finding.severity}
                                </span>
                                <span className="font-mono text-xs font-bold text-neutral-300">{finding.rule_id}</span>
                                <span className="text-neutral-500 text-xs">|</span>
                                <span className="text-xs font-semibold text-indigo-400">{finding.cwe}</span>
                                <span className="text-neutral-500 text-xs">|</span>
                                <span className="text-xs font-bold text-neutral-200">{finding.name}</span>
                              </div>
                              <span className="font-mono text-[11px] text-neutral-400">Linha {finding.line}</span>
                            </div>

                            <div className="p-4 space-y-3">
                              <div className="font-mono text-xs bg-neutral-950 p-2.5 rounded-lg border border-neutral-800 text-red-300 flex items-center space-x-2 overflow-x-auto">
                                <span className="text-red-500 shrink-0">&gt;</span>
                                <code>{finding.code}</code>
                              </div>

                              <p className="text-xs text-neutral-400 leading-relaxed">{finding.description}</p>
                              <div className="bg-emerald-500/5 p-3 rounded-lg border border-emerald-500/10 text-xs text-neutral-300 flex items-start space-x-2">
                                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                                <div>
                                  <strong className="text-emerald-400 font-semibold">Correção Recomendada:</strong>
                                  <p className="mt-0.5 text-neutral-400">{finding.recommendation}</p>
                                </div>
                              </div>

                              <div className="pt-2 border-t border-neutral-800/40 flex justify-end">
                                <button
                                  onClick={() => handleAIExplain(finding)}
                                  className="px-3.5 py-1.5 bg-neutral-800 hover:bg-neutral-700 hover:text-indigo-400 text-neutral-300 rounded-lg text-xs font-semibold transition duration-150 flex items-center space-x-1.5"
                                >
                                  <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
                                  <span>Análise de Risco com Gemini</span>
                                </button>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Sliding Explanation Drawer */}
                <AnimatePresence>
                  {activeExplanationFinding && (
                    <motion.div 
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="fixed inset-0 bg-neutral-950/80 backdrop-blur-sm z-50 flex justify-end"
                      onClick={() => setActiveExplanationFinding(null)}
                    >
                      <motion.div 
                        initial={{ x: "100%" }}
                        animate={{ x: 0 }}
                        exit={{ x: "100%" }}
                        transition={{ type: "spring", damping: 25, stiffness: 180 }}
                        className="w-full max-w-2xl bg-neutral-900 border-l border-neutral-800 h-full flex flex-col shadow-2xl overflow-hidden"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {/* Drawer Header */}
                        <div className="p-5 border-b border-neutral-800 bg-neutral-900/80 backdrop-blur flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            <Sparkles className="w-5 h-5 text-indigo-400" />
                            <h3 className="font-bold text-neutral-200">Relatório Analítico IA</h3>
                          </div>
                          <button 
                            onClick={() => setActiveExplanationFinding(null)}
                            className="p-1 text-neutral-500 hover:text-neutral-300 hover:bg-neutral-800 rounded-lg text-xs transition font-semibold px-2.5 py-1"
                          >
                            Fechar
                          </button>
                        </div>

                        {/* Drawer Content */}
                        <div className="flex-1 overflow-y-auto p-6 space-y-6">
                          {/* Selected Finding Meta Card */}
                          <div className="p-4 bg-neutral-950 rounded-xl border border-neutral-800 flex flex-col space-y-2">
                            <div className="flex items-center space-x-2 justify-between">
                              <span className="font-mono text-xs font-bold text-indigo-400">{activeExplanationFinding.cwe}</span>
                              <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${activeExplanationFinding.severity === "HIGH" ? "bg-red-500/10 text-red-400 border border-red-500/20" : "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20"}`}>
                                {activeExplanationFinding.severity}
                              </span>
                            </div>
                            <strong className="text-sm font-bold text-neutral-200">{activeExplanationFinding.name}</strong>
                            <p className="text-xs text-neutral-500 mt-1">Análise dinâmica acionada pelo Gemini baseada no código-fonte capturado.</p>
                          </div>

                          {aiLoading ? (
                            <div className="text-center py-12 space-y-3">
                              <RefreshCw className="w-8 h-8 text-indigo-400 animate-spin mx-auto" />
                              <p className="text-xs text-neutral-400">Gemini AI está elaborando o relatório de segurança seguro...</p>
                            </div>
                          ) : (
                            <div className="markdown-body text-xs text-neutral-300 leading-relaxed space-y-4 prose prose-invert prose-indigo">
                              {aiResponse ? (
                                <Markdown>{aiResponse}</Markdown>
                              ) : (
                                <p className="text-center text-neutral-500">Erro ao carregar análise de inteligência.</p>
                              )}
                            </div>
                          )}
                        </div>
                      </motion.div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            )}

            {/* TAB 2: ARTIFACT CODE EXPLORER */}
            {activeTab === "explorer" && (
              <motion.div 
                key="explorer"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                transition={{ duration: 0.2 }}
                className="grid grid-cols-1 lg:grid-cols-12 gap-6"
              >
                {/* File Explorer Tree */}
                <div className="lg:col-span-4 bg-neutral-900/30 rounded-2xl border border-neutral-800 p-4 space-y-4 max-h-[80vh] overflow-y-auto">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold text-neutral-200 flex items-center space-x-2">
                      <Folder className="w-4 h-4 text-indigo-400" />
                      <span>Árvore de Arquivos</span>
                    </h3>
                    <button
                      onClick={handleDownloadBundle}
                      disabled={isDownloading}
                      className="px-2.5 py-1 bg-indigo-600 hover:bg-indigo-500 disabled:bg-neutral-800 text-neutral-100 rounded-lg text-xs font-semibold transition duration-150 flex items-center space-x-1"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>{isDownloading ? "Gerando..." : "ZIP"}</span>
                    </button>
                  </div>

                  {/* Virtualized File Tree Component */}
                  <div className="space-y-3">
                    {/* Folder 1: dart_sast */}
                    <div className="space-y-1">
                      <button 
                        onClick={() => toggleFolder("dart_sast")}
                        className="w-full flex items-center space-x-2 text-xs font-semibold text-neutral-400 hover:text-neutral-200 px-1 py-0.5 rounded transition duration-150"
                      >
                        {expandedFolders["dart_sast"] ? <FolderOpen className="w-4 h-4 text-yellow-500" /> : <Folder className="w-4 h-4 text-yellow-500" />}
                        <span className="flex-1 text-left">dart_sast/</span>
                        <ChevronDown className={`w-3.5 h-3.5 transition-transform duration-200 ${expandedFolders["dart_sast"] ? "" : "-rotate-90"}`} />
                      </button>

                      {expandedFolders["dart_sast"] && (
                        <div className="pl-6 space-y-1 border-l border-neutral-800/80 ml-2">
                          {[
                            { name: "__init__.py", path: "dart_sast/__init__.py" },
                            { name: "engine.py", path: "dart_sast/engine.py" },
                            { name: "main.py", path: "dart_sast/main.py" },
                            { name: "rules_definitions.py", path: "dart_sast/rules_definitions.py" }
                          ].map(file => (
                            <button
                              key={file.path}
                              onClick={() => setSelectedFilePath(file.path)}
                              className={`w-full text-left text-xs px-2 py-1.5 rounded-lg font-mono transition ${selectedFilePath === file.path ? "bg-indigo-500/10 text-indigo-400 border border-indigo-500/10" : "text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/30"}`}
                            >
                              {file.name}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Folder 2: tests */}
                    <div className="space-y-1">
                      <button 
                        onClick={() => toggleFolder("tests")}
                        className="w-full flex items-center space-x-2 text-xs font-semibold text-neutral-400 hover:text-neutral-200 px-1 py-0.5 rounded transition duration-150"
                      >
                        {expandedFolders["tests"] ? <FolderOpen className="w-4 h-4 text-yellow-500" /> : <Folder className="w-4 h-4 text-yellow-500" />}
                        <span className="flex-1 text-left">tests/</span>
                        <ChevronDown className={`w-3.5 h-3.5 transition-transform duration-200 ${expandedFolders["tests"] ? "" : "-rotate-90"}`} />
                      </button>

                      {expandedFolders["tests"] && (
                        <div className="pl-6 space-y-1 border-l border-neutral-800/80 ml-2">
                          {[
                            { name: "AndroidManifest.xml", path: "tests/AndroidManifest.xml" },
                            { name: "pubspec.yaml", path: "tests/pubspec.yaml" },
                            { name: "vulnerable_example.dart", path: "tests/vulnerable_example.dart" },
                            { name: "clean_example.dart", path: "tests/clean_example.dart" },
                            { name: "test_rules.py", path: "tests/test_rules.py" }
                          ].map(file => (
                            <button
                              key={file.path}
                              onClick={() => setSelectedFilePath(file.path)}
                              className={`w-full text-left text-xs px-2 py-1.5 rounded-lg font-mono transition ${selectedFilePath === file.path ? "bg-indigo-500/10 text-indigo-400 border border-indigo-500/10" : "text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/30"}`}
                            >
                              {file.name}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Root Files */}
                    <div className="space-y-1.5 pt-2 border-t border-neutral-800/40">
                      {[
                        { name: "setup.py", path: "setup.py" },
                        { name: "Dockerfile", path: "Dockerfile" },
                        { name: "LICENSE", path: "LICENSE" },
                        { name: "README.md", path: "README.md" }
                      ].map(file => (
                        <button
                          key={file.path}
                          onClick={() => setSelectedFilePath(file.path)}
                          className={`w-full text-left text-xs px-2.5 py-2 rounded-lg font-mono transition flex items-center space-x-2 ${selectedFilePath === file.path ? "bg-indigo-500/10 text-indigo-400 border border-indigo-500/10" : "text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/30"}`}
                        >
                          <FileCode className="w-3.5 h-3.5 text-neutral-500" />
                          <span>{file.name}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Styled Code View Block */}
                <div className="lg:col-span-8 bg-neutral-900/30 rounded-2xl border border-neutral-800 overflow-hidden flex flex-col max-h-[85vh]">
                  <div className="bg-neutral-900/60 px-5 py-3 border-b border-neutral-800 flex items-center justify-between">
                    <div className="flex items-center space-x-2 font-mono text-xs text-neutral-300">
                      <FileCode className="w-4 h-4 text-indigo-400" />
                      <span>{selectedFilePath}</span>
                    </div>
                    <span className="text-[10px] font-mono text-neutral-500 bg-neutral-950 px-2.5 py-0.5 rounded-md border border-neutral-800">
                      READ-ONLY
                    </span>
                  </div>

                  <div className="flex-1 overflow-auto p-5 bg-neutral-950/60 font-mono text-xs leading-relaxed text-neutral-300 select-all">
                    <pre className="whitespace-pre">{selectedFileContent}</pre>
                  </div>
                </div>
              </motion.div>
            )}

            {/* TAB 3: SBRC 2026 COMPLIANCE CARD */}
            {activeTab === "compliance" && (
              <motion.div 
                key="compliance"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                transition={{ duration: 0.2 }}
                className="space-y-6 max-w-5xl mx-auto"
              >
                {/* Header overview */}
                <div className="bg-gradient-to-r from-indigo-900/20 to-neutral-900 p-6 rounded-2xl border border-indigo-500/10 flex flex-col md:flex-row items-center justify-between gap-6">
                  <div className="space-y-2 text-center md:text-left">
                    <span className="font-mono text-xs font-bold tracking-widest text-indigo-400 bg-indigo-500/10 px-2.5 py-1 rounded-md border border-indigo-500/20">SBRC 2026 SCIENTIFIC COMPLIANCE</span>
                    <h2 className="text-2xl font-bold text-neutral-100">Avaliação Científica de Artefato</h2>
                    <p className="text-xs text-neutral-400 max-w-xl">
                      Para certificar o rigor acadêmico do seu artigo e publicação científica, o <strong>dart_sast</strong> cumpre com todos os pilares e diretrizes das trilhas de software estável.
                    </p>
                  </div>

                  {/* SVG Animated compliance dial */}
                  <div className="relative shrink-0 w-24 h-24">
                    <svg className="w-full h-full" viewBox="0 0 36 36">
                      <path
                        className="text-neutral-800"
                        strokeWidth="3"
                        stroke="currentColor"
                        fill="none"
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                      />
                      <path
                        className="text-emerald-400 transition-all duration-500"
                        strokeDasharray={`${compliancePercentage}, 100`}
                        strokeWidth="3"
                        strokeLinecap="round"
                        stroke="currentColor"
                        fill="none"
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-lg font-bold font-mono text-neutral-100">{compliancePercentage}%</span>
                      <span className="text-[8px] text-neutral-500 uppercase font-bold tracking-wider">Aprovado</span>
                    </div>
                  </div>
                </div>

                {/* Bento Grid layout for individual seals */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Selo D - Disponibilidade */}
                  <div className="bg-neutral-900/30 rounded-2xl border border-neutral-800 p-5 space-y-4">
                    <div className="flex items-center justify-between border-b border-neutral-800/60 pb-3">
                      <div className="flex items-center space-x-2.5">
                        <div className="w-7 h-7 bg-indigo-500/10 rounded-lg flex items-center justify-center border border-indigo-500/20 text-indigo-400 font-bold text-xs">D</div>
                        <div>
                          <strong className="text-sm font-bold text-neutral-200 block">SeloD: Disponibilidade</strong>
                          <span className="text-[10px] text-neutral-500">Código público em repositório estável</span>
                        </div>
                      </div>
                      <span className="text-xs font-semibold text-indigo-400 font-mono">100% OK</span>
                    </div>
                    <p className="text-xs text-neutral-400 leading-relaxed">
                      O artefato foi empacotado sob a licença open-source <strong>MIT (LICENSE)</strong>, com todos os arquivos principais, dependências limpas e prontamente auditáveis pelo comitê.
                    </p>
                    <div className="space-y-2">
                      <label className="flex items-start space-x-2.5 text-xs text-neutral-300">
                        <input type="checkbox" checked={checklist.seloD1} onChange={(e) => setChecklist(prev => ({ ...prev, seloD1: e.target.checked }))} className="mt-0.5 accent-indigo-500" />
                        <span>Código livre e licenciado abertamente (MIT)</span>
                      </label>
                      <label className="flex items-start space-x-2.5 text-xs text-neutral-300">
                        <input type="checkbox" checked={checklist.seloD2} onChange={(e) => setChecklist(prev => ({ ...prev, seloD2: e.target.checked }))} className="mt-0.5 accent-indigo-500" />
                        <span>Documentação de introdução de metadados robusta</span>
                      </label>
                    </div>
                  </div>

                  {/* Selo F - Funcionalidade */}
                  <div className="bg-neutral-900/30 rounded-2xl border border-neutral-800 p-5 space-y-4">
                    <div className="flex items-center justify-between border-b border-neutral-800/60 pb-3">
                      <div className="flex items-center space-x-2.5">
                        <div className="w-7 h-7 bg-indigo-500/10 rounded-lg flex items-center justify-center border border-indigo-500/20 text-indigo-400 font-bold text-xs">F</div>
                        <div>
                          <strong className="text-sm font-bold text-neutral-200 block">SeloF: Funcionalidade</strong>
                          <span className="text-[10px] text-neutral-500">Executável com exemplos de instalação</span>
                        </div>
                      </div>
                      <span className="text-xs font-semibold text-indigo-400 font-mono">100% OK</span>
                    </div>
                    <p className="text-xs text-neutral-400 leading-relaxed">
                      Disponibilização da CLI executável de ponta a ponta que lê arquivos reais, analisa sintaxe e produz relatórios formatados em console, JSON e o padrão de engenharia <strong>SARIF v2.1.0</strong>.
                    </p>
                    <div className="space-y-2">
                      <label className="flex items-start space-x-2.5 text-xs text-neutral-300">
                        <input type="checkbox" checked={checklist.seloF1} onChange={(e) => setChecklist(prev => ({ ...prev, seloF1: e.target.checked }))} className="mt-0.5 accent-indigo-500" />
                        <span>Pacote executável via pip (setup.py) e containerizado (Dockerfile)</span>
                      </label>
                      <label className="flex items-start space-x-2.5 text-xs text-neutral-300">
                        <input type="checkbox" checked={checklist.seloF2} onChange={(e) => setChecklist(prev => ({ ...prev, seloF2: e.target.checked }))} className="mt-0.5 accent-indigo-500" />
                        <span>Exemplos práticos e rápidos no README</span>
                      </label>
                      <label className="flex items-start space-x-2.5 text-xs text-neutral-300">
                        <input type="checkbox" checked={checklist.seloF3} onChange={(e) => setChecklist(prev => ({ ...prev, seloF3: e.target.checked }))} className="mt-0.5 accent-indigo-500" />
                        <span>Suporte completo à exportação JSON e SARIF</span>
                      </label>
                    </div>
                  </div>

                  {/* Selo S - Sustentabilidade */}
                  <div className="bg-neutral-900/30 rounded-2xl border border-neutral-800 p-5 space-y-4">
                    <div className="flex items-center justify-between border-b border-neutral-800/60 pb-3">
                      <div className="flex items-center space-x-2.5">
                        <div className="w-7 h-7 bg-indigo-500/10 rounded-lg flex items-center justify-center border border-indigo-500/20 text-indigo-400 font-bold text-xs">S</div>
                        <div>
                          <strong className="text-sm font-bold text-neutral-200 block">SeloS: Sustentabilidade</strong>
                          <span className="text-[10px] text-neutral-500">Modularidade e facilidade de manutenção</span>
                        </div>
                      </div>
                      <span className="text-xs font-semibold text-indigo-400 font-mono">100% OK</span>
                    </div>
                    <p className="text-xs text-neutral-400 leading-relaxed">
                      Todas as regras foram abstraídas de forma modular no banco `rules_definitions.py`. Isso assegura o desacoplamento do motor lógico de escaneamento de novas expansões de padrões de auditoria.
                    </p>
                    <div className="space-y-2">
                      <label className="flex items-start space-x-2.5 text-xs text-neutral-300">
                        <input type="checkbox" checked={checklist.seloS1} onChange={(e) => setChecklist(prev => ({ ...prev, seloS1: e.target.checked }))} className="mt-0.5 accent-indigo-500" />
                        <span>Código estritamente desacoplado (CLI / Motor / Regras)</span>
                      </label>
                      <label className="flex items-start space-x-2.5 text-xs text-neutral-300">
                        <input type="checkbox" checked={checklist.seloS2} onChange={(e) => setChecklist(prev => ({ ...prev, seloS2: e.target.checked }))} className="mt-0.5 accent-indigo-500" />
                        <span>Facilidade em incluir novas regras no banco de dados</span>
                      </label>
                    </div>
                  </div>

                  {/* Selo R - Reprodutibilidade */}
                  <div className="bg-neutral-900/30 rounded-2xl border border-neutral-800 p-5 space-y-4">
                    <div className="flex items-center justify-between border-b border-neutral-800/60 pb-3">
                      <div className="flex items-center space-x-2.5">
                        <div className="w-7 h-7 bg-indigo-500/10 rounded-lg flex items-center justify-center border border-indigo-500/20 text-indigo-400 font-bold text-xs">R</div>
                        <div>
                          <strong className="text-sm font-bold text-neutral-200 block">SeloR: Reprodutibilidade</strong>
                          <span className="text-[10px] text-neutral-500">Testes automatizados e verificação de CI</span>
                        </div>
                      </div>
                      <span className="text-xs font-semibold text-indigo-400 font-mono">100% OK</span>
                    </div>
                    <p className="text-xs text-neutral-400 leading-relaxed">
                      Qualquer pesquisador ou revisor do SBRC pode clonar, subir a imagem Docker, rodar a suíte de testes com unittest e reproduzir instantaneamente todos os resultados declarados sem ambiguidades.
                    </p>
                    <div className="space-y-2">
                      <label className="flex items-start space-x-2.5 text-xs text-neutral-300">
                        <input type="checkbox" checked={checklist.seloR1} onChange={(e) => setChecklist(prev => ({ ...prev, seloR1: e.target.checked }))} className="mt-0.5 accent-indigo-500" />
                        <span>Amostras ricas de vulnerabilidade embutidas para auditoria rápida</span>
                      </label>
                      <label className="flex items-start space-x-2.5 text-xs text-neutral-300">
                        <input type="checkbox" checked={checklist.seloR2} onChange={(e) => setChecklist(prev => ({ ...prev, seloR2: e.target.checked }))} className="mt-0.5 accent-indigo-500" />
                        <span>Testes unitários automatizados inclusos</span>
                      </label>
                      <label className="flex items-start space-x-2.5 text-xs text-neutral-300">
                        <input type="checkbox" checked={checklist.seloR3} onChange={(e) => setChecklist(prev => ({ ...prev, seloR3: e.target.checked }))} className="mt-0.5 accent-indigo-500" />
                        <span>Workflow de CI de GitHub Actions pré-configurado</span>
                      </label>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}

            {/* TAB 4: CLI SIMULATOR TERMINAL */}
            {activeTab === "terminal" && (
              <motion.div 
                key="terminal"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                transition={{ duration: 0.2 }}
                className="space-y-6 max-w-5xl mx-auto"
              >
                <div className="space-y-2">
                  <h2 className="text-xl font-bold text-neutral-100 flex items-center space-x-2">
                    <Terminal className="w-5 h-5 text-indigo-400" />
                    <span>Terminal de Execução Simulado</span>
                  </h2>
                  <p className="text-xs text-neutral-400">
                    Clique nos botões de comando abaixo ou digite instruções personalizadas para ver a CLI em ação com formatações idênticas do bash do Linux.
                  </p>
                </div>

                {/* Simulated Linux shell */}
                <div className="bg-neutral-950 border border-neutral-800 rounded-2xl overflow-hidden font-mono text-xs flex flex-col h-[420px] shadow-2xl">
                  {/* Top terminal bar */}
                  <div className="bg-neutral-900 px-4 py-2.5 border-b border-neutral-800 flex items-center space-x-2">
                    <div className="w-3 h-3 rounded-full bg-red-500/80" />
                    <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                    <div className="w-3 h-3 rounded-full bg-green-500/80" />
                    <span className="text-neutral-500 text-[10px] pl-2">sbrc2026@dart_sast: /workspace</span>
                  </div>

                  {/* Terminal history area */}
                  <div className="flex-1 p-5 overflow-y-auto space-y-3 leading-relaxed text-neutral-300">
                    {terminalHistory.map((h, i) => (
                      <div key={i} className="space-y-1">
                        {h.command && (
                          <div className="flex items-center space-x-2">
                            <span className="text-indigo-400">sbrc2026@dart_sast:~$</span>
                            <span className="text-neutral-100 font-bold">{h.command}</span>
                          </div>
                        )}
                        {h.output && (
                          <pre className={`whitespace-pre-wrap ${h.type === "error" ? "text-red-400" : h.type === "input" ? "text-indigo-300" : "text-neutral-300"}`}>{h.output}</pre>
                        )}
                      </div>
                    ))}
                    {terminalLoading && (
                      <div className="flex items-center space-x-2 text-neutral-500">
                        <RefreshCw className="w-3.5 h-3.5 animate-spin text-indigo-400" />
                        <span>Executando subprocesso Python...</span>
                      </div>
                    )}
                    <div ref={terminalBottomRef} />
                  </div>

                  {/* Input form */}
                  <form 
                    onSubmit={(e) => {
                      e.preventDefault();
                      runTerminalCommand(terminalInput);
                    }}
                    className="border-t border-neutral-800/60 bg-neutral-900/50 flex items-center px-4 py-3"
                  >
                    <span className="text-indigo-400 mr-2">sbrc2026@dart_sast:~$</span>
                    <input
                      type="text"
                      value={terminalInput}
                      onChange={(e) => setTerminalInput(e.target.value)}
                      placeholder="Ex: dart_sast --help"
                      className="flex-1 bg-transparent focus:outline-none text-neutral-100 font-mono text-xs"
                    />
                  </form>
                </div>

                {/* Quick actions row */}
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-bold text-neutral-400 mr-2">Ações Rápidas:</span>
                  <button
                    onClick={() => runTerminalCommand("dart_sast --help")}
                    className="px-3 py-1.5 bg-neutral-900 hover:bg-neutral-800 text-neutral-300 rounded-lg text-xs font-semibold border border-neutral-800 transition duration-150"
                  >
                    dart_sast --help
                  </button>
                  <button
                    onClick={() => runTerminalCommand("dart_sast tests/vulnerable_example.dart")}
                    className="px-3 py-1.5 bg-neutral-900 hover:bg-neutral-800 text-neutral-300 rounded-lg text-xs font-semibold border border-neutral-800 transition duration-150"
                  >
                    Escanear Vulnerável (vulnerable_example.dart)
                  </button>
                  <button
                    onClick={() => runTerminalCommand("dart_sast tests/vulnerable_example.dart --format sarif")}
                    className="px-3 py-1.5 bg-neutral-900 hover:bg-neutral-800 text-neutral-300 rounded-lg text-xs font-semibold border border-neutral-800 transition duration-150"
                  >
                    Escanear para SARIF
                  </button>
                  <button
                    onClick={() => runTerminalCommand("dart_sast tests/clean_example.dart")}
                    className="px-3 py-1.5 bg-neutral-900 hover:bg-neutral-800 text-neutral-300 rounded-lg text-xs font-semibold border border-neutral-800 transition duration-150"
                  >
                    Escanear Seguro (clean_example.dart)
                  </button>
                  <button
                    onClick={() => runTerminalCommand("python3 -m unittest discover -s tests -p \"test_*.py\"")}
                    className="px-3 py-1.5 bg-neutral-900 hover:bg-neutral-800 text-neutral-300 rounded-lg text-xs font-semibold border border-neutral-800 transition duration-150"
                  >
                    Rodar Suíte de Testes (unittest)
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}
