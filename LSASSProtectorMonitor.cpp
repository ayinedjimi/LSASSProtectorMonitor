// LSASSProtectorMonitor.cpp
// Ayi NEDJIMI Consultants - WinToolsSuite
// Outil de monitoring des accès suspects au processus LSASS

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winevt.h>
#include <commctrl.h>
#include <commdlg.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <fstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ===== RAII AutoHandle =====
class AutoHandle {
    HANDLE h;
public:
    AutoHandle(HANDLE handle = nullptr) : h(handle) {}
    ~AutoHandle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    operator HANDLE() const { return h; }
    HANDLE* operator&() { return &h; }
    AutoHandle(const AutoHandle&) = delete;
    AutoHandle& operator=(const AutoHandle&) = delete;
};

// ===== Structures =====
struct LSASSAlert {
    std::wstring horodatage;
    std::wstring processSuspect;
    DWORD pid;
    std::wstring typeAcces;
    std::wstring utilisateur;
    std::wstring alertes;
};

// ===== Globales =====
HWND g_hMainWnd = nullptr;
HWND g_hListView = nullptr;
HWND g_hStatusBar = nullptr;
HWND g_hBtnStart = nullptr;
HWND g_hBtnStop = nullptr;
HWND g_hBtnExport = nullptr;

std::vector<LSASSAlert> g_alerts;
std::mutex g_dataMutex;
std::atomic<bool> g_monitoring(false);
std::thread g_monitorThread;
std::wstring g_logFilePath;
DWORD g_lsassPID = 0;

constexpr int ID_BTN_START = 1001;
constexpr int ID_BTN_STOP = 1002;
constexpr int ID_BTN_EXPORT = 1003;
constexpr int ID_LISTVIEW = 2001;
constexpr int ID_STATUSBAR = 3001;

// ===== Logging =====
void InitLog() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    g_logFilePath = std::wstring(tempPath) + L"WinTools_LSASSProtectorMonitor_log.txt";
}

void Log(const std::wstring& message) {
    SYSTEMTIME st;
    GetLocalTime(&st);

    std::wofstream logFile(g_logFilePath, std::ios::app);
    if (logFile.is_open()) {
        logFile << std::setfill(L'0')
                << std::setw(4) << st.wYear << L"-"
                << std::setw(2) << st.wMonth << L"-"
                << std::setw(2) << st.wDay << L" "
                << std::setw(2) << st.wHour << L":"
                << std::setw(2) << st.wMinute << L":"
                << std::setw(2) << st.wSecond << L" | "
                << message << std::endl;
        logFile.close();
    }
}

// ===== Utilitaires =====
std::wstring GetCurrentTimeStamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);

    std::wstringstream ss;
    ss << std::setfill(L'0')
       << std::setw(4) << st.wYear << L"-"
       << std::setw(2) << st.wMonth << L"-"
       << std::setw(2) << st.wDay << L" "
       << std::setw(2) << st.wHour << L":"
       << std::setw(2) << st.wMinute << L":"
       << std::setw(2) << st.wSecond;

    return ss.str();
}

std::wstring GetProcessUser(HANDLE hProcess) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return L"Inconnu";
    }
    AutoHandle autoToken(hToken);

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwSize);
    if (dwSize == 0) return L"Inconnu";

    std::vector<BYTE> buffer(dwSize);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), dwSize, &dwSize)) {
        return L"Inconnu";
    }

    TOKEN_USER* pTokenUser = (TOKEN_USER*)buffer.data();
    wchar_t userName[256] = {0};
    wchar_t domainName[256] = {0};
    DWORD userNameSize = 256;
    DWORD domainNameSize = 256;
    SID_NAME_USE sidType;

    if (LookupAccountSidW(nullptr, pTokenUser->User.Sid, userName, &userNameSize,
                          domainName, &domainNameSize, &sidType)) {
        return std::wstring(domainName) + L"\\" + userName;
    }

    return L"Inconnu";
}

// ===== Trouver PID de lsass.exe =====
DWORD FindLSASSPID() {
    AutoHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe32 = {0};
    pe32.dwSize = sizeof(pe32);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"lsass.exe") == 0) {
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    return 0;
}

// ===== Détecter noms suspects =====
bool IsProcessNameSuspicious(const std::wstring& processName) {
    std::wstring lowerName = processName;
    for (auto& c : lowerName) c = towlower(c);

    // Patterns suspects (outils de dumping connus)
    std::vector<std::wstring> suspiciousPatterns = {
        L"mimikatz", L"procdump", L"dumpert", L"nanodump",
        L"sqldumper", L"rdrleakdiag", L"comsvcs", L"taskmgr"
    };

    for (const auto& pattern : suspiciousPatterns) {
        if (lowerName.find(pattern) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

// ===== ListView =====
void InitListView() {
    LVCOLUMNW lvc = {0};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    lvc.fmt = LVCFMT_LEFT;

    lvc.pszText = (LPWSTR)L"Horodatage";
    lvc.cx = 160;
    ListView_InsertColumn(g_hListView, 0, &lvc);

    lvc.pszText = (LPWSTR)L"Processus Suspect";
    lvc.cx = 180;
    ListView_InsertColumn(g_hListView, 1, &lvc);

    lvc.pszText = (LPWSTR)L"PID";
    lvc.cx = 80;
    ListView_InsertColumn(g_hListView, 2, &lvc);

    lvc.pszText = (LPWSTR)L"Type Accès";
    lvc.cx = 150;
    ListView_InsertColumn(g_hListView, 3, &lvc);

    lvc.pszText = (LPWSTR)L"Utilisateur";
    lvc.cx = 180;
    ListView_InsertColumn(g_hListView, 4, &lvc);

    lvc.pszText = (LPWSTR)L"Alertes";
    lvc.cx = 200;
    ListView_InsertColumn(g_hListView, 5, &lvc);

    ListView_SetExtendedListViewStyle(g_hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
}

void UpdateListView() {
    std::lock_guard<std::mutex> lock(g_dataMutex);

    ListView_DeleteAllItems(g_hListView);

    for (size_t i = 0; i < g_alerts.size(); ++i) {
        LVITEMW lvi = {0};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;

        lvi.iSubItem = 0;
        lvi.pszText = (LPWSTR)g_alerts[i].horodatage.c_str();
        ListView_InsertItem(g_hListView, &lvi);

        ListView_SetItemText(g_hListView, (int)i, 1, (LPWSTR)g_alerts[i].processSuspect.c_str());

        std::wstring pidStr = std::to_wstring(g_alerts[i].pid);
        ListView_SetItemText(g_hListView, (int)i, 2, (LPWSTR)pidStr.c_str());

        ListView_SetItemText(g_hListView, (int)i, 3, (LPWSTR)g_alerts[i].typeAcces.c_str());
        ListView_SetItemText(g_hListView, (int)i, 4, (LPWSTR)g_alerts[i].utilisateur.c_str());
        ListView_SetItemText(g_hListView, (int)i, 5, (LPWSTR)g_alerts[i].alertes.c_str());
    }

    std::wstring status = L"Monitoring LSASS - Alertes: " + std::to_wstring(g_alerts.size());
    SendMessageW(g_hStatusBar, SB_SETTEXTW, 0, (LPARAM)status.c_str());
}

// ===== Ajouter alerte =====
void AddAlert(const LSASSAlert& alert) {
    {
        std::lock_guard<std::mutex> lock(g_dataMutex);
        g_alerts.push_back(alert);
    }

    Log(L"ALERTE: " + alert.processSuspect + L" (PID " + std::to_wstring(alert.pid) + L") - " + alert.alertes);

    PostMessageW(g_hMainWnd, WM_USER + 1, 0, 0);
}

// ===== Monitoring LSASS =====
void MonitorLSASSAccess() {
    Log(L"Début monitoring LSASS (PID: " + std::to_wstring(g_lsassPID) + L")");

    while (g_monitoring) {
        AutoHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            Sleep(5000);
            continue;
        }

        PROCESSENTRY32W pe32 = {0};
        pe32.dwSize = sizeof(pe32);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                // Ignorer lsass lui-même et le processus système
                if (pe32.th32ProcessID == g_lsassPID || pe32.th32ProcessID == 0 || pe32.th32ProcessID == 4) {
                    continue;
                }

                // Ignorer notre propre processus
                if (pe32.th32ProcessID == GetCurrentProcessId()) {
                    continue;
                }

                // Vérifier si le nom du processus est suspect
                bool isSuspicious = IsProcessNameSuspicious(pe32.szExeFile);

                if (isSuspicious) {
                    // Tenter d'ouvrir le processus pour obtenir plus d'infos
                    AutoHandle hProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID));
                    if (hProcess) {
                        wchar_t exePath[MAX_PATH] = {0};
                        DWORD pathSize = MAX_PATH;
                        QueryFullProcessImageNameW(hProcess, 0, exePath, &pathSize);

                        LSASSAlert alert;
                        alert.horodatage = GetCurrentTimeStamp();
                        alert.processSuspect = std::wstring(pe32.szExeFile) + L" (" + exePath + L")";
                        alert.pid = pe32.th32ProcessID;
                        alert.typeAcces = L"Processus suspect détecté";
                        alert.utilisateur = GetProcessUser(hProcess);
                        alert.alertes = L"ATTENTION: Outil de dumping potentiel";

                        AddAlert(alert);
                    }
                }

            } while (Process32NextW(hSnapshot, &pe32) && g_monitoring);
        }

        // Attendre 5 secondes avant la prochaine vérification
        for (int i = 0; i < 50 && g_monitoring; ++i) {
            Sleep(100);
        }
    }

    Log(L"Arrêt monitoring LSASS");
}

// ===== Vérifier événements Sysmon =====
void CheckSysmonEvents() {
    Log(L"Vérification événements Sysmon pour CreateRemoteThread sur LSASS");

    // Query Event Log Sysmon (Microsoft-Windows-Sysmon/Operational)
    // Event ID 8: CreateRemoteThread
    std::wstring query = L"*[System[(EventID=8)]] and *[EventData[Data[@Name='TargetImage'] and (contains(., 'lsass.exe'))]]";

    EVT_HANDLE hResults = EvtQuery(nullptr, L"Microsoft-Windows-Sysmon/Operational",
                                   query.c_str(), EvtQueryChannelPath | EvtQueryReverseDirection);

    if (!hResults) {
        Log(L"Impossible de lire les événements Sysmon (Sysmon peut ne pas être installé)");
        return;
    }

    EVT_HANDLE hEvent = nullptr;
    DWORD returned = 0;
    int eventCount = 0;

    // Lire les 10 derniers événements
    while (EvtNext(hResults, 1, &hEvent, INFINITE, 0, &returned) && eventCount < 10) {
        // Extraire informations de l'événement
        DWORD bufferSize = 0;
        DWORD bufferUsed = 0;
        DWORD propertyCount = 0;

        EvtRender(nullptr, hEvent, EvtRenderEventXml, bufferSize, nullptr, &bufferUsed, &propertyCount);

        if (bufferUsed > 0) {
            std::vector<wchar_t> buffer(bufferUsed / sizeof(wchar_t) + 1);
            if (EvtRender(nullptr, hEvent, EvtRenderEventXml, bufferUsed, buffer.data(), &bufferUsed, &propertyCount)) {
                std::wstring eventXml(buffer.data());

                // Parser basique pour extraire SourceProcessId et SourceImage
                size_t srcPidPos = eventXml.find(L"<Data Name='SourceProcessId'>");
                size_t srcImgPos = eventXml.find(L"<Data Name='SourceImage'>");

                if (srcPidPos != std::wstring::npos && srcImgPos != std::wstring::npos) {
                    // Extraire PID source
                    srcPidPos += 29;
                    size_t srcPidEnd = eventXml.find(L"</Data>", srcPidPos);
                    std::wstring pidStr = eventXml.substr(srcPidPos, srcPidEnd - srcPidPos);

                    // Extraire image source
                    srcImgPos += 25;
                    size_t srcImgEnd = eventXml.find(L"</Data>", srcImgPos);
                    std::wstring srcImage = eventXml.substr(srcImgPos, srcImgEnd - srcImgPos);

                    LSASSAlert alert;
                    alert.horodatage = GetCurrentTimeStamp();
                    alert.processSuspect = srcImage;
                    alert.pid = _wtoi(pidStr.c_str());
                    alert.typeAcces = L"CreateRemoteThread";
                    alert.utilisateur = L"Voir Event Log";
                    alert.alertes = L"CRITIQUE: Thread distant créé dans LSASS";

                    AddAlert(alert);
                }
            }
        }

        EvtClose(hEvent);
        eventCount++;
    }

    EvtClose(hResults);
    Log(L"Vérification Sysmon terminée: " + std::to_wstring(eventCount) + L" événements analysés");
}

// ===== Export CSV =====
void ExportToCSV() {
    OPENFILENAMEW ofn = {0};
    wchar_t szFile[MAX_PATH] = L"LSASSAlerts.csv";

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"CSV Files (*.csv)\0*.csv\0All Files (*.*)\0*.*\0";
    ofn.lpstrTitle = L"Exporter les alertes LSASS";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = L"csv";

    if (!GetSaveFileNameW(&ofn)) return;

    std::ofstream csvFile(szFile, std::ios::binary);
    if (!csvFile.is_open()) {
        MessageBoxW(g_hMainWnd, L"Impossible d'ouvrir le fichier pour l'export.", L"Erreur", MB_ICONERROR);
        return;
    }

    // BOM UTF-8
    csvFile << "\xEF\xBB\xBF";

    // En-têtes
    csvFile << "Horodatage;Processus Suspect;PID;Type Accès;Utilisateur;Alertes\n";

    std::lock_guard<std::mutex> lock(g_dataMutex);
    for (const auto& alert : g_alerts) {
        std::wstring line = alert.horodatage + L";" +
                           alert.processSuspect + L";" +
                           std::to_wstring(alert.pid) + L";" +
                           alert.typeAcces + L";" +
                           alert.utilisateur + L";" +
                           alert.alertes + L"\n";

        int len = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, nullptr, 0, nullptr, nullptr);
        char* utf8 = new char[len];
        WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, utf8, len, nullptr, nullptr);
        csvFile << utf8;
        delete[] utf8;
    }

    csvFile.close();

    Log(L"Export CSV: " + std::wstring(szFile));
    MessageBoxW(g_hMainWnd, L"Export terminé avec succès.", L"Information", MB_ICONINFORMATION);
}

// ===== Window Procedure =====
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE: {
        HFONT hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        g_hListView = CreateWindowExW(0, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
            10, 10, 960, 450, hWnd, (HMENU)ID_LISTVIEW, GetModuleHandle(nullptr), nullptr);
        SendMessageW(g_hListView, WM_SETFONT, (WPARAM)hFont, TRUE);
        InitListView();

        g_hBtnStart = CreateWindowExW(0, L"BUTTON", L"Démarrer Monitoring",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            10, 470, 200, 35, hWnd, (HMENU)ID_BTN_START, GetModuleHandle(nullptr), nullptr);
        SendMessageW(g_hBtnStart, WM_SETFONT, (WPARAM)hFont, TRUE);

        g_hBtnStop = CreateWindowExW(0, L"BUTTON", L"Arrêter",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
            220, 470, 200, 35, hWnd, (HMENU)ID_BTN_STOP, GetModuleHandle(nullptr), nullptr);
        SendMessageW(g_hBtnStop, WM_SETFONT, (WPARAM)hFont, TRUE);

        g_hBtnExport = CreateWindowExW(0, L"BUTTON", L"Exporter Alertes",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            430, 470, 200, 35, hWnd, (HMENU)ID_BTN_EXPORT, GetModuleHandle(nullptr), nullptr);
        SendMessageW(g_hBtnExport, WM_SETFONT, (WPARAM)hFont, TRUE);

        g_hStatusBar = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
            WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
            0, 0, 0, 0, hWnd, (HMENU)ID_STATUSBAR, GetModuleHandle(nullptr), nullptr);
        SendMessageW(g_hStatusBar, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(g_hStatusBar, SB_SETTEXTW, 0, (LPARAM)L"Prêt - Ayi NEDJIMI Consultants");

        return 0;
    }

    case WM_SIZE: {
        int width = LOWORD(lParam);
        int height = HIWORD(lParam);

        MoveWindow(g_hListView, 10, 10, width - 20, height - 120, TRUE);
        MoveWindow(g_hBtnStart, 10, height - 100, 200, 35, TRUE);
        MoveWindow(g_hBtnStop, 220, height - 100, 200, 35, TRUE);
        MoveWindow(g_hBtnExport, 430, height - 100, 200, 35, TRUE);
        SendMessageW(g_hStatusBar, WM_SIZE, 0, 0);
        return 0;
    }

    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case ID_BTN_START:
            g_lsassPID = FindLSASSPID();
            if (g_lsassPID == 0) {
                MessageBoxW(hWnd, L"Impossible de trouver le processus lsass.exe.", L"Erreur", MB_ICONERROR);
                break;
            }

            g_monitoring = true;
            EnableWindow(g_hBtnStart, FALSE);
            EnableWindow(g_hBtnStop, TRUE);

            SendMessageW(g_hStatusBar, SB_SETTEXTW, 0, (LPARAM)L"Monitoring LSASS en cours...");

            g_monitorThread = std::thread([]() {
                MonitorLSASSAccess();
            });

            // Lancer aussi la vérification Sysmon
            std::thread([]() {
                CheckSysmonEvents();
            }).detach();

            break;

        case ID_BTN_STOP:
            g_monitoring = false;
            if (g_monitorThread.joinable()) {
                g_monitorThread.join();
            }

            EnableWindow(g_hBtnStart, TRUE);
            EnableWindow(g_hBtnStop, FALSE);
            SendMessageW(g_hStatusBar, SB_SETTEXTW, 0, (LPARAM)L"Monitoring arrêté");
            break;

        case ID_BTN_EXPORT:
            ExportToCSV();
            break;
        }
        return 0;
    }

    case WM_USER + 1:
        UpdateListView();
        return 0;

    case WM_DESTROY:
        g_monitoring = false;
        if (g_monitorThread.joinable()) {
            g_monitorThread.join();
        }
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, message, wParam, lParam);
}

// ===== WinMain =====
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    InitLog();
    Log(L"=== LSASSProtectorMonitor démarré ===");

    INITCOMMONCONTROLSEX icex = {0};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wcex = {0};
    wcex.cbSize = sizeof(wcex);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.hInstance = hInstance;
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszClassName = L"LSASSProtectorMonitorClass";
    wcex.hIcon = LoadIcon(nullptr, IDI_SHIELD);
    wcex.hIconSm = LoadIcon(nullptr, IDI_SHIELD);

    RegisterClassExW(&wcex);

    g_hMainWnd = CreateWindowExW(0, L"LSASSProtectorMonitorClass",
        L"LSASSProtectorMonitor - Ayi NEDJIMI Consultants",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1000, 600,
        nullptr, nullptr, hInstance, nullptr);

    if (!g_hMainWnd) return 1;

    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    Log(L"=== LSASSProtectorMonitor arrêté ===");
    return (int)msg.wParam;
}
